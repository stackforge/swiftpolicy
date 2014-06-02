# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from swift.common import utils as swift_utils
from swift.common.middleware import acl as swift_acl
from swift.common.swob import HTTPNotFound, HTTPForbidden, HTTPUnauthorized
from swift.common.swob import Request
from swift.common.utils import register_swift_info
from enforcer import get_enforcer


class SwiftPolicy(object):
    """Swift middleware to handle Keystone authorization based
    openstack policy.json format

    In Swift's proxy-server.conf add this middleware to your pipeline::

        [pipeline:main]
        pipeline = catch_errors cache authtoken swiftpolicy proxy-server

    Make sure you have the authtoken middleware before the
    swiftpolicy middleware.

    The authtoken middleware will take care of validating the user and
    swiftpolicy will authorize access.

    The authtoken middleware is shipped directly with keystone it
    does not have any other dependences than itself so you can either
    install it by copying the file directly in your python path or by
    installing keystone.

    If support is required for unvalidated users (as with anonymous
    access) or for formpost/staticweb/tempurl middleware, authtoken will
    need to be configured with ``delay_auth_decision`` set to true.  See
    the Keystone documentation for more detail on how to configure the
    authtoken middleware.

    In proxy-server.conf you will need to have the setting account
    auto creation to true::

        [app:proxy-server]
        account_autocreate = true

    And add a swift authorization filter section, such as::

        [filter:swiftpolicy]
        use = egg:swiftpolicy#swiftpolicy
        operator_roles = admin, swiftoperator
        policy = /path/to/policy.json

    This maps tenants to account in Swift.

    The user whose able to give ACL / create Containers permissions
    will be the one that are inside the ``operator_roles``
    setting which by default includes the admin and the swiftoperator
    roles.

    If you need to have a different reseller_prefix to be able to
    mix different auth servers you can configure the option
    ``reseller_prefix`` in your swiftpolicy entry like this::

        reseller_prefix = NEWAUTH

    :param app: The next WSGI app in the pipeline
    :param conf: The dict of configuration values
    """
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = swift_utils.get_logger(conf, log_route='swiftpolicy')
        self.reseller_prefix = conf.get('reseller_prefix', 'AUTH_').strip()
        if self.reseller_prefix and self.reseller_prefix[-1] != '_':
            self.reseller_prefix += '_'
        self.operator_roles = conf.get('operator_roles',
                                       'admin, swiftoperator').lower()
        self.reseller_admin_role = conf.get('reseller_admin_role',
                                            'ResellerAdmin').lower()
        config_is_admin = conf.get('is_admin', "false").lower()
        self.is_admin = swift_utils.config_true_value(config_is_admin)
        config_overrides = conf.get('allow_overrides', 't').lower()
        self.allow_overrides = swift_utils.config_true_value(config_overrides)
        self.policy_file = conf.get('policy', None)

    def __call__(self, environ, start_response):
        identity = self._keystone_identity(environ)

        # Check if one of the middleware like tempurl or formpost have
        # set the swift.authorize_override environ and want to control the
        # authentication
        if (self.allow_overrides and
                environ.get('swift.authorize_override', False)):
            msg = 'Authorizing from an overriding middleware (i.e: tempurl)'
            self.logger.debug(msg)
            return self.app(environ, start_response)

        if identity:
            self.logger.debug('Using identity: %r', identity)
            environ['keystone.identity'] = identity
            environ['REMOTE_USER'] = identity.get('tenant')
            environ['swift.authorize'] = self.authorize
            # Check reseller_request again poicy
            if self.check_action('reseller_request', environ):
                environ['reseller_request'] = True
        else:
            self.logger.debug('Authorizing as anonymous')
            environ['swift.authorize'] = self.authorize

        environ['swift.clean_acl'] = swift_acl.clean_acl

        return self.app(environ, start_response)

    def _keystone_identity(self, environ):
        """Extract the identity from the Keystone auth component."""
        # In next release, we would add user id in env['keystone.identity'] by
        # using _integral_keystone_identity to replace current
        # _keystone_identity. The purpose of keeping it in this release it for
        # back compatibility.
        if environ.get('HTTP_X_IDENTITY_STATUS') != 'Confirmed':
            return
        roles = []
        if 'HTTP_X_ROLES' in environ:
            roles = environ['HTTP_X_ROLES'].split(',')
        identity = {'user': environ.get('HTTP_X_USER_NAME'),
                    'tenant': (environ.get('HTTP_X_TENANT_ID'),
                               environ.get('HTTP_X_TENANT_NAME')),
                    'roles': roles}
        return identity

    def _integral_keystone_identity(self, environ):
        """Extract the identity from the Keystone auth component."""
        if environ.get('HTTP_X_IDENTITY_STATUS') != 'Confirmed':
            return
        roles = []
        if 'HTTP_X_ROLES' in environ:
            roles = environ['HTTP_X_ROLES'].split(',')
        identity = {'user': (environ.get('HTTP_X_USER_ID'),
                             environ.get('HTTP_X_USER_NAME')),
                    'tenant': (environ.get('HTTP_X_TENANT_ID'),
                               environ.get('HTTP_X_TENANT_NAME')),
                    'roles': roles}
        return identity

    def _get_account_for_tenant(self, tenant_id):
        return '%s%s' % (self.reseller_prefix, tenant_id)

    def get_creds(self, environ):
        req = Request(environ)
        try:
            parts = req.split_path(1, 4, True)
            _, account, _, _ = parts
        except ValueError:
            account = None

        env_identity = self._integral_keystone_identity(environ)
        if not env_identity:
            # user identity is not confirmed. (anonymous?)
            creds = {
                'identity': None,
                'is_authoritative': (account and
                                     account.startswith(self.reseller_prefix))
            }
            return creds

        tenant_id, tenant_name = env_identity['tenant']
        user_id, user_name = env_identity['user']
        roles = [r.strip() for r in env_identity.get('roles', [])]
        account = self._get_account_for_tenant(tenant_id)
        is_admin = (tenant_name == user_name)

        creds = {
            "identity": env_identity,
            "roles": roles,
            "account": account,
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "user_id": user_id,
            "user_name": user_name,
            "is_admin": is_admin
        }
        return creds

    def get_target(self, environ):
        req = Request(environ)
        try:
            parts = req.split_path(1, 4, True)
            version, account, container, obj = parts
        except ValueError:
            version = account = container = obj = None

        referrers, acls = swift_acl.parse_acl(getattr(req, 'acl', None))
        target = {
            "req": req,
            "method": req.method.lower(),
            "version": version,
            "account": account,
            "container": container,
            "object": obj,
            "acls": acls,
            "referrers": referrers
        }
        return target

    @staticmethod
    def get_action(method, parts):
        version, account, container, obj = parts
        action = method.lower() + "_"
        if obj:
            action += "object"
        elif container:
            action += "container"
        elif account:
            action += "account"

        return action

    def check_action(self, action, environ):
        creds = self.get_creds(environ)
        target = self.get_target(environ)
        enforcer = get_enforcer(self.operator_roles,
                                self.reseller_admin_role,
                                self.is_admin,
                                self.logger,
                                self.policy_file)
        self.logger.debug("enforce action '%s'", action)
        return enforcer.enforce(action, target, creds)

    def authorize(self, req):
        try:
            parts = req.split_path(1, 4, True)
        except ValueError:
            return HTTPNotFound(request=req)

        env = req.environ
        action = self.get_action(req.method, parts)

        if self.check_action(action, env):
            if self.check_action("swift_owner", env):
                req.environ['swift_owner'] = True
            return
        return self.denied_response(req)

    def denied_response(self, req):
        """Deny WSGI Response.

        Returns a standard WSGI response callable with the status of 403 or 401
        depending on whether the REMOTE_USER is set or not.
        """
        if req.remote_user:
            return HTTPForbidden(request=req)
        else:
            return HTTPUnauthorized(request=req)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)
    register_swift_info('swiftpolicy')

    def auth_filter(app):
        return SwiftPolicy(app, conf)
    return auth_filter
