# Copyright 2014 OpenStack Foundation
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

from policy import register
from policy import Enforcer
from policy import Check
from policy import Rules
from string import Template


def get_enforcer(operators_roles, reseller_role, is_admin, logger, policy_file=None):
    swift_operators = [role.strip()
                       for role in operators_roles.split(',')]
    if policy_file:
        return FileBasedEnforcer(policy_file, logger=logger)
    else:
        return DefaultEnforcer(swift_operators, reseller_role, is_admin, logger=logger)


class DefaultEnforcer(Enforcer):
    def __init__(self, swift_operator, swift_reseller, is_admin=False, logger=None):
        super(DefaultEnforcer, self).__init__(policy_file=None, rules=None,
                                              default_rule=None)

        self.swift_operator = swift_operator
        self.swift_reseller = swift_reseller
        self.is_admin = is_admin
        self.log = logger

    def _get_policy(self):
        param = {
            "reseller_admin": self.swift_reseller,
            "operators": " or ".join(["role:%s" % role
                                      for role in self.swift_operator])
        }
        if self.is_admin:
            template = default_policy_is_admin_tmpl
        else:
            template = default_policy_tmpl

        policy = template % param
        return policy

    def load_rules(self, force_reload=False):
        #import pdb; pdb.set_trace()
        policy = self._get_policy()
        rules = Rules.load_json(policy, self.default_rule)
        self.set_rules(rules)

class FileBasedEnforcer(Enforcer):
    def __init__(self, policy_file, logger):
        super(FileBasedEnforcer, self).__init__(policy_file=None, rules=None,
                                              default_rule=None)
        self.policy_file = policy_file
        self.log = logger

    def _get_policy(self):
        with open(self.policy_file, 'r') as policies:
            policy = policies.read()

        return policy

    def load_rules(self, force_reload=False):
        #import pdb; pdb.set_trace()
        policy = self._get_policy()
        try:
            rules = Rules.load_json(policy, self.default_rule)
        except ValueError as error:
            raise
        self.set_rules(rules)


@register("acl")
class AclCheck(Check):
    @staticmethod
    def _authorize_cross_tenant(user_id, user_name,
                                tenant_id, tenant_name, acls):
        """Check cross-tenant ACLs.

        Match tenant:user, tenant and user could be its id, name or '*'

        :param user_id: The user id from the identity token.
        :param user_name: The user name from the identity token.
        :param tenant_id: The tenant ID from the identity token.
        :param tenant_name: The tenant name from the identity token.
        :param acls: The given container ACL.

        :returns: matched string if tenant(name/id/*):user(name/id/*) matches
                  the given ACL.
                  None otherwise.

        """
        for tenant in [tenant_id, tenant_name, '*']:
            for user in [user_id, user_name, '*']:
                s = '%s:%s' % (tenant, user)
                if s in acls:
                    return True
        return False

    @staticmethod
    def _check_role(roles, acls):
        # Check if we have the role in the acls and allow it
        for user_role in roles:
            if user_role in (r.lower() for r in acls):
                #log_msg = 'user %s:%s allowed in ACL: %s authorizing'
                #self.logger.debug(log_msg, tenant_name, user_name,
                #                  user_role)
                return True
        return False

    @staticmethod
    def _authorize_unconfirmed_identity(req, obj, referrers, acls):
        """"
        Perform authorization for access that does not require a
        confirmed identity.

        :returns: A boolean if authorization is granted or denied.  None if
                  a determination could not be made.
        """
        # Allow container sync.
        if (req.environ.get('swift_sync_key')
                and (req.environ['swift_sync_key'] ==
                     req.headers.get('x-container-sync-key', None))
                and 'x-timestamp' in req.headers):
            #log_msg = 'allowing proxy %s for container-sync'
            #self.logger.debug(log_msg, req.remote_addr)
            return True

        # Check if referrer is allowed.
        from swift.common.middleware import acl as swift_acl
        if swift_acl.referrer_allowed(req.referer, referrers):
            if obj or '.rlistings' in acls:
                #log_msg = 'authorizing %s via referer ACL'
                #self.logger.debug(log_msg, req.referrer)
                return True
            return False

    def __call__(self, target, creds, enforcer):
        """ """
        user_id = creds.get("user_id", None)
        user_name = creds.get("user_name", None)
        tenant_id = creds.get("tenant_id", None)
        tenant_name = creds.get("tenant_name", None)
        roles = creds.get("roles", None)

        acls = target["acls"]
        req = target["req"]
        obj = target["object"]
        referrers = target["referrers"]

        if self.match == "check_cross_tenant":
            res = self._authorize_cross_tenant(user_id, user_name,
                                               tenant_id, tenant_name,
                                               acls)

        elif self.match == "check_roles":
            res = self._check_role(roles, acls)

        elif self.match == "check_is_public":
            res = self._authorize_unconfirmed_identity(req, obj,
                                                       referrers, acls)

        else:
            raise ValueError("{match} not allowed for rule 'acl'".
                             format(match=self.match))

        enforcer.log.debug("Rule '%s' evaluated to %s" % (self.match, res))
        return res


default_policy_tmpl = (
    '{'
    '"is_anonymous": "identity:None",'
    '"is_authenticated": "not rule:is_anonymous",'
    '"swift_reseller": "(role:%(reseller_admin)s)",'
    '"swift_operator": "%(operators)s",'

    '"swift_owner": "rule:swift_reseller'
    ' or rule:swift_operator",'

    '"reseller_request": "rule:swift_reseller",'
    '"same_tenant": "account:%%(account)s",'
    '"tenant_mismatch": "not rule:same_tenant",'

    '"allowed_for_authenticated": "rule:swift_reseller'
    ' or acl:check_cross_tenant'
    ' or acl:check_is_public'
    ' or (rule:same_tenant and rule:swift_operator)'
    ' or (rule:same_tenant and acl:check_roles)",'

    '"allowed_for_anonymous": "is_authoritative:True'
    ' and acl:check_is_public",'

    '"allowed_for_user": "(rule:is_authenticated'
    ' and rule:allowed_for_authenticated)'
    ' or rule:allowed_for_anonymous",'

    '"get_account": "rule:allowed_for_user",'
    '"post_account": "rule:allowed_for_user",'
    '"head_account": "rule:allowed_for_user",'
    '"delete_account": "rule:swift_reseller",'
    '"options_account": "",'
    '"get_container": "rule:allowed_for_user",'
    '"put_container": "rule:allowed_for_user",'
    '"delete_container": "rule:allowed_for_user",'
    '"post_container": "rule:allowed_for_user",'
    '"head_container": "rule:allowed_for_user",'
    '"options_container": "",'
    '"get_object": "rule:allowed_for_user",'
    '"put_object": "rule:allowed_for_user",'
    '"copy_object": "rule:allowed_for_user",'
    '"delete_object": "rule:allowed_for_user",'
    '"head_object": "rule:allowed_for_user",'
    '"post_object": "rule:allowed_for_user",'
    '"options_object": ""'
    '}'
)

default_policy_is_admin_tmpl = (
    '{'
    '"is_anonymous": "identity:None",'
    '"is_authenticated": "not rule:is_anonymous",'
    '"swift_reseller": "(role:%(reseller_admin)s)",'
    '"swift_operator": "%(operators)s",'

    '"swift_owner": "rule:swift_reseller'
    ' or rule:swift_operator'
    # diff: add is_admin to swift_owner
    ' or is_admin:True",'

    '"reseller_request": "rule:swift_reseller",'
    '"same_tenant": "account:%%(account)s",'
    '"tenant_mismatch": "not rule:same_tenant",'

    '"allowed_for_authenticated": "rule:swift_reseller'
    ' or acl:check_cross_tenant or acl:check_is_public'
    ' or (rule:same_tenant and rule:swift_operator)'
    # diff: allow access if user is_admin
    ' or (rule:same_tenant and is_admin:True)'
    ' or (rule:same_tenant and is_admin:False and acl:check_roles)",'

    '"allowed_for_anonymous": "is_authoritative:True'
    ' and acl:check_is_public",'

    '"allowed_for_user": "(rule:is_authenticated'
    ' and rule:allowed_for_authenticated)'
    ' or rule:allowed_for_anonymous",'

    '"get_account": "rule:allowed_for_user",'
    '"post_account": "rule:allowed_for_user",'
    '"head_account": "rule:allowed_for_user",'
    '"delete_account": "rule:swift_reseller",'
    '"options_account": "",'
    '"get_container": "rule:allowed_for_user",'
    '"put_container": "rule:allowed_for_user",'
    '"delete_container": "rule:allowed_for_user",'
    '"post_container": "rule:allowed_for_user",'
    '"head_container": "rule:allowed_for_user",'
    '"options_container": "",'
    '"get_object": "rule:allowed_for_user",'
    '"put_object": "rule:allowed_for_user",'
    '"copy_object": "rule:allowed_for_user",'
    '"delete_object": "rule:allowed_for_user",'
    '"head_object": "rule:allowed_for_user",'
    '"post_object": "rule:allowed_for_user",'
    '"options_object": ""'
    '}'
)
