SwiftPolicy Middleware.
-----------------------

SwiftPolicy Middleware for OpenStack Swift, allows to use json policy file 
format to handle swift authorizations.

SwiftPolicy is an adaptation of the keystoneauth middleware here:
https://github.com/openstack/swift/blob/master/swift/common/middleware/keystoneauth.py

For compatibity reasons, with the shipped default.json file SwiftPolicy 
will behave exactly like keystoneauth. (except we removed the deprecated 
is_admin feature).

Install
-------

1) Install SwiftPolicy  with ``sudo python setup.py install`` or ``sudo python
   setup.py develop``.

2) Alter your proxy-server.conf pipeline to have SwiftPolicy:

For example, you can use SwiftPolicy in place of keystoneauth middleware:

    Change::

        [pipeline:main]
        pipeline = catch_errors cache tempauth proxy-server

    To::

        [pipeline:main]
        pipeline = catch_errors cache swiftpolicy tempauth proxy-server

3) Add to your proxy-server.conf the section for the SwiftPolicy WSGI filter::

Policy file is given using ``policy`` option 

    [filter:swift3]
    use = egg:swiftpolicy#swiftpolicy
    policy = %(here)s/default.json

We install along with this middleare a default policy file in /etc/swift/default.json, which make our middleware behaves
the same way as keystoneauth (for compatibility reasons).


Policy file
-----------

The policy file will list all possible actions on swift proxy.
Action's format is: ``<http verbe>_<swift entity>`` (example: "get_container", "put_object", etc).

    ...
    "get_container": "rule:allowed_for_user",
    "put_container": "rule:allowed_for_user",
    "delete_container": "rule:allowed_for_user",
    ...

Policy file contains also two specific rules: "swift_owner" "reseller_request", they define
when swift_owner and reseller_request headers are set to true, as those two value are part
of the contract between the auth system and swift.

    ...
    "swift_owner": "rule:swift_reseller or rule:swift_operator",
    "reseller_request": "rule:swift_reseller",
    ...
 

Example
-------

* To deny creation of new containers: set put_container to '!':

        ...
        "get_container": "rule:allowed_for_user",
        "put_container": "!",
        ...

* To restrict creation of new container to users with role "admin":

        ...
        "get_container": "rule:allowed_for_user",
        "put_container": "role:admin",
        ...

Limitations
-----------

* swiftpolicy does not support dynamic laoding of the policy file, and thus, swift proxy have
to be restarted when policy file is updated.