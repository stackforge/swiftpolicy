SwiftPolicy Middleware
----------------------

The SwiftPolicy Middleware for OpenStack Swift allows to use a JSON policy file 
to handle swift authorizations.

SwiftPolicy is an adaptation of the keystoneauth middleware here:
https://github.com/openstack/swift/blob/master/swift/common/middleware/keystoneauth.py


Install
-------

1) Install SwiftPolicy  with ``sudo python setup.py install`` or ``sudo python
   setup.py develop``.

2) Alter your proxy-server.conf pipeline to include SwiftPolicy:

For example, you can use SwiftPolicy in place of the keystoneauth middleware:

    Change::

        [pipeline:main]
        pipeline = catch_errors cache tempauth proxy-server

    To::

        [pipeline:main]
        pipeline = catch_errors cache swiftpolicy tempauth proxy-server

3) Add to your proxy-server.conf the section for the SwiftPolicy WSGI filter.

The policy file is set with the ``policy`` option ::

    [filter:swift3]
    use = egg:swiftpolicy#swiftpolicy
    policy = %(here)s/default.json

This middleware comes with a default policy file in /etc/swift/default.json that maintains
compatibility with keystoneauth.


Policy file
-----------

The policy file will list all possible actions on a swift proxy.
Action's syntax is: ``<http verb>_<swift entity>`` (example: "get_container", "put_object", etc).

    ...
    "get_container": "rule:allowed_for_user",
    "put_container": "rule:allowed_for_user",
    "delete_container": "rule:allowed_for_user",
    ...


The policy file contains also two specific rules: "swift_owner" "reseller_request", they are defined
when swift_owner and reseller_request headers are set to true, as those two values are part
of the contract with the auth system (more details here: http://docs.openstack.org/developer/swift/overview_auth.html)

    ...
    "swift_owner": "rule:swift_reseller or rule:swift_operator",
    "reseller_request": "rule:swift_reseller",
    ...
 
Example
-------

* To forbid the creation of new containers: set put_container to '!':

        ...
        "get_container": "rule:allowed_for_user",
        "put_container": "!",
        ...

* To restrict the creation of new containers to users with the role "admin":

        ...
        "get_container": "rule:allowed_for_user",
        "put_container": "role:admin",
        ...

Limitations
-----------

* swiftpolicy does not support dynamic reload of policies, and thus, the swift proxy has
to be restarted when the policy file is updated.


License / Copyright
-------------------

This software is released under the MIT License.

Copyright (c) 2014 Cloudwatt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.