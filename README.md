Swift3
------

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
   setup.py develop`` or via whatever packaging system you may be using.

2) Alter your proxy-server.conf pipeline to have SwiftPolicy:

You can use SwiftPolicy in place of keystoneauth middleware:

    Was::

        [pipeline:main]
        pipeline = catch_errors cache tempauth proxy-server

    Change To::

        [pipeline:main]
        pipeline = catch_errors cache swiftpolicy tempauth proxy-server

3) Add to your proxy-server.conf the section for the SwiftPolicy WSGI filter::

Policy file is given using ``policy`` option 

    [filter:swift3]
    use = egg:swiftpolicy#swiftpolicy
    policy = {HERE}/default.json
