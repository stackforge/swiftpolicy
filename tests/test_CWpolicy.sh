#!/bin/sh

CLEANUP=${CLEANUP-true}
# assuming a devstack with the following parameters, where swiftpolicy mw
# was added to the swift pipeline and using CWpolicy.json

OS_ADMIN=admin
OS_ADMIN_PASSWORD=admin
OS_ADMIN_TENANT=admin
OS_AUTH_URL=http://localhost:5000/v2.0

# CW related variables
CW_ROLE1=upload_disabled
CW_ROLE2=remove_only
CW_USER=cwuser

# Create user, tenant, roles
OS_USERNAME=$OS_ADMIN OS_TENANT_NAME=$OS_ADMIN_TENANT OS_PASSWORD=$OS_ADMIN_PASSWORD OS_AUTH_URL=$OS_AUTH_URL keystone tenant-create --name $CW_USER
OS_USERNAME=$OS_ADMIN OS_TENANT_NAME=$OS_ADMIN_TENANT OS_PASSWORD=$OS_ADMIN_PASSWORD OS_AUTH_URL=$OS_AUTH_URL keystone role-create --name $CW_ROLE1
OS_USERNAME=$OS_ADMIN OS_TENANT_NAME=$OS_ADMIN_TENANT OS_PASSWORD=$OS_ADMIN_PASSWORD OS_AUTH_URL=$OS_AUTH_URL keystone role-create --name $CW_ROLE2
OS_USERNAME=$OS_ADMIN OS_TENANT_NAME=$OS_ADMIN_TENANT OS_PASSWORD=$OS_ADMIN_PASSWORD OS_AUTH_URL=$OS_AUTH_URL keystone user-create --name $CW_USER --tenant $CW_USER --pass $CW_USER --enabled true

# Let's do regular stuff first
OS_USERNAME=$OS_ADMIN OS_TENANT_NAME=$OS_ADMIN_TENANT OS_PASSWORD=$OS_ADMIN_PASSWORD OS_AUTH_URL=$OS_AUTH_URL keystone user-role-add --user $CW_USER --tenant $CW_USER --role Member

echo "testy test" > testytest
echo "Testing uploading an object/container"
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name obj1 container1 testytest
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name delobj1 todelete testytest
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name delobj2 todelete testytest
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name delobj3 todelete testytest
echo "Testing list and stat"
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift list container1 
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift stat
echo "Testing deleting delobj3"
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift delete todelete delobj3

echo ""
# Now prevent uploads
echo "Applying $CW_ROLE1"
OS_USERNAME=$OS_ADMIN OS_TENANT_NAME=$OS_ADMIN_TENANT OS_PASSWORD=$OS_ADMIN_PASSWORD OS_AUTH_URL=$OS_AUTH_URL keystone user-role-add --user $CW_USER --tenant $CW_USER --role $CW_ROLE1
echo "Testing upload"
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name obj2 container1 testytest
if [ $? -ne 0 ]; then
    echo "Upload forbidden, all good"
else
    echo "FAIL - User can upload data"
fi;
# pass
echo "Testing listing container1"
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift list container1
# pass
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift stat
# pass
echo "Testing deletion"
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift delete todelete delobj2
# pass
echo "Testing download"
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift download container1 obj1

echo ""
# Now authorize file removal only
echo "Applying $CW_ROLE2"
OS_USERNAME=$OS_ADMIN OS_TENANT_NAME=$OS_ADMIN_TENANT OS_PASSWORD=$OS_ADMIN_PASSWORD OS_AUTH_URL=$OS_AUTH_URL keystone user-role-remove --user $CW_USER --tenant $CW_USER --role $CW_ROLE1
OS_USERNAME=$OS_ADMIN OS_TENANT_NAME=$OS_ADMIN_TENANT OS_PASSWORD=$OS_ADMIN_PASSWORD OS_AUTH_URL=$OS_AUTH_URL keystone user-role-add --user $CW_USER --tenant $CW_USER --role $CW_ROLE2
echo "Testing upload"
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name obj2 container1 testytest
if [ $? -ne 0 ]; then
    echo "Upload forbidden, all good"
else
    echo "FAIL - User can upload data"
fi;
# pass
echo "Testing listing container1"
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift list container1
# pass
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift stat
# pass
echo "Testing deleting delobj1"
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift delete todelete delobj1
# fail
echo "Testing downloading object"
OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift download container1 obj1
if [ $? -ne 0 ]; then
    echo "Download forbidden, all good"
else
    echo "FAIL - User can download data"
fi;


# cleanup
cleanup () {
    rm testytest obj1
    OS_USERNAME=$OS_ADMIN OS_TENANT_NAME=$OS_ADMIN_TENANT OS_PASSWORD=$OS_ADMIN_PASSWORD OS_AUTH_URL=$OS_AUTH_URL keystone user-delete $CW_USER
    OS_USERNAME=$OS_ADMIN OS_TENANT_NAME=$OS_ADMIN_TENANT OS_PASSWORD=$OS_ADMIN_PASSWORD OS_AUTH_URL=$OS_AUTH_URL keystone tenant-delete $CW_USER
    OS_USERNAME=$OS_ADMIN OS_TENANT_NAME=$OS_ADMIN_TENANT OS_PASSWORD=$OS_ADMIN_PASSWORD OS_AUTH_URL=$OS_AUTH_URL keystone role-delete $CW_ROLE1
    OS_USERNAME=$OS_ADMIN OS_TENANT_NAME=$OS_ADMIN_TENANT OS_PASSWORD=$OS_ADMIN_PASSWORD OS_AUTH_URL=$OS_AUTH_URL keystone role-delete $CW_ROLE2
}

if [ "$CLEANUP" = "true" ]
then
    cleanup
fi
