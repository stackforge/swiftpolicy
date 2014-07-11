#!/bin/sh

CLEANUP=${CLEANUP-true}
# assuming a devstack with the following parameters, where swiftpolicy mw
# was added to the swift pipeline and using CWpolicy.json

BASE_URL=http://localhost
OS_ADMIN=admin
OS_ADMIN_PASSWORD=admin
OS_ADMIN_TENANT=admin
OS_AUTH_URL=$BASE_URL:5000/v2.0

# CW related variables
CW_ROLE1=upload_disabled
CW_ROLE2=remove_only
CW_USER=cwuser
CW_SUPPORT=support

setup () {
    echo "***** SETUP ****"
    echo ">> Create users, tenant and roles"
    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone tenant-create --name $CW_USER 2>&1 >/dev/null

    CW_TID=$(OS_USERNAME=$OS_ADMIN \
        OS_TENANT_NAME=$OS_ADMIN_TENANT \
        OS_PASSWORD=$OS_ADMIN_PASSWORD \
        OS_AUTH_URL=$OS_AUTH_URL keystone tenant-get $CW_USER |awk '{if ($2 == "id") {print $4}}')

    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone role-create --name $CW_ROLE1 2>&1 >/dev/null

    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone role-create --name $CW_ROLE2 2>&1 >/dev/null

    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone role-create --name $CW_SUPPORT 2>&1 >/dev/null

    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone user-create --name $CW_USER --tenant $CW_USER --pass $CW_USER --enabled true 2>&1 >/dev/null

    echo ">> Create support user"
    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone user-create --name $CW_SUPPORT --pass $CW_SUPPORT --enabled true 2>&1 >/dev/null

    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone user-role-add --user $CW_SUPPORT --tenant $CW_USER --role $CW_SUPPORT 2>&1 >/dev/null

    # Let's do regular stuff first
    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone user-role-add --user $CW_USER --tenant $CW_USER --role Member 2>&1 >/dev/null
    
}

tests () {

    echo "***** TESTS ****"
    echo "testy test" > testytest
    echo "*** Regular user - $CW_USER ***"

    echo ">> Testing uploading an object/container"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name obj1 container1 testytest 2>&1 >/dev/null
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name delobj1 todelete testytest 2>&1 >/dev/null
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name delobj2 todelete testytest 2>&1 >/dev/null
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name delobj3 todelete testytest 2>&1 >/dev/null

    echo ">> Testing list and stat"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift list container1 2>&1 >/dev/null
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift stat 2>&1 >/dev/null

    echo ">> Testing deleting delobj3"
    OS_USERNAME=$CW_USER OS_TENANT_NAME=$CW_USER OS_PASSWORD=$CW_USER OS_AUTH_URL=$OS_AUTH_URL swift delete todelete delobj3

    echo ">> Testing download - object"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift download container1 obj1 2>&1 >/dev/null

    echo ">> Testing download - container"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift download container1 2>&1 >/dev/null
    
    echo ">> Testing sharing temp URLs"
    # Create the tempurl key
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift post -m Temp-URL-Key:test1 2>&1 >/dev/null    
    # get the url
    TEMP_URL=$(swift-temp-url GET 6000 /v1/AUTH_$CW_TID/container1/obj1 test1)
    # Download the file
    wget $BASE_URL:8080$TEMP_URL


    echo ""
    echo "*** Now prevent uploads ***"
    echo ">> Applying $CW_ROLE1"
    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone user-role-add --user $CW_USER --tenant $CW_USER --role $CW_ROLE1 2>&1 >/dev/null
    echo ">> Testing upload"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name obj2 container1 testytest 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
        echo "... Upload forbidden, all good"
    else
        echo "... FAIL - User can upload data"
    fi;
    # pass
    echo ">> Testing listing container1"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift list container1 2>&1 >/dev/null
    # pass
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift stat 2>&1 >/dev/null
    # pass
    echo ">> Testing deletion"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift delete todelete delobj2 2>&1 >/dev/null
    # pass
    echo ">> Testing download - object"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift download container1 obj1 2>&1 >/dev/null
    echo ">> Testing download - container"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift download container1 2>&1 >/dev/null
    echo ">> Testing sharing temp URLs"
    # Create the tempurl key
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift post -m Temp-URL-Key:test2 2>&1 >/dev/null    
    # get the url
    TEMP_URL=$(swift-temp-url GET 6000 /v1/AUTH_$CW_TID/container1/obj1 test2)
    # Download the file
    wget $BASE_URL:8080$TEMP_URL


    echo ""
    echo "*** Now authorize file removal only ***"
    echo ">> Applying $CW_ROLE2"
    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone user-role-remove --user $CW_USER --tenant $CW_USER --role $CW_ROLE1 2>&1 >/dev/null
    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone user-role-add --user $CW_USER --tenant $CW_USER --role $CW_ROLE2 2>&1 >/dev/null

    echo ">> Testing upload"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name obj2 container1 testytest 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
        echo "... Upload forbidden, all good"
    else
        echo "... FAIL - User can upload data"
    fi;
    # pass
    echo ">> Testing listing container1"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift list container1 2>&1 >/dev/null
    # pass
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift stat
    # pass
    echo ">> Testing deleting delobj1"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift delete todelete delobj1 2>&1 >/dev/null
    # fail
    echo ">> Testing downloading object"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift download container1 obj1 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
        echo "... Download forbidden, all good"
    else
        echo "... FAIL - User can download data"
    fi;
    echo ">> Testing downloading container"
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift download container1 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
        echo "... Download forbidden, all good"
    else
        echo "... FAIL - User can download data"
    fi;
    echo ">> Testing sharing temp URLs"
    # get the url
    TEMP_URL=$(swift-temp-url GET 6000 /v1/AUTH_$CW_TID/container1/obj1 test2)
    # Download the file, shouldn't work
    wget $BASE_URL:8080$TEMP_URL 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
        echo "... Share Download forbidden, all good"
    else
        echo "... FAIL - User can share data"
    fi;    
    sleep 20
    # Create the tempurl key, shouldn't even work either
    OS_USERNAME=$CW_USER \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_USER \
    OS_AUTH_URL=$OS_AUTH_URL swift post -m Temp-URL-Key:test3 2>&1
    if [ $? -ne 0 ]; then
        echo "... Cannot change metadata, all good"
    else
        echo "... FAIL - User can change temp url key"
    fi;


    echo ""
    echo "*** Testing support user ***"
    echo ">> Testing upload"
    OS_USERNAME=$CW_SUPPORT \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_SUPPORT \
    OS_AUTH_URL=$OS_AUTH_URL swift upload --object-name obj2 container1 testytest 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
        echo "... Upload forbidden, all good"
    else
        echo "... FAIL - User can upload data"
    fi;
    # pass
    echo ">> Testing listing container1"
    OS_USERNAME=$CW_SUPPORT \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_SUPPORT \
    OS_AUTH_URL=$OS_AUTH_URL swift list container1 2>&1 >/dev/null
    # pass
    OS_USERNAME=$CW_SUPPORT \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_SUPPORT \
    OS_AUTH_URL=$OS_AUTH_URL swift stat 2>&1 >/dev/null
    # fail
    echo ">> Testing deleting delobj1"
    OS_USERNAME=$CW_SUPPORT \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_SUPPORT \
    OS_AUTH_URL=$OS_AUTH_URL swift delete todelete delobj1 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
        echo "... Delete forbidden, all good"
    else
        echo "... FAIL - User can delete data"
    fi;
    # fail
    echo ">> Testing downloading object"
    OS_USERNAME=$CW_SUPPORT \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_SUPPORT \
    OS_AUTH_URL=$OS_AUTH_URL swift download container1 obj1 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
        echo "... Download forbidden, all good"
    else
        echo "... FAIL - User can download data"
    fi;
    echo ">> Testing downloading container"
    OS_USERNAME=$CW_SUPPORT \
    OS_TENANT_NAME=$CW_USER \
    OS_PASSWORD=$CW_SUPPORT \
    OS_AUTH_URL=$OS_AUTH_URL swift download container1 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
        echo "... Download forbidden, all good"
    else
        echo "... FAIL - User can download data"
    fi;
}


# cleanup
cleanup () {
    echo "**** CLEANUP *****"
    rm testytest obj1
    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone user-delete $CW_SUPPORT 2>&1 >/dev/null
    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone user-delete $CW_USER 2>&1 >/dev/null
    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone tenant-delete $CW_USER 2>&1 >/dev/null
    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone role-delete $CW_ROLE1 2>&1 >/dev/null
    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone role-delete $CW_ROLE2 2>&1 >/dev/null
    OS_USERNAME=$OS_ADMIN \
    OS_TENANT_NAME=$OS_ADMIN_TENANT \
    OS_PASSWORD=$OS_ADMIN_PASSWORD \
    OS_AUTH_URL=$OS_AUTH_URL keystone role-delete $CW_SUPPORT 2>&1 >/dev/null
}

setup
tests

if [ "$CLEANUP" = "true" ]
then
    cleanup
fi
