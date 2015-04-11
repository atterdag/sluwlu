**sluwlu.pl** (Sync-Local-Users-With-LDAP-Users) will compare a systems local users and groups with the users and groups in a LDAP DIT.

It will then generate a passwd.new and group.new with the LDAP UIDs, GIDs etc, and if a local-only user or group is conflicting with a LDAP user and group, it will find a new unused UID or GID for the user or group.

Finally it will generate some scripts that modifies the ownership of the files belonging to the UIDs and GIDs of changed users and groups.

E.g. if the local user **‘jdoe‘** had his UID changed from 1002 to 1003, then for instance all his files under **/home/jdoe** would belong to someone else after you have exchanged **/etc/passwd** with the new passwd. But the **chown.sh** script contains a ‘chown‘ command for each file, that ‘belonged’ to the old UID of jdoe. And running the **chown.sh** script will the change back ownership to jdoe of all the files that belonged to the old UID of jdoe.