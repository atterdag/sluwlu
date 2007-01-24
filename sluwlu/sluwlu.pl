#!/usr/bin/perl
#
# VERSION: $Id: sluwlu.pl,v 1.1 2007-01-24 09:07:23 atterdag Exp $
#
# AUTHOR: Valdemar Lemche <valdemar@lemche.net>
#
# PURPOSE: sluwlu.pl (Sync-Local-Users-With-LDAP-Users) will compare a system
# local users and groups with the users and groups in a LDAP DIT.
#
# It will then generate a passwd.new and group.new with the LDAP UIDs, GIDs
# etc, and if a local-only user or group is conflicting with a LDAP user and
# group, it will find a new unused UID or GID for the user or group.
#
# Finally it will generate some scripts that modifies the ownership of the
# files belonging to the UIDs and GIDs of changed users and groups.
#
# E.g. if the local user 'jdoe' had his UID changed from 1002 to 1003, then
# for instance all his files under /home/jdoe would belong to someone else
# after you have exchanged /etc/passwd with the new passwd. But the chown.sh
# script contains a 'chown' command for each file, that 'belonged' to the old
# UID of jdoe. And running the chown.sh script will the change back ownership
# to jdoe of all the files that belonged to the old UID of jdoe.
#
# USAGE: Send the system to runlevel 1. Make sure all daemons are dead and only
# the neccessary programs are running.
# Start up your network interface so that you can communicate with your LDAP
# server. Run sluwlu.pl, then verify that passwd.new, group.new, chown.sh and
# chgrp.sh contains the information that you would expect. And finally run
# ./run.sh. Thats it and now restart your box.
#
# CHANGELOG:
# sluwlu.pl (0.1-alpha) unstable; urgency=high
#
#   * Initial release
#
#  -- Valdemar Lemche <valdemar@lemche.net>  wed, 24 Jan 2007 07:55 +0100
#
# Get the latest version from http://valdemar.lemche.net
#
# sluwlu.pl is Copyright (C) 2006 Valdemar Lemche.  All rights reserved.
# This script is free software; you can redistribute it and/or modify it
# under the same terms as Perl itself.
#
# This script is released TOTALLY AS-IS. If it will have any negative impact
# on your systems, make you sleepless at night or even cause World War III;
# I will claim no responsibility! You may use this script at you OWN risk.
#

# Define modules to use
use strict;
use Net::LDAP;
use Data::Dumper;
use Getopt::Std;

# Define some global hashes to shared global information
our ( %ids, %configuration, $opt_c, $opt_d, $opt_h );

my $syntax =
"sluwlu.pl [-c configuration file] [-d] [-h]\n\n\t-d\tDumps all the infomations collected in some text files, for debugging purposes\n\t-h\tThis help text\n\n";

getopts('c:dh');

die $syntax if ( $opt_h eq '1' );

# Run sub to parse configuration file
if ( $opt_c eq '' ) {
    &read_configuration_file('./sluwlu.cfg');
}
else {
    &read_configuration_file($opt_c);
}

# Get the local users of the system
&get_local_users();

# Get the LDAP users
&get_ldap_users();

# Get the local groups
&get_local_groups();

# Get the LDAP groups
&get_ldap_groups();

# Iterate over both local and LDAP groups
for my $group ( keys( %{ $ids{'groups'} } ) ) {

# Check if the local group's ID is in conflict with a LDAP group, and assign a new unused id if so
    &assign_new_id( 'groups', $group );
}

# Iterate over both local and LDAP groups
for my $user ( keys( %{ $ids{'users'} } ) ) {

    # Check if users local ID conflicts with LDAP, and ass
    &assign_new_id( 'users', $user );
    our (@repositories);
    if ( $ids{'users'}->{$user}->{'repositories'} eq "local" ) {
        @repositories = qw ( local );
    }
    elsif ( $ids{'users'}->{$user}->{'repositories'} eq "ldap" ) {
        @repositories = qw ( ldap );
    }
    elsif ( $ids{'users'}->{$user}->{'repositories'} eq "both" ) {
        @repositories = qw ( local ldap  );
    }
    foreach my $repository (@repositories) {
        $ids{'users'}->{$user}->{$repository}->{'group'} =
          &translate_gid_to_group( $user, $repository );
    }
    &assign_new_gid($user);
}

&find_users_files();
&find_groups_files();

&update_passwd();
&update_group();

&chown_files();
&chgrp_files();

&run_script();

if ( $opt_d eq '1' ) {
    &dump();
}

sub get_local_users {
    open( PASSWD, $configuration{'passwd_file'} );
    while (<PASSWD>) {
        chomp;
        my @entry = split( /:/, $_ );
        $ids{'users'}->{ $entry[0] }->{'local'}->{'id'}  = $entry[2];
        $ids{'users'}->{ $entry[0] }->{'local'}->{'gid'} = $entry[3];
        $ids{'users'}->{ $entry[0] }->{'repositories'}   = "local";
    }
    close(PASSWD);
}

sub get_local_groups {

    # open local group file
    open( GROUP, $configuration{'group_file'} );

    # iterate over the lines in group
    while (<GROUP>) {

        # strip trailing new line
        chomp;

        # split the line into seperate values and seperate with :
        my @entry = split( /:/, $_ );

        # set the local id for the group
        $ids{'groups'}->{ $entry[0] }->{'local'}->{'id'} = $entry[2];

        # set that throup is a local group
        $ids{'groups'}->{ $entry[0] }->{'repositories'} = "local";
    }
}

sub get_ldap_users {
    my $ldap = Net::LDAP->new( $configuration{'ldap_host'} ) or die "$@";
    our ($mesg);
    if ( $configuration{'binddn'} eq '' ) {
        $mesg = $ldap->bind();
    }
    else {
        $mesg = $ldap->bind(
            "$configuration{'binddn'}",
            password => "$configuration{'binddn_password'}",
            version  => 3
        );
    }
    our ($basedn);
    if ( $configuration{'user_suffix'} eq '' ) {
        $basedn =
          $configuration{'user_suffix'} . ',' . $configuration{'basedn'};
    }
    else {
        $basedn = $configuration{'basedn'};
    }
    $mesg = $ldap->search(
        base   => $basedn,
        filter => $configuration{'user_search_filter'},
        attrs  => [
            $configuration{'user_gid_attribute'},
            $configuration{'user_name_attribute'},
            $configuration{'user_id_attribute'}
        ]
    );
    $mesg->code && die $mesg->error;
    foreach my $entry ( $mesg->entries ) {
        my $user = $entry->get_value( $configuration{'user_name_attribute'} );
        if ( defined( $ids{'users'}->{$user} ) ) {
            $ids{'users'}->{$user}->{'repositories'} = "both";
        }
        else {
            $ids{'users'}->{$user}->{'repositories'} = "ldap";
        }
        $ids{'users'}->{$user}->{'ldap'}->{'id'} =
          $entry->get_value( $configuration{'user_id_attribute'} );
        $ids{'users'}->{$user}->{'ldap'}->{'gid'} =
          $entry->get_value( $configuration{'user_gid_attribute'} );
    }
    $mesg = $ldap->unbind;
}

sub get_ldap_groups {
    my $ldap = Net::LDAP->new( $configuration{'ldap_host'} ) or die "$@";
    our ($mesg);
    if ( $configuration{'binddn'} eq '' ) {
        $mesg = $ldap->bind();
    }
    else {
        $mesg = $ldap->bind(
            "$configuration{'binddn'}",
            password => "$configuration{'binddn_password'}",
            version  => 3
        );
    }
    our ($basedn);
    if ( $configuration{'group_suffix'} eq '' ) {
        $basedn =
          $configuration{'user_suffix'} . ',' . $configuration{'basedn'};
    }
    else {
        $basedn = $configuration{'basedn'};
    }
    $mesg = $ldap->search(
        base   => $basedn,
        filter => $configuration{'group_search_filter'},
        attrs  => [
            $configuration{'group_name_attribute'},
            $configuration{'group_id_attribute'}
        ]
    );
    $mesg->code && die $mesg->error;
    foreach my $entry ( $mesg->entries ) {
        my $group = $entry->get_value( $configuration{'group_name_attribute'} );
        if ( defined( $ids{'groups'}->{$group} ) ) {
            $ids{'groups'}->{$group}->{'repositories'} = "both";
        }
        else {
            $ids{'groups'}->{$group}->{'repositories'} = "ldap";
        }
        $ids{'groups'}->{$group}->{'ldap'}->{'id'} =
          $entry->get_value( $configuration{'group_id_attribute'} );
    }
    $mesg = $ldap->unbind;
}

sub find_users_files {
    for my $user ( keys( %{ $ids{'users'} } ) ) {
        if ( $ids{'users'}->{$user}->{'status'} eq 'changed' ) {
            open( FIND,
                "find / -uid $ids{'users'}->{$user}->{'local'}->{'id'}|" );
            @{ $ids{'users'}->{$user}->{'files'} } = <FIND>;
            close(FIND);
        }
    }
}

sub find_groups_files {
    for my $group ( keys( %{ $ids{'groups'} } ) ) {
        if ( $ids{'groups'}->{$group}->{'status'} eq 'changed' ) {
            open( FIND,
                "find / -gid $ids{'groups'}->{$group}->{'local'}->{'id'}|" );
            @{ $ids{'groups'}->{$group}->{'files'} } = <FIND>;
            close(FIND);
        }
    }
}

sub chown_files {
    open( CHOWN_FILE, ">chown.sh" );
    print CHOWN_FILE '#!/bin/sh' . "\n";
    for my $user ( keys( %{ $ids{'users'} } ) ) {
        if ( $ids{'users'}->{$user}->{'status'} eq 'changed' ) {
            for my $file ( @{ $ids{'users'}->{$user}->{'files'} } ) {
                chomp($file);
                print CHOWN_FILE 'chown' . $user . ' ' . $file;
            }
        }
    }
    close(CHOWN_FILE);
    chmod( 0755, "chown.sh" );
}

sub chgrp_files {
    open( CHGRP_FILE, ">chgrp.sh" );
    print CHGRP_FILE '#!/bin/sh' . "\n";
    for my $group ( keys( %{ $ids{'groups'} } ) ) {
        if ( $ids{'groups'}->{$group}->{'status'} eq 'changed' ) {
            for my $file ( @{ $ids{'groups'}->{$group}->{'files'} } ) {
                print CHGRP_FILE 'chgrp ' . $group . ' ' . $file;
            }
        }
    }
    close(CHGRP_FILE);
    chmod( 0755, "chgrp.sh" );
}

sub update_passwd {
    open( PASSWD, $configuration{'passwd_file'} );
    my @passwd = <PASSWD>;
    close(PASSWD);
    open( PASSWD, ">passwd.new" );
    for my $line (@passwd) {

        #if
        chomp($line);
        my ( $username, $password, $uid, $gid, $gecos, $homedir, $shell ) =
          split( /:/, $line );
        print PASSWD $username . ':'
          . $password . ':'
          . $ids{'users'}->{$username}->{'new'}->{'id'} . ':'
          . $ids{'users'}->{$username}->{'new'}->{'gid'} . ':'
          . $gecos . ':'
          . $homedir . ':'
          . $shell . "\n";
    }
    close(PASSWD);
}

sub update_group {
    open( GROUP, $configuration{'group_file'} );
    my @group = <GROUP>;
    close(GROUP);
    open( GROUP, ">group.new" );
    for my $line (@group) {
        chomp($line);
        my ( $groupname, $password, $gid, $members ) = split( /:/, $line );
        print GROUP $groupname . ':'
          . $password . ':'
          . $ids{'groups'}->{$groupname}->{'new'}->{'id'} . ':'
          . $members . "\n";
    }
    close(GROUP);
}

sub translate_gid_to_group {
    for my $group ( keys( %{ $ids{'groups'} } ) ) {
        if ( $ids{'users'}->{ $_[0] }->{ $_[1] }->{'gid'} eq
            $ids{'groups'}->{$group}->{ $_[1] }->{'id'} )
        {
            return ($group);
        }
    }
}

sub assign_new_id {
    unless ( $ids{ $_[0] }->{ $_[1] }->{'status'} eq "changing"
        || $ids{ $_[0] }->{ $_[1] }->{'status'} eq "changed"
        || $ids{ $_[0] }->{ $_[1] }->{'status'} eq "unchanged" )
    {
        $ids{ $_[0] }->{ $_[1] }->{'status'} = "changing";
        if (
            (
                   $ids{ $_[0] }->{ $_[1] }->{'repositories'}  eq "both"
                && $ids{ $_[0] }->{ $_[1] }->{'local'}->{'id'} eq
                $ids{ $_[0] }->{ $_[1] }->{'ldap'}->{'id'}
            )
            || $ids{ $_[0] }->{ $_[1] }->{'repositories'} eq "ldap"
          )
        {
            $ids{ $_[0] }->{ $_[1] }->{'new'}->{'id'} =
              $ids{ $_[0] }->{ $_[1] }->{'ldap'}->{'id'};
            $ids{ $_[0] }->{ $_[1] }->{'status'} = "unchanged";
        }
        elsif ($ids{ $_[0] }->{ $_[1] }->{'repositories'} eq "local"
            && &keep_local_id( $_[0], $_[1] ) eq "1" )
        {
            $ids{ $_[0] }->{ $_[1] }->{'new'}->{'id'} =
              $ids{ $_[0] }->{ $_[1] }->{'local'}->{'id'};
            $ids{ $_[0] }->{ $_[1] }->{'status'} = "unchanged";
        }
        else {
            if ( $ids{ $_[0] }->{ $_[1] }->{'repositories'} eq "both" ) {
                foreach my $user ( keys( %{ $ids{ $_[0] } } ) ) {
                    unless ( $user eq $_[1] ) {
                        if ( $ids{ $_[0] }->{ $_[1] }->{'ldap'}->{'id'} eq
                            $ids{ $_[0] }->{$user}->{'local'}->{'id'} )
                        {
                            &assign_new_id( $ids{ $_[0] }->{$user} );
                        }
                        $ids{ $_[0] }->{ $_[1] }->{'new'}->{'id'} =
                          $ids{ $_[0] }->{ $_[1] }->{'ldap'}->{'id'};
                    }
                }
            }
            elsif ( $ids{ $_[0] }->{ $_[1] }->{'repositories'} eq "local" ) {
                $ids{ $_[0] }->{ $_[1] }->{'new'}->{'id'} =
                  &find_unused_id( $_[0], $_[1] );
            }
            $ids{ $_[0] }->{ $_[1] }->{'status'} = "changed";
        }
    }
}

sub keep_local_id {
    our ($local_id) = "free";
    for my $user ( keys( %{ $ids{ $_[0] } } ) ) {
        unless ( $_[0] eq $user ) {
            if ( $ids{ $_[0] }->{ $_[0] }->{'local'}->{'id'} eq
                   $ids{ $_[0] }->{$user}->{'ldap'}->{'id'}
                || $ids{ $_[0] }->{ $_[0] }->{'local'}->{'id'} eq
                $ids{ $_[0] }->{$user}->{'local'}->{'id'}
                || $ids{ $_[0] }->{ $_[0] }->{'local'}->{'id'} eq
                $ids{ $_[0] }->{$user}->{'new'}->{'id'} )
            {
                $local_id = "taken";
                last;
            }
        }
    }
    if ( $local_id eq "free" ) {
        return ("1");
    }
    else {
        return ("0");
    }
}

sub find_unused_id {
    our $new_id = ( $ids{ $_[0] }->{ $_[1] }->{'local'}->{'id'} ) + 1;
    until ( $new_id eq "65535" ) {
        our $id_used = "no";
        for my $user ( keys( %{ $ids{ $_[0] } } ) ) {
            if (   $new_id eq $ids{ $_[0] }->{'local'}->{'id'}
                || $new_id eq $ids{ $_[0] }->{'ldap'}->{'id'}
                || $new_id eq $ids{ $_[0] }->{'new'}->{'id'} )
            {
                $id_used = "yes";
            }
        }
        if ( $id_used eq "no" ) {
            return ($new_id);
            last;
        }
        $new_id++;
    }
}

sub assign_new_gid {

    # If user exists in both repositories
    if ( $ids{'users'}->{ $_[0] }->{'repositories'} eq "both" ) {

        # If ldap group name equals local group name
        if ( $ids{'users'}->{ $_[0] }->{'local'}->{'group'} eq
            $ids{'users'}->{ $_[0] }->{'ldap'}->{'group'} )
        {

            # Set users local group name as new group name
            $ids{'users'}->{ $_[0] }->{'new'}->{'group'} =
              $ids{'users'}->{ $_[0] }->{'local'}->{'group'};

 # If the user's local group name's local gid is the same as the group's new id.
            if (
                $ids{'groups'}->{ $ids{'users'}->{ $_[0] }->{'new'}->{'group'} }
                ->{'local'}->{'id'} eq
                $ids{'groups'}->{ $ids{'users'}->{ $_[0] }->{'new'}->{'group'} }
                ->{'new'}->{'id'} )
            {

                # Set the new gid as the local gid
                $ids{'users'}->{ $_[0] }->{'new'}->{'gid'} =
                  $ids{'users'}->{ $_[0] }->{'local'}->{'gid'};
            }

            # Else
            else {

                # set new gid as group's new id
                $ids{'users'}->{ $_[0] }->{'new'}->{'gid'} =
                  $ids{'groups'}
                  ->{ $ids{'users'}->{ $_[0] }->{'new'}->{'group'} }->{'new'}
                  ->{'id'};
            }
        }

        # Else
        else {

            # set new gid and new group name from the ldap group
            $ids{'users'}->{ $_[0] }->{'new'}->{'group'} =
              $ids{'users'}->{ $_[0] }->{'ldap'}->{'group'};
            $ids{'users'}->{ $_[0] }->{'new'}->{'gid'} =
              $ids{'groups'}->{ $ids{'users'}->{ $_[0] }->{'ldap'}->{'group'} }
              ->{'new'}->{'id'};
        }
    }

    # Else if user only exists as a local user
    elsif ( $ids{'users'}->{ $_[0] }->{'repositories'} eq "local" ) {

        # then set the user's new gid to the new id of the user's group
        $ids{'users'}->{ $_[0] }->{'new'}->{'gid'} =
          $ids{'groups'}->{ $ids{'users'}->{ $_[0] }->{'local'}->{'group'} }
          ->{'new'}->{'id'};
    }
}

sub run_script {
    open( RUN_SCRIPT, ">run.sh" );
    print RUN_SCRIPT <<EOF;
#!/bin/sh
mv /etc/passwd /etc/passwd.old
mv /etc/group /etc/group.old
cp passwd /etc/passwd
cp group /etc/group
./chown.sh
./chgrp.sh
EOF
    close(RUN_SCRIPT);
    chmod( 0755, "run.sh" );
}

sub dump {
    open( IDS, ">ids-dump.txt" );
    print IDS Dumper( \%ids );
    close(IDS);
    open( CONFIGURATION, ">configuration-dump.txt" );
    print CONFIGURATION Dumper( \%configuration );
    close(CONFIGURATION);
}

sub read_configuration_file {
    print "Reading configuration file ...\n";

    # Defines the required parameters in the configuration file
    @{ $configuration{'parameters'}->{'required'} } = qw(
      passwd_file
      group_file
      ldap_host
      basedn
      user_suffix
      user_search_filter
      user_name_attribute
      user_id_attribute
      user_gid_attribute
      group_suffix
      group_search_filter
      group_name_attribute
      group_id_attribute
    );

    # Defines the optional parameters in the configuration file
    @{ $configuration{'parameters'}->{'optional'} } = qw(
      binddn
      binddn_password
    );

    # Opens configuration file
    open( CONFIG_FILE, $_[0] )
      || die "cannot open " . $_[0] . ": " . $! . "\n";

    # Parses the configuration file, line for line
    foreach my $line (<CONFIG_FILE>) {

        # Remove line ending
        chomp($line);

        # If the line is a comment,
        # contains only spaces
        # or tabs,
        # or is a an empty line
        if (   $line =~ /^#/
            || $line =~ /^\s+$/
            || $line =~ /^\s+$/
            || $line =~ /^\t+$/
            || $line =~ /^$/ )
        {

            # then goto to next line
            next;
        }

        # Splits the line into parameter and value
        my ( $parameter, $value ) = split( / = /, $line );

        # Strips any trailing spaces for parameter
        $parameter =~ s/\s+$//g;

        # Strips any leading spaces for value
        $value =~ s/^\s+//g;

        # Strips any trailing spaces for value
        $value =~ s/\s+$//g;

        # Defines a validation check
        our $validated = 0;

        # iterate over parameter groups
        foreach my $valid_parameters_group (
            keys( %{ $configuration{'parameters'} } ) )
        {

            # For each valid parameter
            foreach my $valid_parameter (
                @{ $configuration{'parameters'}->{$valid_parameters_group} } )
            {

                # if the valid parameter matches the parameter
                if ( $valid_parameter eq $parameter ) {

                    # then use the value from the configuration file
                    $configuration{$valid_parameter} = $value;

                    # declare the parameter as validated
                    $validated = 1;

                    # and break the loop
                    last;
                }
            }

=why_do_I_need_this
                        # if validated
                        if ( $validated eq "1" ) {

                                # then break loop
                                last;
                        }
=cut

        }

        # If the parameter is not a valid setting
        unless ( $validated eq "1" ) {

            # then die
            die 'The parameter, "'
              . $parameter . '"'
              . " used in "
              . $_[0]
              . " is unknown -- exitting!\n";
        }

    }

    # Close configuration file
    close(CONFIG_FILE);

    # For each required parameter
    foreach
      my $required_parameter ( @{ $configuration{'parameters'}->{'required'} } )
    {

        # if parameter is unset
        if ( $configuration{$required_parameter} eq "" ) {

            # then die
            die $required_parameter . " haven't been defined -- exitting!\n";
        }
    }
}
