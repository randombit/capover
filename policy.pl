#!/usr/bin/perl -w

# CapOver Policy Compiler, v0.9.3
# (C) 2003-2004 Jack Lloyd (lloyd@randombit.net)
#    Licensed under the terms of the GNU GPLv2

use strict;
use File::Spec;

# Choose sysctl, echo, or sysctlp
#   sysctlp: print stuff that can be passed to sysctl -p
#   sysctl: print sysctl(8) commands (execute with shell)
#   echo: print echo(1) commands (execute with shell)
#   other: ER-ROR
my $OUTPUT_FORMAT = 'sysctlp';

# Toggle for sanity checks (don't touch!) 
my $SANITY_CHECKS = 1;

if($#ARGV != 0 && $#ARGV != 1)
{
    print "Usage: $0 <policy>\n";
    exit 1;
}

my $POLICY = $ARGV[0];
if($#ARGV == 1)
{
    my $ARG = $ARGV[0];
    $SANITY_CHECKS = 0 if($ARG eq '--0wn-me');
    $POLICY = $ARGV[1];
}

open CONFIG, $POLICY or die "$0: Couldn't read $POLICY\n";

my $config_line = '';
my $default_audit = 1; # if not set, the default is on
while(<CONFIG>)
{
    # cannonicalize input (and check for default_audit)
    chomp;
    s/#.*//; # kill comments
    s/{/ {/; # cap_name{ -> cap_name {
    s/\s+/ /; # all spaces/tabs (however many) -> one space
    s/ $//; # remove trailing spaces
    s/^ //;

    next if($_ eq '');
    if(/^default_audit /)
    {
        if(/default_audit 0/ || /default_audit off/)
          { $default_audit = 0; }
        elsif(/default_audit 1/ || /default_audit on/)
           { $default_audit = 1; }
        else
           { print STDERR "WARNING: Unknown setting $_\n"; }
    }
    else
       { $config_line .= $_ . ' '; }
}

# cannonicalize more
my @configs = split(/} /, $config_line);
foreach my $x (@configs) { $x =~ s/ { / /; $x =~ s/ $//; }

# A list of valid cap names, so we can sanity check
#   This doubles as a 'is really dangerous' list;
#        0: probably OK for any user/any path
#        1: dangerous for all except a specific path + specific user
#
#  Naturally this is a judgement call, don't assume just because there is no
#  warning, that your policy is a good idea. The ones marked "dangerous" will
#  lead to full root privs with minimal effort.

my %CAP_NAMES = (
   'chown' => 1,
   'dac_override' => 1,
   'dac_read_search' => 1,
   'fowner' => 1,
   'fs_immutable' => 0,
   'fsetid' => 1,
   'ipc_lock' => 0,
   'ipc_owner' => 0,
   'kill' => 1,
   'lease' => 0,
   'mknod' => 1,
   'net_admin' => 0,
   'net_bind' => 0,
   'net_broadcast' => 0,
   'net_raw' => 0,
   'setgid' => 1,
   'setuid' => 1,
   'sys_admin' => 1,
   'sys_boot' => 0,
   'sys_chroot' => 0,
   'sys_module' => 1,
   'sys_nice' => 0,
   'sys_pacct' => 0,
   'sys_ptrace' => 1,
   'sys_rawio' => 1,
   'sys_resource' => 0,
   'sys_time' => 0,
   'sys_tty_config' => 0
);

# now convert it into something for sysctl
my %out_conf;
foreach my $config (@configs)
{
    my @elem = split(/ /, $config);

    # The number of elements must be *odd*; a single cap name, plus
    # one or more type/value pairs. I know this looks like we're making
    # sure it's even, but it's really not.
    if($#elem % 2 != 0 || $#elem == 0)
    {
        die "ERROR: Bad config '$config'\n";
    }

    my @caps = split(/,/, $elem[0]);
    my $audit = $default_audit;
    my @users;
    my @groups;
    my @paths;

    for(my $j = 1; $j != $#elem + 1; $j += 2)
    {
        if($elem[$j] eq 'group' || $elem[$j] eq 'groups')
           {
               push @groups, split(/,/, $elem[$j+1])
                   unless($elem[$j+1] eq 'any');
           }
        elsif($elem[$j] eq 'user' || $elem[$j] eq 'users')
           {
               push @users, split(/,/, $elem[$j+1])
                   unless($elem[$j+1] eq 'any');
           }
        elsif($elem[$j] eq 'audit')
        {
            $audit = $elem[$j+1];
            $audit = 1 if($audit eq 'on');
            $audit = 0 if($audit eq 'off');
            if($audit ne '0' && $audit ne '1')
            {
                print STDERR "WARNING: Unknown audit setting $audit\n";
                $audit = 1; # default to on (NOT $default_audit)
            }
        }
        elsif($elem[$j] eq 'path')
        {
            my $path = $elem[$j+1];

            # cannonicalize the HELL out of $path
            unless($path eq 'any')
            {
                $path = File::Spec->rel2abs($path);

                # We're allowed to assume Unix paths 'cause it's an LSM
                # policy compiler... :)
                while($path =~ m@/\.\./@)
                {
                    $path =~ s@/\w*/\.\./@/@g;
                    # This prevents a (seriously obscure) infinte loop
                    $path = File::Spec->rel2abs($path);
                };
                
                die "ERROR: $path is relative (must be absolute)\n"
                    unless(File::Spec->file_name_is_absolute($path));

                while(-l $path)
                {
                    my (undef,$dirs,undef) = File::Spec->splitpath($path);
                    $path = readlink($path);
                    die "readlink failed ($!)\n" if !defined($path);

                    unless(File::Spec->file_name_is_absolute($path))
                    {
                        $path = File::Spec->catpath(undef, $dirs, $path);
                    }
                }

                stat($path);
                die "ERROR: $path is not a program on this system, or is " .
                            "invalid for CapOver's purposes (script, etc)\n"
                    unless(-e _ && -f _ && -B _);

                push @paths, $path;
            }
        }
        else
        {
            die "ERROR: bad config $config\n";
        }
    }

    push @users, undef if($#users == -1);
    push @groups, undef if($#groups == -1);
    push @paths, undef if($#paths == -1);

    foreach my $cap (@caps)
    {
        die "ERROR: Capability $cap isn't known\n"
            unless defined($CAP_NAMES{$cap});
    }

    # This could be better
    sub check_sanity
    {
        my ($cap,$user,$group,$path) = @_;
        my $dangerous = $CAP_NAMES{$cap};

        return if($SANITY_CHECKS == 0);

        $user = '' unless defined($user);
        $group = '' unless defined($group);
        $path = '' unless defined($path);

        my $mass_group = 0;
        # Other dangerous groups?
        $mass_group = 1 if($group eq 'users' || $group eq 'nobody');

        # Catch really obvious cases of stupidity (or malice)
        if($path =~ /^\/bin\/.*sh/)
        {
            die "ERROR: Refusing to give $cap to $path under any " .
                "circumstances.\n" .
                "                             THIS IS A TERRIBLE IDEA.\n";
        }

        print STDERR "WARNING: Empty rule for $cap will be ignored\n"
            if($path eq '' && $user eq '' && $group eq '');

        print STDERR
            "WARNING: $cap is dangerous to give to arbitrary programs,\n".
            "   are you sure this is a good idea?\n"
            if($dangerous && $path eq '');

        print STDERR
            "WARNING: Giving $cap to the $group group is dangerous\n"
            if(!$dangerous && $path eq '' && $mass_group && $user eq '');

        print STDERR
            "WARNING: Giving $cap to the $group group is VERY dangerous\n"
            if($dangerous && $path eq '' && $mass_group && $user eq '');
    }

    # first do some sanity checking
    foreach my $cap (@caps)
    {
        foreach my $user (@users)
        {
            foreach my $group (@groups)
            {
                foreach my $path (@paths)
                {
                    check_sanity($cap,$user,$group,$path);
                }
            }
        }
    }

    sub lookup_user
    {
        my $user = $_[0];
        my (undef,undef,$id,undef,undef,undef,undef) = getpwnam($user);
        die "ERROR: Unknown user $user\n" unless defined($id);
        return $id;
    }

    sub lookup_group
    {
        my $group = $_[0];
        my (undef,undef,$id,undef) = getgrnam($group);
        die "ERROR: Unkown group $group\n" unless defined($id);
        return $id;
    }

    # now generate the policies
    foreach my $cap (@caps)
    {
        foreach my $user (@users)
        {
            foreach my $group (@groups)
            {
                foreach my $path (@paths)
                {
                    my $policy = '';
                    if(defined($user))
                    { $policy .= 'u' . sprintf('%04X', lookup_user($user)); }
                    if(defined($group))
                    { $policy .= 'g' . sprintf('%04X', lookup_group($group)); }
                    if(defined($path))
                       { $policy .= "p$path"; }

                    if($policy ne '')
                    {
                        $policy = "a$audit" . $policy;
                        if(!defined($out_conf{$cap})) { $out_conf{$cap} = ''; }
                        else { $out_conf{$cap} .= '_'; }
                        $out_conf{$cap} .= $policy;
                    }
                }
            }
        }
    }
}

if($OUTPUT_FORMAT ne 'sysctl' and $OUTPUT_FORMAT ne 'sysctlp' and
   $OUTPUT_FORMAT ne 'echo')
{
    print "Bad OUTPUT_FORMAT ($OUTPUT_FORMAT)\n";
    exit 1;
}

# Huzah. The config is good. Print some stuff.
foreach my $cap (keys %out_conf)
{
    print 'echo "', $out_conf{$cap}, "\" > /proc/sys/kernel/cap_over/$cap\n"
        if($OUTPUT_FORMAT eq 'echo');
    print "sysctl -w kernel.cap_over.$cap=", $out_conf{$cap}, "\n"
        if($OUTPUT_FORMAT eq 'sysctl');
    print "kernel.cap_over.$cap = ", $out_conf{$cap}, "\n"
        if($OUTPUT_FORMAT eq 'sysctlp');
}
