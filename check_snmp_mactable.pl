#!/usr/bin/perl -w
#
# check_snmp_mactable.pl
#
# Copyright 2015 IDNT Europe GmbH
#
# HISTORY
#
# Version 1.0 <marcus.zoller@idnt.net> create.
#
# PURPOSE
#
# This script reads the MAC address table from a switch or router
# using SNMP. The table is cached on a file in /tmp and updated 
# at the give interval.
#
# LICENSE
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307
#

use strict;
use Getopt::Long;
&Getopt::Long::config('bundling');
use Net::SNMP qw(snmp_dispatcher oid_lex_sort);
use Data::Dumper;

# Path to traffic files.  
my $datafile = "/tmp/snmp_mactable";

my %STATUS_CODE =
  ( 'OK' => '0', 'WARNING' => '1', 'CRITICAL' => '2', 'UNKNOWN' => '3' );

  
my $snmpFdbAddress		= '1.3.6.1.2.1.17.4.3.1.1';
my $snmpFdbPort			= '1.3.6.1.2.1.17.4.3.1.2';

# ---------------------------------------------------------------------
# HELPER
# ---------------------------------------------------------------------
sub bytes2bits {
 return unit2bytes(@_)*8;
};

# Print results and exit script
sub stop {
 my $result = shift;
 my $exit_code = shift;
 print $result . "\n";
 exit ( $STATUS_CODE{$exit_code} );
};

# Print help information
sub print_usage {
	print <<EOU;
    Usage: check_snmp_mactable.pl -H host [ -C community_string ] [ -p snmp_port ]
EOU
	stop("UNKNOWN", "UNKNOWN");
}

# ---------------------------------------------------------------------
# CMDARGS
# ---------------------------------------------------------------------
my $snmp_community  = "public";
my $snmp_host = "localhost";
my $snmp_port = 161;
my $snmp_version = 2;
my $refresh_interval = 3600;
my $opt_help;

my $status = GetOptions(
 "C|community=s" => \$snmp_community,
 "H|hostname=s"  => \$snmp_host,
 "p|port=i"      => \$snmp_port,
 "i|interval=i"  => \$refresh_interval,
 "h|help" 	 	 => \$opt_help,
);

print_usage() if ($opt_help);

# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------

$datafile .= "." . $snmp_host . ".dat";

my @mapping;
my $output = "";

if (! -f $datafile || ((stat($datafile))[9]+$refresh_interval) < time) {
	open(DATA, ">$datafile") or stop("UNKNOWN: Unable to write data file $datafile: $!", "UNKNOWN");

	my $session;
	my $error;

	if ($snmp_version =~ /[12]/) {
		($session, $error) = Net::SNMP->session(
		  -hostname  => $snmp_host,
		  -community => $snmp_community,
		  -port      => $snmp_port,
		  -version   => $snmp_version,
		  -translate => [-octetstring => 0],
		);
		if (!defined($session)) {
			stop("UNKNOWN: $error","UNKNOWN");
		};
	}
	elsif ($snmp_version =~ /3/) {
		stop("No support for SNMP v3 yet\n", "UNKNOWN");
	}
	else {
		stop("Unknown SNMP v$snmp_version\n", "UNKNOWN");
	};

	my $response;

	if (!defined($response = $session->get_table (-baseoid => $snmpFdbAddress))) {
		my $answer = $session->error;
		$session->close;
		stop("SNMP error: $answer\n", "UNKNOWN");
	}

	my $x;
	my @tmp;
	
	foreach (oid_lex_sort(keys (%{$response}))) {
        $x = unpack ('H*', $response-> { $_ });
        $x =~ s/(.(?!\Z))/$1/g;
        push (@tmp, $x);
    }
	
	if (!defined($response = $session->get_table (-baseoid => $snmpFdbPort))) {
		my $answer = $session->error;
		$session->close;
		stop("SNMP error: $answer\n", "UNKNOWN");
	}

	my $i = 0;
	foreach (oid_lex_sort (keys (%{$response}))) { 
		printf DATA ("%s;%s\n", $response->{ $_ }, $tmp[$i]);
		$i++;
	}
	
	close(DATA);
}

open(DATA, "<$datafile") or stop("UNKNOWN: Unable to open data file $datafile: $!", "UNKNOWN");
while (my $line = <DATA>) {
	chomp($line);
	my ($port, $mac) = split /;/, $line;
	if (defined($mapping[$port])) {
		$mapping[$port] = "$mapping[$port] $mac,";
	} else {
		$mapping[$port] = "$mac,";
	}
}
close(DATA);

my $i = 0;
for($i=0; $i<@mapping; $i++) {
	if (defined($mapping[$i])) {
		$output .= sprintf("Port %2d: %s\n", $i, $mapping[$i]);
	}
}

stop($output, "OK");

