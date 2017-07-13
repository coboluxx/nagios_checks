#!/usr/bin/perl
#
# Nagios plugin to check the health of HP ProCurve Switches.
#
# This script enumerates all sensors on the device and checks
# the sensors health state. 
#
# Copyright (c) 2015 IDNT Europe GmbH [https://www.idnt.net]
#
# This program is free software; you may redistribute it and/or modify it
# under the same terms of the GNU General Public License Version 2+.
#
# History:
#       1.00 20150510 <marcus.zoller@idnt.net> created
#
use strict;
use Getopt::Std;
use lib "/usr/lib64/nagios/plugins";
use utils qw(%ERRORS $TIMEOUT);
use Net::SNMP qw(:snmp DEBUG_ALL);
use vars qw($PROGNAME $VERSION %OPTS $OID_SENSOR_NAMES_BASE $OID_SENSOR_STATUS_BASE %STATUS %VALMAP);

$VERSION        = 1.00;
$PROGNAME       = 'check_hp_procurve_health';
$OID_SENSOR_NAMES_BASE = '.1.3.6.1.4.1.11.2.14.11.1.2.6.1.7';
$OID_SENSOR_STATUS_BASE = '.1.3.6.1.4.1.11.2.14.11.1.2.6.1.4';

%STATUS = ();
%VALMAP = (
    5   => 'Not present',
    4   => 'Good',
    3   => 'Warning',
    2   => 'Critical',
    1   => 'Unknown'
);

sub _version() {
    print "$PROGNAME $VERSION\n";
}

sub _usage() {
    print "\nUsage: ${PROGNAME} -H host_address [-C snmp_community] [-p snmp_port] [-t timeout]\n",
        "\n";
    exit 1;
}

sub _exit {
    print @_;
    exit $ERRORS{'UNKNOWN'};
}

_usage() if (! getopts("H:C:p:t:", \%OPTS) || ! defined($OPTS{H}) || ! defined($OPTS{C}));

my($s, $e) = Net::SNMP->session(
  -hostname             => $OPTS{H},
  exists($OPTS{C}) ? (-community    => $OPTS{C}) : (),
  exists($OPTS{p}) ? (-port         => $OPTS{p}) : (),
  exists($OPTS{t}) ? (-timeout      => $OPTS{t}) : (-timeout =>  int(($TIMEOUT / 3) + 1)),
  -retries              => 2,
  -version              => 2,
);

if (!defined($s)) {
   _exit($e);
}

# Get sensor names...
my @args = (
        -varbindlist            => [ $OID_SENSOR_NAMES_BASE ],
        -maxrepetitions         => 25
);

outer: while (defined($s->get_bulk_request(@args))) {

    my @oids = oid_lex_sort(keys(%{$s->var_bind_list()}));

    foreach (@oids) {

        my $oid = $_;

        last outer if (!oid_base_match($OID_SENSOR_NAMES_BASE, $oid));

        my($index) = $oid =~ /$OID_SENSOR_NAMES_BASE\.(.*)/;
        $STATUS{join('.', $OID_SENSOR_STATUS_BASE, $index)} = {
            name => $s->var_bind_list()->{$oid}
        };

        # Make sure we have not hit the end of the MIB
        if ($s->var_bind_list()->{$oid} eq 'endOfMibView') { last outer; }
    }

    # Get the last OBJECT IDENTIFIER in the returned list
    @args = (-maxrepetitions => 25, -varbindlist => [pop(@oids)]);
}

# Let the user know about any errors
if ($s->error() ne '') {
   _exit($s->error());
}

if (keys %STATUS == 0) {
    print "No data returned from SNMP query.\n";
    exit $ERRORS{'UNKNOWN'};
}

# Get sensor values
my $r = $s->get_request(-varbindlist => [ keys %STATUS ]);

my $mesg = '';
my $state = 4;

foreach my $index (keys %STATUS) {
    $mesg .= (length($mesg) ? ", " : "") . $STATUS{$index}{name} . ": " . $VALMAP{$r->{$index}};
    $state = $r->{$index} if ($r->{$index} < $state);
}

$s->close();

if ($state < 3) {
    print $mesg, "\n";
    exit $ERRORS{'CRITICAL'};
}
if ($state < 4) {
    print $mesg, "\n";
    exit $ERRORS{'WARNING'};
}
if ($state == 4) {
    print $mesg, "\n";
    exit $ERRORS{'OK'};
}

print $mesg, "\n";
exit $ERRORS{'UNKNOWN'};
