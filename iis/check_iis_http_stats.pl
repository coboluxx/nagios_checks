#!/usr/bin/perl
#
# Nagios plugin to check IIS request statistics.
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
use vars qw($PROGNAME $VERSION %OPTS $STATUS $OIDBASE $LAST $perf @VERBS);
use Storable;

$VERSION        = 1.00;
$PROGNAME       = 'check_iis_http_stats';

$OIDBASE = '1.3.6.1.4.1.311.1.7.3.1';

$perf = "";

@VERBS = ( "OPTIONS", "GET", "POST", "HEAD", "PUT", "DELETE" );

$STATUS = {
        'time' => time,
        'OID' => {
                '1.3.6.1.4.1.311.1.7.3.1.1'     => { name => 'totalBytesSentHighWord', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.2'     => { name => 'totalBytesSentLowWord', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.3'     => { name => 'totalBytesReceivedHighWord', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.4'     => { name => 'totalBytesReceivedLowWord', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.5'     => { name => 'totalFilesSent', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.6'     => { name => 'totalFilesReceived', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.9'     => { name => 'totalAnonymousUsers', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.10'    => { name => 'totalNonAnonymousUsers', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.15'    => { name => 'connectionAttempts', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.16'    => { name => 'logonAttempts', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.17'    => { name => 'totalOptions', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.18'    => { name => 'totalGets', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.19'    => { name => 'totalPosts', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.20'    => { name => 'totalHeads', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.21'    => { name => 'totalPuts', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.22'    => { name => 'totalDeletes', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.23'    => { name => 'totalTraces', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.24'    => { name => 'totalMoves', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.25'    => { name => 'totalCopy', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.26'    => { name => 'totalMkcol', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.27'    => { name => 'totalPropfind', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.28'    => { name => 'totalProppatch', value => 0 },
				'1.3.6.1.4.1.311.1.7.3.1.29'    => { name => 'totalSearch', value => 0 },
				'1.3.6.1.4.1.311.1.7.3.1.30'    => { name => 'totalLock', value => 0 },
				'1.3.6.1.4.1.311.1.7.3.1.31'    => { name => 'totalUnlock', value => 0 },
				'1.3.6.1.4.1.311.1.7.3.1.32'    => { name => 'totalOthers', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.35'    => { name => 'totalCGIRequests', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.36'    => { name => 'totalBGIRequests', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.40'    => { name => 'totalBlockedRequests', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.41'    => { name => 'totalAllowedRequests', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.42'    => { name => 'totalRejectedRequests', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.43'    => { name => 'totalNotFoundErrors', value => 0 },
                '1.3.6.1.4.1.311.1.7.3.1.44'    => { name => 'totalLockedErrors', value => 0 },
        }
};

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

_usage() if (! getopts("H:C:p:t:v:", \%OPTS) || ! defined($OPTS{H}) || ! defined($OPTS{C}));

if (defined($OPTS{v})) {
	@VERBS = ();
	
	# HTTP verbs to return data for
	foreach my $verb (split(/,/, $OPTS{v})) {
		$verb =~ s/^\s+|\s+$//g;
		push(@VERBS, uc($verb));
	}
}

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

my @args = (
    -varbindlist        => [ $OIDBASE ],
    -maxrepetitions     => 25
);

outer: while (defined($s->get_bulk_request(@args))) {

    my @oids = oid_lex_sort(keys(%{$s->var_bind_list()}));

    foreach (@oids) {

        my $oid = $_;

        last outer if (!oid_base_match($OIDBASE, $oid));

        my ($lookup) = $oid =~ /($OIDBASE\.[0-9]+).*/;

        if ( defined($STATUS->{'OID'}->{$lookup})) {
            $STATUS->{'OID'}->{$lookup}->{'value'} = $s->var_bind_list()->{$oid};
        }

        # Make sure we have not hit the end of the MIB
        if ($s->var_bind_list()->{$oid} eq 'endOfMibView') { last outer; }
    }

    # Get the last OBJECT IDENTIFIER in the returned list
    @args = (-maxrepetitions => 25, -varbindlist => [pop(@oids)]);
}

$s->close();

my $datafile = "/tmp/$PROGNAME.$OPTS{H}.dat";

if (! -f $datafile) {
    store($STATUS, $datafile);
    print "Collecting data...\n";
    exit $ERRORS{'UNKNOWN'};
}

eval { $LAST = retrieve $datafile; };
if ($@) {
    unlink($datafile);
    store($STATUS, $datafile);
    print "Collecting data...\n";
    exit $ERRORS{'UNKNOWN'};
}

store($STATUS, $datafile);

my $totalByteSentNow = $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.1'}->{'value'} << 32;
$totalByteSentNow += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.2'}->{'value'};
my $totalByteReceivedNow = $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.3'}->{'value'} << 32;
$totalByteReceivedNow += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.4'}->{'value'};
my $totalByteSentLast = $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.1'}->{'value'} << 32;
$totalByteSentLast += $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.2'}->{'value'};
my $totalByteReceivedLast = $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.3'}->{'value'} << 32;
$totalByteReceivedLast += $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.4'}->{'value'};

if ($totalByteSentNow < $totalByteSentLast || $totalByteReceivedNow < $totalByteReceivedLast) {
    print "Collecting data...\n";
    exit $ERRORS{'UNKNOWN'};
}

my $reqs = 0;

$perf .= sprintf(" byte_snd=%dB", ($totalByteSentNow-$totalByteSentLast) / ($STATUS->{'time'} - $LAST->{'time'}));
$perf .= sprintf(" byte_rcv=%dB", ($totalByteReceivedNow-$totalByteReceivedLast) / ($STATUS->{'time'} - $LAST->{'time'}));

#
# request stats
#
$perf .= sprintf(" req_BLOCKED=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.40'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.40'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
$perf .= sprintf(" req_ALLOWED=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.41'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.41'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
$perf .= sprintf(" req_REJECTED=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.42'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.42'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
		
# 
# ERRORS
#
$perf .= sprintf(" err_NOTFOUND=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.43'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.43'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
$perf .= sprintf(" err_LOCKED=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.44'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.44'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));

#
# HTTP VERB counters
#
my $other = 0;

# HTTP OPTIONS
if ("OPTIONS" ~~ @VERBS) {
	$perf .= sprintf(" http_OPTIONS=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.17'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.17'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
} 
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.17'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.17'}->{'value'}
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.17'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.17'}->{'value'};

# HTTP GET
if ("GET" ~~ @VERBS) {
	$perf .= sprintf(" http_GET=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.18'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.18'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.18'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.18'}->{'value'}
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.18'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.18'}->{'value'};

# HTTP POST	 
if ("POST" ~~ @VERBS) {
	$perf .= sprintf(" http_POST=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.19'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.19'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.19'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.19'}->{'value'}
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.19'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.19'}->{'value'};

# HTTP HEAD	 
if ("HEAD" ~~ @VERBS) {
	$perf .= sprintf(" http_HEAD=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.20'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.20'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.20'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.20'}->{'value'}
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.20'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.20'}->{'value'};

# HTTP PUT
if ("PUT" ~~ @VERBS) {
	$perf .= sprintf(" http_PUT=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.21'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.21'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.21'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.21'}->{'value'}
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.21'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.21'}->{'value'};

# HTTP DELETE
if ("DELETE" ~~ @VERBS) {
$perf .= sprintf(" http_DELETE=%.2f",
    ($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.22'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.22'}->{'value'}) /
    ($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.22'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.22'}->{'value'};
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.22'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.22'}->{'value'};

# HTTP TRACE
if ("TRACE" ~~ @VERBS) {
	$perf .= sprintf(" http_TRACE=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.23'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.23'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.23'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.23'}->{'value'};
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.23'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.23'}->{'value'};

# HTTP MOVE
if ("MOVE" ~~ @VERBS) {
	$perf .= sprintf(" http_MOVE=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.24'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.24'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.24'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.24'}->{'value'};
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.24'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.24'}->{'value'};

# HTTP COPY
if ("COPY" ~~ @VERBS) {
	$perf .= sprintf(" http_COPY=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.25'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.25'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.25'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.25'}->{'value'};
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.25'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.25'}->{'value'};

# HTTP MKCOL
if ("MKCOL" ~~ @VERBS) {
	$perf .= sprintf(" http_MKCOL=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.26'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.26'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.26'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.26'}->{'value'};
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.26'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.26'}->{'value'};

# HTTP PROPFIND
if ("PROPFIND" ~~ @VERBS) {
	$perf .= sprintf(" http_PROPFIND=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.27'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.27'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.27'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.27'}->{'value'};
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.27'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.27'}->{'value'};

# HTTP PROPPATCH
if ("PROPPATCH" ~~ @VERBS) {
	$perf .= sprintf(" http_PROPPATCH=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.28'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.28'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.28'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.28'}->{'value'};
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.28'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.28'}->{'value'};

# HTTP SEARCH
if ("SEARCH" ~~ @VERBS) {
	$perf .= sprintf(" http_SEARCH=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.29'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.29'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.29'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.29'}->{'value'};
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.29'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.29'}->{'value'};

# HTTP LOCK
if ("LOCK" ~~ @VERBS) {
	$perf .= sprintf(" http_LOCK=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.30'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.30'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.30'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.30'}->{'value'};
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.30'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.30'}->{'value'};

# HTTP UNLOCK
if ("UNLOCK" ~~ @VERBS) {
	$perf .= sprintf(" http_UNLOCK=%.2f",
		($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.31'}->{'value'}-
		 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.31'}->{'value'}) /
		($STATUS->{'time'} - $LAST->{'time'}));
}
else {
	$other += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.31'}->{'value'}-
		$LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.31'}->{'value'};
};
$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.31'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.31'}->{'value'};

# Other HTTP verbs
$perf .= sprintf(" http_OTHER=%.2f",
	(($STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.32'}->{'value'}-
	 $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.32'}->{'value'}) + $other) /
	($STATUS->{'time'} - $LAST->{'time'}));

$reqs += $STATUS->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.32'}->{'value'}-
     $LAST->{'OID'}->{'1.3.6.1.4.1.311.1.7.3.1.32'}->{'value'};

printf("Serving %.2f requests/s now | $perf\n", $reqs/($STATUS->{'time'} - $LAST->{'time'}));

exit $ERRORS{'OK'};
