#!/usr/bin/perl
#
# Nagios plugin to check a process running inside an OpenVZ container
#
# - Checks if the container is running
# - Checks if the process is running inside the container 
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
use Getopt::Long;

# Nagios codes
my %ERRORS=('OK'=>0, 'WARNING'=>1, 'CRITICAL'=>2, 'UNKNOWN'=>3, 'DEPENDENT'=>4);

sub nagios_return($$)
{
    my ($ret, $message) = @_;
    my ($retval, $retstr);
    if (defined($ERRORS{$ret})) {
        $retval = $ERRORS{$ret};
        $retstr = $ret;
    } else {
        $retstr = 'UNKNOWN';
        $retval = $ERRORS{$retstr};
        $message = "WTF is return code '$ret'??? ($message)";
    }
    $message = "$retstr - $message\n";
    print $message;
    exit $retval;
}
                                                                                                             
sub usage()
{
    print("
        -c|--ctid=<ctid>        Container to check
		-p|--process=<proc>		Process name to check for
        --help                  Guess what ;-)");
}

my $ctid = undef;         		# Container ID
my $proc = undef;         		# Process name

GetOptions(
 'c|ctid=s' => \$ctid,
 'p|process=s' => \$proc,
 'help' => sub { &usage(); },
);

&nagios_return("UNKNOWN", "[1] --help see help for valid command line arguments.") if (!$ctid || !$proc);

my $pid = undef;
my $pcpu = 0;
my $pmem = 0;
my $mesg = '';

# Get process information...
open(PROCPS, 'sudo /usr/sbin/vzctl exec '.$ctid.' ps -C '.$proc.' --no-headers -o user,pid,pcpu,pmem,thcount |');
while(<PROCPS>)
{
    chomp;
    if (m/^.*?[\t,\ ]+([0-9]+)[\t,\ ]+([0-9,\.]+)[\t,\ ]+([0-9,\.]+)/)
    {
        $pid = $1;
        $pcpu += $2;
        $pmem += $3;
    }
    else
    {
        $mesg = $_;
    }
}
close(PROCPS);

&nagios_return("CRITICAL", sprintf("%s process not running (CTID=%s) ".$mesg, $proc, $ctid)) if (! defined($pid));

my $perfdata = sprintf("CPU=%s%% MEM=%s%%", $pcpu, $pmem);

$mesg = sprintf("%s is alive (CTID=%s, PID=%s, CPU=%s%%, MEM=%s%%)",
    $proc, $ctid, $pid, $pcpu, $pmem);

my $code = "OK";

&nagios_return($code, "$mesg | $perfdata");
