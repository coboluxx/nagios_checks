#!/usr/bin/perl -w
#
# Plugin to retrieve openvz container statistics.
#
# Copyright (c) 2015 IDNT Europe GmbH
#
# This program is free software; you may redistribute it and/or modify it
# under the same terms of the GNU General Public License Version 2+.
#
# Warning:
#		This must run as root using sudo as /proc/bc is readable by root only.
#
# History:
#       1.00 20150510 <marcus.zoller@idnt.net> created
#
use strict;
use Getopt::Std;
use lib "/usr/lib64/nagios/plugins";
use utils qw(%ERRORS $TIMEOUT);
use Storable;
use Data::Dumper;
use List::Util qw(sum);
use Sys::Hostname;

use vars qw($PROGNAME $VERSION %OPTS $perfdata $output $RESOURCE $CPU $state $HZ $ARCH);

$VERSION        = 1.00;
$PROGNAME       = 'check_ovz_ct';

%OPTS           = ();
$RESOURCE       = {};
$CPU            = {};

chomp($HZ = `/usr/bin/getconf CLK_TCK`);
chomp($ARCH = `/bin/uname -m`);

$output = "";
$perfdata = "";
$state = "OK";

# ----------------------------------------------------------------------
# HELPER
#
sub _version() {
    print "$PROGNAME $VERSION\n";
}

sub _usage() {
    print "\nUsage: ${PROGNAME} -c CTID\n",
            "\n",
            "       -c CTID\n",
            "          The container id to check\n",
            "\n";
    exit 1;
}

sub _exit {
    print @_;
    exit $ERRORS{'UNKNOWN'};
}

# Returs true if the resource value indicates no limit
sub is_unlimited($) {
    my $number = shift;

    if ($ARCH eq "x86_64") {
        return 1 if ($number == 9223372036854775807);
        return undef;
    }

    return 1 if ($number == 2147483647);
    return undef;
}

sub convert($$) {
    my $name = shift;
    my $value = shift;
    if ($name =~ m/^.*?pages$/) {
        return $value * 4096; # we have 4K pages
    }
    return $value;
}

sub get_uom($) {
    my $name = shift;
    if ($name =~ m/^.*?pages$/) {
        return "B";
    }
    return "";
}

sub get_barrier($) {
    my $name = shift;
    return is_unlimited($RESOURCE->{$name}->{'barrier'}) ? "" : convert($name, $RESOURCE->{$name}->{'barrier'});
}

sub get_limit($) {
    my $name = shift;
    return is_unlimited($RESOURCE->{$name}->{'limit'}) ? "" : convert($name, $RESOURCE->{$name}->{'limit'});
}

sub get_perfdata {
    my $name = shift;
    my $label = shift || $name;
    return sprintf(" %s=%d%s;%s;%s", $label, convert($name, $RESOURCE->{$name}->{'held'}),
        get_uom($name), get_barrier($name), get_limit($name));
}

# ----------------------------------------------------------------------
# MAIN
#
_usage() if (! getopts("c:", \%OPTS) || ! defined($OPTS{c}));

# See if we have a configuration file for this container
if (! -f "/etc/vz/conf/$OPTS{c}.conf") {
    print "Unknown container specified $OPTS{c}. Could not find configuration.\n";
    exit $ERRORS{'UNKNOWN'};
}

# See if the container is running on this host
if (! -d "/proc/bc/$OPTS{c}") {
    print "Container $OPTS{c} is stopped.\n";
    exit $ERRORS{'CRITICAL'};
}


#
# RESOURCE UTILIZATION
#
open(BEANS, "</proc/bc/$OPTS{c}/resources");

while(my $line = <BEANS>) {
    chomp($line);

    next if ($line !~ m/^.*?([a-z,0-9]+).*?([0-9]+).*?([0-9]+).*?([0-9]+).*?([0-9]+).*?([0-9]+)$/i);

    $RESOURCE->{$1} = {
        'held'          => $2,
        'maxheld'       => $3,
        'barrier'       => $4,
        'limit'         => $5,
        'failcnt'       => $6
    };
}

close(BEANS);

# From OVZ docs: oth vzctl and the kernel treats a configuration file as vswap one if PHYSPAGES limit is not set to unlimited (a.k.a. LONG_MAX).
my $is_vswap = !is_unlimited($RESOURCE->{'physpages'}->{'limit'});

# Check configuration
if ($is_vswap) {
    if ($RESOURCE->{'physpages'}->{'barrier'} != 0) {
        $output .= sprintf("WARNING: physpages.barriert should be 0 on vSwap enabled container.\n");
        if ($state ne 'CRITICAL') {
            $state = 'WARNING';
        }
    }
    if ($RESOURCE->{'swappages'}->{'barrier'} != 0) {
        $output .= sprintf("WARNING: physpages.barriert should be 0 on vSwap enabled container.\n");
        if ($state ne 'CRITICAL') {
            $state = 'WARNING';
        }
    }
    if (!is_unlimited($RESOURCE->{'privvmpages'}->{'barrier'})) {
        $output .= sprintf("WARNING: privvmpages.barriert should be unlimited on vSwap enabled container.\n");
        if ($state ne 'CRITICAL') {
            $state = 'WARNING';
        }
    }
    if (!is_unlimited($RESOURCE->{'privvmpages'}->{'limit'})) {
        $output .= sprintf("WARNING: privvmpages.barriert should be unlimited on vSwap enabled container.\n");
        if ($state ne 'CRITICAL') {
            $state = 'WARNING';
        }
    }
    if ($RESOURCE->{'lockedpages'}->{'barrier'} != $RESOURCE->{'physpages'}->{'limit'}) {
        $output .= sprintf("WARNING: lockedpages.barriert should not be set. it is set implicit to physpages.limit on vSwap enabled container.\n");
        if ($state ne 'CRITICAL') {
            $state = 'WARNING';
        }
    }
    if ($RESOURCE->{'oomguarpages'}->{'barrier'} != $RESOURCE->{'physpages'}->{'limit'}) {
        $output .= sprintf("WARNING: oomguarpages.barriert should not be set. it is set implicit to physpages.limit on vSwap enabled container.\n");
        if ($state ne 'CRITICAL') {
            $state = 'WARNING';
        }
    }
    if ($RESOURCE->{'vmguarpages'}->{'barrier'} != ($RESOURCE->{'physpages'}->{'limit'}+$RESOURCE->{'swappages'}->{'limit'})) {
        $output .= sprintf("WARNING: vmguarpages.barriert should not be set. it is set implicit to physpages.limit + swappages.limit on vSwap enabled container.\n");
        if ($state ne 'CRITICAL') {
            $state = 'WARNING';
        }
    }
}

# Numper of processes
$perfdata .= get_perfdata('numproc');
$perfdata .= get_perfdata('numfile');
$perfdata .= get_perfdata('numflock');
$perfdata .= get_perfdata('numpty');
$perfdata .= get_perfdata('numsiginfo');
$perfdata .= get_perfdata('numiptent');
$perfdata .= get_perfdata('numtcpsock');
$perfdata .= get_perfdata('numothersock');
$perfdata .= get_perfdata('physpages', "ram");
$perfdata .= get_perfdata('swappages', "swap");


#
# CPU UTILIZATION
#

# start with getting number of CPU's on system
my $CPUCOUNT = 0;

open(CPUCNT, "</proc/cpuinfo");
while(my $line = <CPUCNT>) {
    chomp($line);
    $CPUCOUNT++ if ($line =~ m/^processor/);
}
close(CPUCNT);

open(STAT, "</proc/vz/fairsched/$OPTS{c}/cpu.proc.stat");
while(my $line = <STAT>) {
    chomp($line);

    #     user,  nice, system, uptime                                   # in jiffies
    #                                    idle,  strv, uptime, used      # in cycles, strv is unused, used is cycles of all cpus
    #cpu  271239 0     23299   354649723 102490 0     0       582
    #cpu0 39903  0     3102    22135444  11834  0     0       113
    #...
    next if ($line !~ m/^(cpu[^0-9]+).*?([0-9]+).*?([0-9]+).*?([0-9]+).*?([0-9]+).*?([0-9]+).*?([0-9]+).*?([0-9]+).*?([0-9]+)$/i);

    $CPU->{'ct'} = {
        'user'          => $2,
        'nice'          => $3,
        'system'        => $4,
        'uptime_j'      => $5
    };
}
close(STAT);

open(STAT, "</proc/stat");
while(my $line = <STAT>) {
    chomp($line);

    #     user,  nice, system, idle, iowait, ....
    #cpu  271239 0     23299   354649723 102490 0     0       582
    #cpu0 39903  0     3102    22135444  11834  0     0       113
    #...
    next if ($line !~ m/^(cpu[^0-9]+).*?([0-9]+).*?([0-9]+).*?([0-9]+).*?([0-9]+).*?([0-9]+).*$/i);

    my @cpu = split /\s+/, $line;
    shift @cpu;

    $CPU->{'sys'} = {
        'user'          => $cpu[0],
        'nice'          => $cpu[1],
        'system'        => $cpu[2],
        'total'         => sum(@cpu),
    };
}
close(STAT);

if (-f "/tmp/${PROGNAME}.$OPTS{c}.cpustat") {

    # We have a previous value
    my $PCPU = retrieve("/tmp/${PROGNAME}.$OPTS{c}.cpustat");

    # calculate jiffies uptime delta (note: to convert to seconds we have HZ jiffies per second per CPU
    my $ct_elapsed_j = ($CPU->{'ct'}->{'uptime_j'} - $PCPU->{'ct'}->{'uptime_j'});

    my $ct_cpu_user = ($CPU->{'ct'}->{'user'} - $PCPU->{'ct'}->{'user'}) / $ct_elapsed_j * 100;
    my $ct_cpu_nice = ($CPU->{'ct'}->{'nice'} - $PCPU->{'ct'}->{'nice'}) / $ct_elapsed_j * 100;
    my $ct_cpu_sys = ($CPU->{'ct'}->{'system'} - $PCPU->{'ct'}->{'system'}) / $ct_elapsed_j * 100;
    my $ct_cpu_idle = 100 - $ct_cpu_user - $ct_cpu_nice - $ct_cpu_sys;

    # calculate time openvz used in total
    my $ct_time_spent = (($CPU->{'ct'}->{'user'} + $CPU->{'ct'}->{'nice'} + $CPU->{'ct'}->{'system'})-
                        ($PCPU->{'ct'}->{'user'} + $PCPU->{'ct'}->{'nice'} + $PCPU->{'ct'}->{'system'}));
	if ($ct_elapsed_j>0) {
		$ct_time_spent = $ct_time_spent / $ct_elapsed_j;
	};

    my $sys_time_used = (($CPU->{'sys'}->{'user'} + $CPU->{'sys'}->{'nice'} + $CPU->{'sys'}->{'system'})-
                        ($PCPU->{'sys'}->{'user'} + $PCPU->{'sys'}->{'nice'} + $PCPU->{'sys'}->{'system'}));
	if ($ct_elapsed_j>0) {
		$sys_time_used = $sys_time_used / $ct_elapsed_j;
	};

    my $sys_time_total = ($CPU->{'sys'}->{'total'} - $PCPU->{'sys'}->{'total'});
	if ($ct_elapsed_j>0) {
		$sys_time_total = $sys_time_total / $ct_elapsed_j
	}
    my $sys_cpu_time = 0;
	if ($ct_time_spent > 0) {
		$sys_cpu_time = $sys_time_used / $ct_time_spent;
	};
    my $sys_cpu_usage = $ct_time_spent / ($sys_time_total / 100);

    $perfdata .= sprintf(" ct_cpu_user=%.2f%% ct_cpu_nice=%.2f%% ct_cpu_sys=%.2f%% ct_cpu_idle=%.2f%% sys_cpu_time=%.2f%% sys_cpu_usage=%.2f%%",
        $ct_cpu_user, $ct_cpu_nice, $ct_cpu_sys, $ct_cpu_idle, $sys_cpu_time, $sys_cpu_usage);
}

store($CPU, "/tmp/${PROGNAME}.$OPTS{c}.cpustat");

print "Alive on " . hostname(). " ".$output." |".$perfdata, "\n";
exit $ERRORS{$state};
