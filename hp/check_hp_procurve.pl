#!/usr/bin/perl
#
# Nagios plugin to check switch inventory. The plugin collects
# information that is used by the other check_hp_procurve_
# scripts which we do not want to collect on every run like
# port names, VLAN taggings, ...
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
use Net::SNMP qw(:snmp);
use SNMP::Info;
use Storable;
use Data::Dumper;

use vars qw($PROGNAME $VERSION %OPTS $SWITCH $PERFDATA $info $invcache @MODES $output $perfdata $status $session $error);

$VERSION        = 1.00;
$PROGNAME       = 'check_hp_procurve';

%OPTS           = ();
@MODES          = qw(device port);

$SWITCH         = {
    'ports'             => {},
    'vlans'             => {},
    'trunks'            => {},
    'iids'              => {}
};

$output = "";
$perfdata = "";

# Warning and critical levels
my $device_mem_warn = 80;
my $device_mem_crit = 95;
my $device_cpu_warn = 80;
my $device_cpu_crit = 90;

# SNMP OID's
# 64-bit counters
my $snmpIfHCInOctets            = '1.3.6.1.2.1.31.1.1.1.6';
my $snmpIfHCInUcastPkts         = '1.3.6.1.2.1.31.1.1.1.7';
my $snmpIfHCInMulticastPkts     = '1.3.6.1.2.1.31.1.1.1.8';
my $snmpIfHCInBroadcastPkts     = '1.3.6.1.2.1.31.1.1.1.9';
my $snmpIfHCOutOctets           = '1.3.6.1.2.1.31.1.1.1.10';
my $snmpIfHCOutUcastPkts        = '1.3.6.1.2.1.31.1.1.1.11';
my $snmpIfHCOutMulticastPkts    = '1.3.6.1.2.1.31.1.1.1.12';
my $snmpIfHCOutBroadcastPkts    = '1.3.6.1.2.1.31.1.1.1.13';
# status:
my $snmpIfAdminStatus           = '1.3.6.1.2.1.2.2.1.7';
my $snmpIfOperStatus            = '1.3.6.1.2.1.2.2.1.8';
my $snmpIfSpeed                 = '1.3.6.1.2.1.31.1.1.1.15';
# errors:
my $snmpIfInDiscards            = '1.3.6.1.2.1.2.2.1.13';
my $snmpIfInErrors              = '1.3.6.1.2.1.2.2.1.14';
my $snmpIfOutDiscards           = '1.3.6.1.2.1.2.2.1.19';
my $snmpIfOutErrors             = '1.3.6.1.2.1.2.2.1.20';

# ----------------------------------------------------------------------
# HELPER
#
sub _version() {
    print "$PROGNAME $VERSION\n";
}

sub _usage() {
    print "\nUsage: ${PROGNAME} -H host [-C community] [-i inventory-interval] [-u perfdata-interval] [-d] -m MODE [-P port]\n",
        "\n",
        "       -H host\n",
        "          The hostname to connect to. Default: localhost\n",
        "       -C community\n",
        "          Sets the SNMP community string. Default: public\n",
        "       -i inventory-interval\n",
        "          Sets the inventory update interval. Default: 3600\n",
        "       -d\n",
        "          Enables debug output.\n",
        "       -m MODE\n",
        "          Sets the mode of operation. Known modes are:\n",
        "            device - checks the siwtch device itself\n",
        "            port - checks the switch port indicated by -P\n",
        "       -P port\n",
        "          The switch port to check if in port mode (see -m).\n",
        "\n";
    exit 1;
}

sub _exit {
    print @_;
    exit $ERRORS{'UNKNOWN'};
}

sub format_dec {
    my $prefix_x="";
    my ($x)=@_;

    if ( $x>1000000000000000000 ) {
        $x=$x/1000000000000000000;
        $prefix_x="E";
    }
    elsif ( $x>1000000000000000 ) {
        $x=$x/1000000000000000;
        $prefix_x="P";
    }
    elsif ( $x>1000000000000 ) {
        $x=$x/1000000000000;
        $prefix_x="T";
    }
    elsif ( $x>1000000000 ) {
        $x=$x/1000000000;
        $prefix_x="G";
    }
    elsif ( $x>1000000 ) {
        $x=$x/1000000;
        $prefix_x="M";
    }
    elsif ( $x>1000 ) {
        $x=$x/1000;
        $prefix_x="K";
    }

    $x = sprintf("%.2f",$x);
    return $x.$prefix_x;
}

sub format_bin {
    my $prefix_x="";
    my ($x)=@_;

    if ( $x>1152921504606846976 ) {
        $x=$x/1152921504606846976;
        $prefix_x="E";
    }
    elsif ( $x>1125899906842624 ) {
        $x=$x/1125899906842624;
        $prefix_x="P";
    }
    elsif ( $x>1099511627776 ) {
        $x=$x/1099511627776;
        $prefix_x="T";
    }
    elsif ( $x>1073741824 ) {
        $x=$x/1073741824;
        $prefix_x="G";
    }
    elsif ( $x>1048576 ) {
        $x=$x/1048576;
        $prefix_x="M";
    }
    elsif ( $x>1024 ) {
        $x=$x/1024;
        $prefix_x="K";
    }

    $x = sprintf("%.2f",$x);
    return $x.$prefix_x;
}

# ----------------------------------------------------------------------
# INVENTORY UPDATE
#
sub update_inventory() {

    init_info();

    # get switch information
    $SWITCH->{'uptime'} = $info->uptime();
    $SWITCH->{'serial'} = $info->serial();
    $SWITCH->{'name'} = $info->name();
    $SWITCH->{'model'} = $info->model();
    $SWITCH->{'location'} = $info->location();
    $SWITCH->{'os_version'} = $info->os_ver();
    $SWITCH->{'stp_version'} = $info->stp_ver();
    $SWITCH->{'stp_updated'} = $info->stp_time();
    $SWITCH->{'fw_version'} = $info->e_fwver()->{1};

    # get vlan mapping
    my $tbl_vlan_index = $info->qb_v_name();

    foreach my $vid (keys %$tbl_vlan_index) {
        $SWITCH->{'vlans'}->{$vid} = {
            name        => $tbl_vlan_index->{$vid}
        };
    }

    # get interface information
    my $tbl_interfaces = $info->interfaces();
    my $tbl_duplex = $info->i_duplex();
    my $tbl_if_type = $info->i_type();
    my $tbl_if_speed = $info->i_speed();
    my $tbl_if_mtu = $info->i_mtu();
    my $tbl_if_mac = $info->i_mac();
    my $tbl_if_name = $info->i_name();
    my $tbl_if_alias = $info->i_alias();
    my $tbl_if_pvid = $info->i_vlan();
    my $tbl_if_vlans = $info->i_vlan_membership();

    foreach my $iid (keys %$tbl_interfaces) {
        my $port = $tbl_interfaces->{$iid};

        my $type = lc($tbl_if_type->{$iid});
        my $vlans = ();
        if (exists($tbl_if_vlans->{$iid})) {
            foreach my $vlan (sort(@{$tbl_if_vlans->{$iid}})) {
                $vlans->{$vlan}->{'name'} = $SWITCH->{'vlans'}->{$vlan}->{'name'};
            }
        }

        if ($type eq 'ethernetcsmacd') {
            $SWITCH->{'iids'}->{$iid} = {
                type    => 'ports',
                port    => $port
            };
            $SWITCH->{'ports'}->{$port} = {
                iid     => $iid,
                duplex  => $tbl_duplex->{$iid},
                mtu     => $tbl_if_mtu->{$iid},
                speed   => $tbl_if_speed->{$iid},
                name    => $tbl_if_name->{$iid},
                label   => $tbl_if_alias->{$iid},
                mac     => $tbl_if_mac->{$iid},
                pvid    => $tbl_if_pvid->{$iid},
                vlans   => $vlans,
                peers   => [],
            };
        }
        elsif ($type eq 'propvirtual') {
            foreach my $vid (keys %{$SWITCH->{'vlans'}}) {
                if ($SWITCH->{'vlans'}->{$vid}->{'name'} eq $port) {
                    $SWITCH->{'vlans'}->{$vid}->{'iid'} = $iid;
                    $SWITCH->{'vlans'}->{$vid}->{'mtu'} = $tbl_if_mtu->{$iid};
                    $SWITCH->{'vlans'}->{$vid}->{'mac'} = $tbl_if_mac->{$iid};
                }
            }
        }
        elsif ($type eq 'propmultiplexor') {
            $SWITCH->{'iids'}->{$iid} = {
                type    => 'trunks',
                port    => $port
            };
            $SWITCH->{'trunks'}->{$port} = {
                iid     => $iid,
                mtu     => $tbl_if_mtu->{$iid},
                speed   => $tbl_if_speed->{$iid},
                name    => $port,
                label   => $tbl_if_alias->{$iid},
                mac     => $tbl_if_mac->{$iid},
                pvid    => $tbl_if_pvid->{$iid},
                vlans   => $vlans,
                peers   => []
            };
        }
    }

    my $tbl_fw_mac = $info->fw_mac();
    my $tbl_fw_port = $info->fw_port();
    my $tbl_bp_index = $info->bp_index();

    foreach my $idx (keys %$tbl_fw_mac) {
        my $bp = $tbl_fw_port->{$idx};
        my $iid = $tbl_bp_index->{$bp};
        my $port = $tbl_interfaces->{$iid};
        if (exists($SWITCH->{'ports'}->{$port})) {
            push(@{$SWITCH->{'ports'}->{$port}->{'peers'}}, $tbl_fw_mac->{$idx});
        }
        elsif (exists($SWITCH->{'trunks'}->{$port})) {
            push(@{$SWITCH->{'trunks'}->{$port}->{'peers'}}, $tbl_fw_mac->{$idx});
        }
    }

    store($SWITCH, $invcache);
}

# ----------------------------------------------------------------------
# PORT CHECK
#
sub check_port($$) {
    my $port = shift;
    my $cfile = shift;

    init_session();

    _exit("Could not find interface port $port.\n") if (! exists($SWITCH->{'ports'}->{$port}));

    my $iid = $SWITCH->{'ports'}->{$port}->{'iid'};

    my @oids;

    # link
    push(@oids, $snmpIfOperStatus . "." . $iid);
    push(@oids, $snmpIfAdminStatus . "." . $iid);
    push(@oids, $snmpIfSpeed . "." . $iid);
    # inputs
    push(@oids, $snmpIfHCInOctets . "." . $iid);
    push(@oids, $snmpIfHCInUcastPkts . "." . $iid);
    push(@oids, $snmpIfHCInMulticastPkts . "." . $iid);
    push(@oids, $snmpIfHCInBroadcastPkts . "." . $iid);
    push(@oids, $snmpIfInDiscards . "." . $iid);
    push(@oids, $snmpIfInErrors . "." . $iid);
    # outputs
    push(@oids, $snmpIfHCOutOctets . "." . $iid);
    push(@oids, $snmpIfHCOutUcastPkts . "." . $iid);
    push(@oids, $snmpIfHCOutMulticastPkts . "." . $iid);
    push(@oids, $snmpIfHCOutBroadcastPkts . "." . $iid);
    push(@oids, $snmpIfOutDiscards . "." . $iid);
    push(@oids, $snmpIfOutErrors . "." . $iid);

    my $res;

    _exit("Unable to retrieve performance information for port $port: " . $session->error ."\n")
        if (!defined($res = $session->get_request(@oids)));

    my $if_speed = $res->{ $snmpIfSpeed . "." . $iid } * 1000000;

    my $update_time = time;

    # Interface inputs
    my $in_bits = $res->{ $snmpIfHCInOctets . "." . $iid }*8;
    my $in_ucast = $res->{ $snmpIfHCInUcastPkts . "." . $iid };
    my $in_mcast = $res->{ $snmpIfHCInMulticastPkts . "." . $iid };
    my $in_bcast = $res->{ $snmpIfHCInBroadcastPkts . "." . $iid };
    my $in_discards = $res->{ $snmpIfInDiscards . "." . $iid };
    my $in_errors = $res->{ $snmpIfInErrors . "." . $iid };
    # Interface outputs
    my $out_bits = $res->{ $snmpIfHCOutOctets . "." . $iid }*8;
    my $out_ucast = $res->{ $snmpIfHCOutUcastPkts . "." . $iid };
    my $out_mcast = $res->{ $snmpIfHCOutMulticastPkts . "." . $iid };
    my $out_bcast = $res->{ $snmpIfHCOutBroadcastPkts . "." . $iid };
    my $out_discards = $res->{ $snmpIfOutDiscards . "." . $iid };
    my $out_errors = $res->{ $snmpIfOutErrors . "." . $iid };

    my $if_admin = $res->{ $snmpIfAdminStatus . "." . $iid };
    my $if_status = $res->{ $snmpIfOperStatus . "." . $iid };

    # Assume ok
    $status = "OK";

    my $if_name = 'Interface ' . $port;
    if (exists($SWITCH->{'ports'}->{$port}->{'label'}) &&
        length($SWITCH->{'ports'}->{$port}->{'label'}) > 0) {
        $if_name = $SWITCH->{'ports'}->{$port}->{'label'};
    }

    if ($if_admin != 1) {
        print $if_name, " is administratively down.\n";
        exit $ERRORS{$status};
    }
    elsif($if_status != 1) {
        print $if_name, " is operational down.\n";
        exit $ERRORS{$status};
    }

    my $if_in_traffic=0;
    my $if_out_traffic=0;
    my $if_in_usage = 0;
    my $if_out_usage = 0;
    my $if_in_ucast = 0;
    my $if_out_ucast = 0;
    my $if_in_bcast = 0;
    my $if_out_bcast = 0;
    my $if_in_mcast = 0;
    my $if_out_mcast = 0;
    my $if_in_discards = 0;
    my $if_out_discards = 0;
    my $if_in_errors = 0;
    my $if_out_errors = 0;

    if (-f $cfile)
    {
        eval { $PERFDATA = retrieve $cfile };
		if ($@) {
			unlink $cfile;
			$PERFDATA = undef;
		}
	}
	
	if (defined($PERFDATA)) 
	{
        if ($update_time-$PERFDATA->{'updated'} > 0)
        {
            $if_in_traffic = ($in_bits-$PERFDATA->{'in_bits'})/($update_time-$PERFDATA->{'updated'});
            $if_out_traffic = ($out_bits-$PERFDATA->{'out_bits'})/($update_time-$PERFDATA->{'updated'});

            $if_in_usage  = sprintf("%.2f", ($if_in_traffic*100)/$if_speed);
            $if_out_usage = sprintf("%.2f", ($if_out_traffic*100)/$if_speed);

            $if_in_traffic  = sprintf("%.2f", $if_in_traffic);
            $if_out_traffic = sprintf("%.2f", $if_out_traffic);

            $if_in_ucast = $in_ucast - $PERFDATA->{'in_ucast'};
            $if_out_ucast = $out_ucast - $PERFDATA->{'out_ucast'};
            $if_in_mcast = $in_mcast - $PERFDATA->{'in_mcast'};
            $if_out_mcast = $out_mcast - $PERFDATA->{'out_mcast'};
            $if_in_bcast = $in_bcast - $PERFDATA->{'in_bcast'};
            $if_out_bcast = $out_bcast - $PERFDATA->{'out_bcast'};

            $if_in_errors = $in_errors - $PERFDATA->{'in_errors'};
            $if_out_errors = $out_errors - $PERFDATA->{'out_errors'};

            $if_in_discards = $in_discards - $PERFDATA->{'in_discards'};
            $if_out_discards = $out_discards - $PERFDATA->{'out_discards'};

			if ($if_in_errors > 0 ||
                $if_out_errors > 0) {
                $output .= "Packet errors counted! ";
                $status = "WARNING";
            }
        }
        else
        {
            $status = "UNKNOWN";
        }
    }
    else
    {
        # No data yet
        $status = "UNKNOWN";
    }

    my $vlan = '';
    my $pvid = $SWITCH->{'ports'}->{$port}->{'pvid'};
    foreach my $vid (sort(keys %{$SWITCH->{'ports'}->{$port}->{'vlans'}})) {
        if (length($vlan) > 0) {
            $vlan .= ", ";
        }
        if ("$vid" eq "$pvid") {
            $vlan .= "U" . $vid. " (" . $SWITCH->{'vlans'}->{$vid}->{'name'}.")";
        }
        else {
            $vlan .= "T" . $vid. " (" . $SWITCH->{'vlans'}->{$vid}->{'name'}.")";
        }
    }

    $output .= sprintf("%s: avg %sbps (%.2f%%) rx: %sbps tx: %sbps (Speed: %s, MAC: %s, VLANs: %s, Peers: %s) ",
        $if_name,
        format_bin($if_in_traffic+$if_out_traffic),
        $if_in_usage + $if_out_usage,
        format_bin($if_in_traffic),
        format_bin($if_out_traffic),
        $SWITCH->{'ports'}->{$port}->{'speed'},
        $SWITCH->{'ports'}->{$port}->{'mac'},
        $vlan,
        join(', ', @{$SWITCH->{'ports'}->{$port}->{'peers'}}),
    );

    $perfdata .= sprintf("total_bw=%d total_use=%.2f%% total_ucast=%d total_bcast=%d total_mcast=%d in_bw=%d in_use=%.2f%% in_ucast=%d in_bcast=%d in_mcast=%d in_errors=%d in_discards=%d out_bw=%d out_use=%.2f%% out_ucast=%d out_bcast=%d out_mcast=%d out_errors=%d out_discards=%d",
        $if_in_traffic+$if_out_traffic,
        $if_in_usage+$if_out_usage,
        $if_in_ucast+$if_out_ucast,
        $if_in_bcast+$if_out_bcast,
        $if_in_mcast+$if_out_mcast,
        $if_in_traffic,
        $if_in_usage,
        $if_in_ucast,
        $if_in_bcast,
        $if_in_mcast,
        $if_in_errors,
        $if_in_discards,
        $if_out_traffic,
        $if_out_usage,
        $if_out_ucast,
        $if_out_bcast,
        $if_out_mcast,
        $if_out_errors,
        $if_out_discards
    );

    $PERFDATA = {
        'updated'       => $update_time-1,
        'in_bits'       => $in_bits,
        'in_ucast'      => $in_ucast,
        'in_mcast'      => $in_mcast,
        'in_bcast'      => $in_bcast,
        'in_discards'   => $in_discards,
        'in_errors'     => $in_errors,
        'out_bits'      => $out_bits,
        'out_ucast'     => $out_ucast,
        'out_mcast'     => $out_mcast,
        'out_bcast'     => $out_bcast,
        'out_discards'  => $out_discards,
        'out_errors'    => $out_errors,
    };

    store($PERFDATA, $cfile);
    print $output . '| ' .$perfdata . "\n";
    exit $ERRORS{$status};
}

# ----------------------------------------------------------------------
# DEVICE CHECK
#
sub check_device() {

    init_info();

    $status = 'OK';

    my $fan_status = $info->fan();
    if ($fan_status ne 'good') {
        $status = 'CRITICAL';
    }

    my $ps1_status = $info->ps1_status();
    if ($ps1_status != 'good') {
        $status = 'CRITICAL';
    }
    my $ps2_status = $info->ps2_status();
    if ($ps2_status ne 'notPresent' && $ps2_status != 'good' && $status ne 'CRITICAL') {
        $status = 'WARNING';
    }

    $output .= sprintf("%s - HP ProCurve %s (SER: %s FWVer: %s OSVer: %s FANS: %s PS1: %s PS2: %s) ",
        $SWITCH->{'name'},
        $SWITCH->{'model'},
        $SWITCH->{'serial'},
        $SWITCH->{'fw_version'},
        $SWITCH->{'os_version'},
        $fan_status,
        $ps1_status,
        $ps2_status
    );

    my $cpu_usage = $info->cpu();
    if ($cpu_usage >= $device_cpu_crit) {
        $status = "CRITICAL";
    }
    elsif ($status ne 'CRITICAL' && $cpu_usage >= $device_cpu_warn) {
        $status = "WARNING";
    }

    my $mem_total = $info->mem_total();
    my $mem_used = $info->mem_used();
    my $mem_usage = $mem_used/($mem_total/100);
    if ($mem_usage > $device_mem_crit) {
        $status = "CRITICAL";
    }
    elsif ($status ne 'CRITICAL' && $mem_usage > $device_mem_warn) {
        $status = "WARNING";
    }
    my $mem_crit = $mem_used/100*$device_mem_crit;
    my $mem_warn = $mem_used/100*$device_mem_warn;

    $perfdata .= sprintf("cpu_usage=%d%%;%d%%;%d%% mem_usage=%-1d%%;%d%%;%d%% mem_total=%db mem_used=%db;%-1db;%-1db",
        $cpu_usage, $device_cpu_warn, $device_cpu_crit,
        $mem_usage, $device_mem_warn, $device_mem_crit,
        $mem_total,
        $mem_used, $mem_warn, $mem_crit
    );

    print $output . '| ' . $perfdata . "\n";
    exit $ERRORS{$status};
}

# ----------------------------------------------------------------------
# SNMP Info
#
sub init_info() {

    return if (defined($info));

    $info = new SNMP::Info(
        AutoSpecify     => 1,
        Debug           => exists($OPTS{d}) ? 1 : 0,
        DestHost        => exists($OPTS{H}) ? $OPTS{H} : 'localhost',
        Community       => exists($OPTS{C}) ? $OPTS{C} : 'public',
        Version         => 2,
        BigInt          => 1,
        BulkWalk        => 1,
        LoopDetect      => 1,
    );

    $error = defined($info) ? $info->error() : undef;

    _exit("SNMP Community or version probably wrong connecting to device. $error\n") if (defined($error) || ! defined($info));
}

#
# SNMP session
#
sub init_session() {

    return if (defined($session));

    ($session, $error) = Net::SNMP->session(
        -hostname  => exists($OPTS{H}) ? $OPTS{H} : 'localhost',
        -community => exists($OPTS{C}) ? $OPTS{C} : 'public',
        -version   => 2
     );

    _exit("SNMP Community or version probably wrong connecting to device. $error\n") if !defined($session);
}

# ----------------------------------------------------------------------
# MAIN
#
_usage() if (! getopts("H:C:i:d:m:P:", \%OPTS));

if (! exists($OPTS{i})) {
    $OPTS{i} = 3600;
}
if (! exists($OPTS{m}) || !($OPTS{m} ~~ @MODES)) {
    _usage();
}

$invcache = '/tmp/'. $PROGNAME . '.' . $OPTS{H} . '.inv';

if (! -f $invcache || ((stat($invcache))[9]+$OPTS{i}) < time) {
    update_inventory();
}
else {
    $SWITCH = retrieve($invcache);
}

if ($OPTS{m} eq 'port' && exists($OPTS{P})) {
    check_port($OPTS{P}, '/tmp/'. $PROGNAME . '.' . $OPTS{H} . '.' . $OPTS{P} . '.perf');
}
elsif ($OPTS{m} eq 'device') {
    check_device();
}
else {
    _usage();
}

__END__
