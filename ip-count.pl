#!/usr/bin/perl -w
use strict;

use Socket;
use Getopt::Long;
use File::Basename;

my %o=();
my ($file, $pattern, $format, $min, $max);
GetOptions( \%o, 'help|h|?','file|f=s','pattern|p=s','format|l=s','min=i','max=i');

if (defined $o{help}) {
    print "Usage: " . basename($0) . " --file|-f <filename> [--pattern|-p <pattern>] [--format|-l <format>] [--min <min>] [--max <max>]\n\n";
    print "       --help|-h|-? prints this message and exits.\n\n";
    print "       <filename>   is required, lists the file you wish to pull the IP hit counts from.\n\n";
    print "       <pattern>    is optional, but limits the results to only lines containing <pattern>,\n";
    print "                    a regular expression. Useful to limit by time like: '02/Aug/2011:21:[12]'.\n\n";
    print "       <format>     is optional, specifying the format of the logfile (common, combined, or IIS).\n\n";
    print "       <min> and <max> can be used individually or together to narrow the results further,\n";
    print "                    printing only IPs that have at least <min> hits or no more than <max> hits.\n\n";
    print "\n      *Note: For larger log files (>100MB) or when your server is currently under high load,\n";
    print "             it is probably a good idea to grep the log file for the pattern you would enter here,\n";
    print "             piping the output to a file, and then then run this script on that smaller file.\n\n";
    exit;
}

if (defined $o{file}) {
    $file = $o{file};
} else {
    print "Please enter a filename to parse. Use --help or -h for more help.\n";
    exit;
}

$pattern = $o{pattern} if defined $o{pattern};

$format = (defined $o{format}) ? $o{format} : 'common';

if (defined $o{min}) {
    $min = $o{min};
} else {
    $min = 0;
}

if (defined $o{max}) {
    $max = $o{max};
} else {
    $max = 1_000_000_000;
}

my %IPs = ();
my $total_ips = 0;
my $filtered_matched_ips = 0;

print "\$file is: $file\n" if defined $file;
print "\$pattern is: $pattern\n" if defined $pattern;

open (FILE, '<', $file) or die "Couldn't open $file : $!";
print "Reading $file\n";

while (<FILE>){
    if (defined $pattern) {
        next unless m#$pattern#g;
    }
    if (uc $format eq 'IIS') {
        chomp;
        next if /^#/; # Skip commented headers in IIS logs
        my %r = &parse_iis_line_to_hash($_);
        $IPs{$r{c_ip}}++;
    } else {
        chomp;
        my %r = &parse_apache_line_to_hash($_);
        $IPs{$r{client}}++;
    }

    $total_ips++;
}

foreach my $IP (sort { $IPs{$b} <=> $IPs{$a} } keys %IPs) {
    next if $IPs{$IP} < $min or $IPs{$IP} > $max;
    my $hostname = &find_ip_hostname($IP);
    print $IPs{$IP}." hits from $IP ($hostname)\n";
    $filtered_matched_ips += $IPs{$IP};
}

print "$filtered_matched_ips total filtered hits.\n" if ($filtered_matched_ips != $total_ips);
print "$total_ips total matched hits.\n";

sub find_ip_hostname() {
    my $ip = shift;
    my %our_ips = ('66.159.90.67' => 'k4health GSA1',
                   '66.159.90.68' => 'k4health GSA2');

    if ( defined($our_ips{$ip}) ) {
        return $our_ips{$ip};
    } else {
        my $name = gethostbyaddr(inet_aton($ip),AF_INET);
        return defined($name) ? $name : 'NO PTR RECORD';
    }
}

sub parse_apache_line_to_hash() {
    # Adapted from ApacheLog::Parser, which only does 'combined'
    my ($line) = @_;
    my @fields = qw( client ruser login dtime request file params proto code bytes refer agent );
    my $common_rx = qr/^
      ([^ ]+)\ +([^ ]+)\ +([^\[]+)\ +            # client, ruser, login
      \[([^\]]+)\]\ +                            # date
      "(.*)"\ +(\d+)\ +(\d+|-)                   # req, code, bytes
    $/x;
    my $combined_rx = qr/^
      ([^ ]+)\ +([^ ]+)\ +([^\[]+)\ +            # client, ruser, login
      \[([^\]]+)\]\ +                            # date
      "(.*)"\ +(\d+)\ +(\d+|-)\ +                # req, code, bytes
      "(.*)"\ +"(.*)"                            # refer, agent
    $/x;
    my %log;
    my $req;

    if ($line =~ $common_rx) {
        ($log{client}, $log{ruser}, $log{login}, $log{dtime}, $req, $log{code}, $log{bytes}) =
        ($1, $2, $3, $4, $5, $6, $7);
    } elsif ($line =~ $combined_rx) {
        ($log{client}, $log{ruser}, $log{login}, $log{dtime}, $req, $log{code}, $log{bytes}, $log{refer}, $log{agent}) =
        ($1, $2, $3, $4, $5, $6, $7, $8, $9);
    } else {
        die "Failed to parse line: $line\n";
    }

    $log{code} or die "no code in $line";

    $req =~ s/^(?:([A-Z]+) +)?//;
    $log{request} = $1 || ''; # ouch, a non-request (telnet) hack
    # just tear this off the end
    $log{proto} = ($req =~ s{ +(HTTP/\d+\.\d+)$}{}) ? $1 : '';

    ($log{file},$log{params}) = split(/\?/, $req, 2);
    defined($log{$_}) or $log{$_} = '' for('file', 'params');
    $log{params} =~ s/\\"/"/g;

    (!defined($log{$_}) or ($log{$_} eq '-')) and $log{$_} = ''
      for('ruser', 'login', 'request', 'code', 'refer', 'agent');
    $log{bytes} = 0 if($log{bytes} eq '-');

    return %log;
}

sub parse_iis_line_to_hash() {
   my ($line) = @_;
   my %log;
   my @fields = qw(date time s_sitename s_ip cs_method cs_uri_stem cs_uri_query server_port
                   cs_username c_ip c_ua sc_status sc_substatus sc_win32_status);
   @log{@fields} = split(/ /, $line);
   return %log;
}
