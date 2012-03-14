#!/usr/bin/perl -w
use strict;

use Socket;
use Getopt::Helpful;
use File::Basename;

my %o=();
my ($file, $pattern);
my $format = 'common';
my $min = 0;
my $max = 1_000_000_000_000;
my $helper = Getopt::Helpful->new(
    usage => 'CALLER (-f) <filename> [options]',
    [
        'f|file=s',\$file,
        '<filename>',
        "Required, lists the file you wish to pull the IP hit counts from."
    ],
    [
        'p|pattern=s',\$pattern,
        '<pattern>',
        "Optional, limits the results to only lines containing the regex <pattern>.
        Useful to limit by time like: '02/Aug/2011:21:[12]'. (Slashes are matched)"
    ],
    [
        'l|format=s',\$format,
        '<format>',
        "Optional, required if parsing IIS logs. Specify --format=IIS if doing so."
    ],
    [
        'min=i',\$min,
        '<num>',
        "Optional, can be used by itself or with --max to narrow results by number of hits."
    ],
    [
        'max=i',\$max,
        '<num>',
        "Optional, can be used by itself or with --min to narrow results by number of hits."
    ],
    '+help',
);

$helper->Get();

$file or $file = shift or die "Please enter a filename to parse. Use --help or -h for more help.\n";

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
