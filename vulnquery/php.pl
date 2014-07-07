#!/bin/perl

#to run, first:  apt-get install memcached libcache-memcached-perl 

# output: 

use LWP::Simple;

use Cache::Memcached;

$version=$ARGV[0];

($ma,$mb,$mc)=split(m/\./,$version,3);

if ($version=~m/5\./) {
    $url="http://www.php.net/ChangeLog-5.php";
    $key="PHP5_VULNS";
} else {
    die "Unsupported version\n";
}

$memd = new Cache::Memcached {
    'servers' => [ "127.0.0.1:11211" ],
    'debug' => 0,
    'compress_threshold' => 10_000,
};

$result=$memd->get("$key");

if ($result!~m/html/) {

    $result=get $url;

    $memd->set("$key", $result, 7200);
}

#print "$result";
$currentversion=0;

while ($result=~m/[a-zA-Z0-9]+/) {

    ($line,$result)=split(m/\n/, $result, 2);
#    print "$line\n";

    if ($line=~m/<h3>Version 5\.([\d\.]+)/) {
	$currentversion=$1;	
	$va=5;
	($vb,$vc)=split(m/\./,$currentversion,3);
#	print "checking 5.$currentversion\n";
    }

    if ($line=~m/CVE-(\d+-\d+)/) {

	$cve="CVE-$1";
#	print "looking up - 5.$currentversion - $version - CVE-$cve\n";
#	print "$va,$vb,$vc ; $ma,$mb,$mc\n";

	if ($ma==$va && $mb==$vb && $mc<$vc) {
	    print `perl cve.pl $cve`;
	}
    }       
}



