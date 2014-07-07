#!/bin/perl

#to run, first:  apt-get install memcached libcache-memcached-perl 

# output: 
#$ perl tomcat.pl 5.0.30
#CVE-2007-2449 - Low - Cross-site scripting
#CVE-2007-2450 - Low - Cross-site scripting
#CVE-2007-3382 - Low - Session hi-jacking
#CVE-2007-3385 - Low - Session hi-jacking
#CVE-2007-1355 - Moderate - Cross-site scripting
#CVE-2005-2090 - Important - Information disclosure
#CVE-2007-1860 - Important - Directory traversal
#CVE-2007-1358 - Low - Cross-site scripting
#CVE-2006-7195 - Moderate - Cross-site scripting
#CVE-2007-1858 - Important - Information disclosure
#CVE-2006-7196 - Low - Cross-site scripting
#CVE-2006-3835 - Low - Directory listing
#CVE-2005-3510 - Important - Denial of service
#CVE-2005-4838 - Low - Cross-site scripting


use LWP::Simple;

use Cache::Memcached;

$version=$ARGV[0];

($va,$vb,$vc)=split(m/\./,$version);

if ($version=~m/^6\./) {
    $url="https://tomcat.apache.org/security-6.html";
    $key="TOMCAT6_VULNS";
} else {
    if ($version=~m/^7\./) {
	$url="https://tomcat.apache.org/security-7.html";
	$key="TOMCAT7_VULNS";	
    } else {
	if ($version=~m/^5\./) {
	    $url="https://tomcat.apache.org/security-5.html";
	    $key="TOMCAT5_VULNS";
	} else {	
	    die "Unsupported version\n";
	}
    }
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

while ($result=~m/[a-zA-Z0-9]+/) {

    ($line,$result)=split(m/\n/, $result, 2);
    
    if ($line=~m/>CVE-([\d\-]+)</) {

	$cve="CVE-$1";
    }
    
    if ( $line=~m/(low|moderate|important): ([^<]+)/i ) {
	$severity=$1;
	$issue=$2;
    }

    if ($line=~m/Affects: (\d)\.(\d)\.(\d+)-(\d)\.(\d)\.(\d+)/) {

	$la=$1;$lb=$2;$lc=$3;
	$ha=$4;$hb=$5;$hc=$6;

	if (($la<=$va && $va<=$ha) && ($lb<=$vb && $vb<=ha) && ($lc<=$vc && $vc<=$hc)) {
	    print "$cve - $severity - $issue\n";
	}
    }
    
}



