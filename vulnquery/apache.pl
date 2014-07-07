#!/bin/perl

#to run, first:  apt-get install memcached libcache-memcached-perl 

# output: 
#jamie@hp:~$ perl apache.pl 2.2.23
#CVE-2013-1862 - low - mod_rewrite log escape filtering
#CVE-2013-1896 - moderate - mod_dav crash
#CVE-2012-3499 - low - XSS due to unescaped hostnames
#CVE-2012-4558 - moderate - XSS in mod_proxy_balancer


use LWP::Simple;

use Cache::Memcached;

$version=$ARGV[0];

if ($version=~m/2\.4\./) {
    $url="https://httpd.apache.org/security/vulnerabilities_24.html";
    $key="APACHE24_VULNS";
} else {
    if ($version=~m/2\.2\./) {
	$url="https://httpd.apache.org/security/vulnerabilities_22.html";   
	$key="APACHE22_VULNS";
    } else {
	die "Unsupported version\n";
    }
}

$memd = new Cache::Memcached {
    'servers' => [ "127.0.0.1:11211" ],
    'debug' => 0,
    'compress_threshold' => 10_000,
};

$result=$memd->get("$key");

if ($result!~m/html/) {

#    print "Cache miss\n";

    $result=get $url;

    $memd->set("$key", $result, 7200);
} else {
    #print "Cache hit\n";
}


while ($result=~m/[a-zA-Z0-9]+/) {

    ($line,$result)=split(m/\n/, $result, 2);
    
    if ($line=~m/name="CVE-([\d\-]+)">([^<]+)/) {

	$cve="CVE-$1";
	$issue=$2;
    }
    
    if ( $line=~m/(low|moderate|important):/ ) {
	$severity=$1;
    }

    if ($line=~m/Affects:/) {
	($affected,$result)=split(m/\n/, $result, 2);

	if ($affected=~m/$version/) {
	    print "$cve - $severity - $issue\n";
	}
    }
    
}



