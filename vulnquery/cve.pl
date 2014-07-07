#!/bin/perl

#to run, first:  apt-get install memcached libcache-memcached-perl 

# output: 
#$ perl cve.pl CVE-2005-4838 
#CVE-2005-4838 - CVSS2 4.3 - MEDIUM - Multiple cross-site scripting (XSS) vulnerabilities in the example web applications for Jakarta Tomcat 5.5.6 and earlier allow remote attackers to inject arbitrary web script or HTML via (1) el/functions.jsp, (2) el/implicit-objects.jsp, and (3) jspx/textRotate.jspx in examples/jsp2/, as demonstrated via script in a request to snp/snoop.jsp.  NOTE: other XSS issues in the manager were simultaneously reported, but these require admin access and do not cross privilege boundaries.

use LWP::Simple;

use Cache::Memcached;

$cve=$ARGV[0];

if ($cve!~m/^CVE-\d+-\d+$/) {
    die "malformed CVE - use CVE-2005-4838\n";
}

$url="https://web.nvd.nist.gov/view/vuln/detail?vulnId=".$cve;
$key=$cve."_NVD";

$memd = new Cache::Memcached {
    'servers' => [ "127.0.0.1:11211" ],
    'debug' => 0,
    'compress_threshold' => 10_000,
};

$result=$memd->get("$key");

if ($result!~m/html/) {

    $result=get $url;

    $memd->set("$key", $result, 72000);
}

while ($result=~m/[a-zA-Z0-9]+/) {


    ($line,$result)=split(m/\n/, $result, 2);


    if ($line=~m!<h4>Overview</h4>!) {
	($overview,$result)=split(m/\n/, $result, 2);
	if ($overview=~m!<p>(.*)</p>!) {
	    $overview=$1;
	}
    }
    
    
    if ($line=~m!<h5>CVSS Severity!) {
	($rating,$result)=split(m/\n/, $result, 2);
	
	if ($rating=~m!>(\d+\.\d+)+<!) {
	    $cvss2=$1;
	}
	
	if ($rating=~m/(HIGH|MEDIUM|LOW)/) {
	    $risk=$1;
	}
    }
}

print "$cve - CVSS2 $cvss2 - $risk - $overview\n";



