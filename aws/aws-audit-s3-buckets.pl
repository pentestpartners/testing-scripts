#!/usr/bin/perl 
use JSON qw( decode_json );

#$regionlist=`aws ec2 describe-regions | grep RegionName | cut -f 2 -d':' | tr -d ' "'`;

$ARGC=1+$#ARGV;

if ($ARGC==0) {
    $region="eu-west-1";
} else {
    if ($ARGV[0]=~m/help/) {
	print "usage: perl json-both.pl [region]\n\neu-west-1 is assumed if no region is given\n'perl aws-audit-security-groups.pl list' to list regions";
    } elsif ($ARGV[0]=~m/list/) {
	$regionlist=`aws ec2 describe-regions | grep RegionName | cut -f 2 -d':' | tr -d ' "'`;
	print STDERR "$regionlist\n";
    }
    else 
    {
	$region=$ARGV[0];
    }
}

print STDERR "Querying $region\n";

# instances
my $jsoni = `aws --output json --region=$region s3api list-buckets`;

print STDERR "Got bucket list...\n";

my $decoded = decode_json($jsoni);

my $owner = $decoded->{'Owner'}->{'DisplayName'};

print "Owner $owner\n";

my @buckets = @{ $decoded->{'Buckets'} };

foreach my $f ( @buckets ) {

    $cdate=$f->{"CreationDate"};    
    $bname=$f->{'Name'};
    
    print "Bucket $bname \n";    
    
    my $jsonsg = `aws --output=json --region=$region s3api get-bucket-acl --bucket $bname`;

    my $decoded = decode_json($jsonsg);

    my @secgrp = @{ $decoded->{'Grants'} };

    foreach my $f ( @secgrp ) {
	$grantee=$f->{"Grantee"}->{'DisplayName'};
	if ($grantee eq "") {
	    $grantee=$f->{"Grantee"}->{'URI'};
	    if ($grantee=~/AllUsers$/) {
              $grantee="All Users";
            }
	}
	$perm=$f->{"Permission"};

	print "Grantee/perm : $grantee / $perm\n";

    }
}

