#!/usr/bin/perl 
use JSON qw( decode_json );
use Data::Dumper;

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

    my $bpol = `aws --output=json --region=$region s3api get-bucket-policy --bucket $bname 2>&1`;

    if ($bpol=~m/NoSuchBucketPolicy/) {
	print "No policy\n";
    } else {

	my $decoded = decode_json($bpol);

	$pol=$decoded->{'Policy'};

	$decoded=decode_json($pol);

	my @stmt = @{ $decoded->{'Statement'} };

	foreach my $s ( @stmt ) {
	    $effect=$s->{'Effect'};
	    $action=$s->{'Action'};
	    $res=$s->{'Resource'};

	    my @principals=$s->{'Principal'};

	    foreach my $p ( @principals ) {

		if (ref ($p->{'AWS'}) eq 'ARRAY') {		  

		    @pr=$p->{'AWS'};

		    foreach my $pri ( @pr ) {
			
			$pri=Dumper($pri);
			chomp($pri);

			$pri=~s/\$VAR1 =/array/;
			
			if (($res=~m/\*/) || $pri=~m/\*/) {
			    print "Resource $res, principal $pri, Effect $effect, Action $action\n";
			}
		    }
		    
		} else {
		    $pr=$p->{'AWS'};
		    if (($res=~m/\*/) || $pr=~m/\*/) {
			print "Resource $res, principal $pr, Effect $effect, Action $action\n";
		    }      	
		}
	    }	   
	} 
	
    }

    my $content = `aws --output=json --region=$region s3api list-objects --max-items 100 --bucket $bname`;

    my $decoded = decode_json($content);   

    my @data = @{ $decoded->{'Contents'} };

    foreach my $f ( @data ) {
	$key=$f->{'Key'};

	$listresult=`curl --silent -r 0-99 -D - "https://$bname.s3.amazonaws.com/$key"`;

	if ($listresult=~m!HTTP/\d.\d 20[06]!) {
	    print "*** Anon read access for key https://$bname.s3.amazonaws.com/$key\n";
	} else {
#	    print "No anon read access to $key \n";
	}
    }

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

    $listresult=`wget -q -O - https://$bname.s3.amazonaws.com/`;

    if ($listresult=~m/ListBucketResult/) {
	print "*** Could list contents via https://$bname.s3.amazonaws.com/\n";
    }
}

