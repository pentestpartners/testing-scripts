#!/usr/bin/perl 
use JSON qw( decode_json );

$ARGC=1+$#ARGV;

#$regionlist=`aws ec2 describe-regions | grep RegionName | cut -f 2 -d':' | tr -d ' "'`;

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
my $jsoni = `aws --output json --region=$region ec2 describe-instances`;

print STDERR "Got instances...\n";

my $decoded = decode_json($jsoni);

my @reserv = @{ $decoded->{'Reservations'} };

foreach my $f ( @reserv ) {

    my @instances = @{ $f->{'Instances'} };

    foreach my $g ( @instances ) {	

	$platf=$f->{"Platform"};    
	$instid=$g->{'InstanceId'};
	$publicip=$g->{'PublicIpAddress'};

	my @secgrp = @{ $g->{'SecurityGroups'} };

	foreach my $h ( @secgrp ) {
	    $secg=$h->{'GroupName'};

	    $hash_ip{$secg}="$publicip,".$hash_ip{$secg};
	    $hash_inst{$secg}="$instid,".$hash_inst{$secg};
	}
    }
}

print STDERR "Got security groups...\n";

my $jsonsg = `aws --output=json --region=$region ec2 describe-security-groups`;

my $decoded = decode_json($jsonsg);

my @secgrp = @{ $decoded->{'SecurityGroups'} };
foreach my $f ( @secgrp ) {
    $desc=$f->{"Description"};
    $group=$f->{"GroupName"};

    my @ipperm = @{ $f->{'IpPermissions'} };

    foreach my $g ( @ipperm ) {	
	$toport=$g->{'ToPort'};
	$fromport=$g->{'FromPort'};
	$proto=$g->{'IpProtocol'};

	my @cidr = @{ $g->{'IpRanges'} };
	foreach my $h ( @cidr ) {
	    $cidr=$h->{'CidrIp'};
	    if ($cidr=~m!0\.0\.0\.0/0!) {

		if ($hash_ip{$group} ne "") {
		    $ips=$hash_ip{$group};
		    chop($ips);
		    print "Group Name : $group\n";
		    print "Description: $desc\n";
		    print "Used for these hosts: ".$ips."\n";
		    if ($proto==-1) { 
			print "any IP traffic, from source $cidr\n";
		    } else {
			if ($fromport ne $toport) {
			    print "dst ports $fromport:$toport/$proto, from source $cidr\n";
			} else {
			    print "dst ports $fromport/$proto, from source $cidr\n";
			}
		    }
		    print "\n";
		}
	    }
	}
    }
}

