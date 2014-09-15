#!/usr/bin/perl -w

use strict;

use IO::Socket::UNIX qw( SOCK_STREAM );

$ARGV[0] or die("Usage: status.pl <socket>\n");

my $socket = IO::Socket::UNIX->new(
   Type => SOCK_STREAM,
   Peer => $ARGV[0],
)
   or die("Can't connect to server: $!\n");

foreach my $line (<$socket>) {
	print $line;
}
