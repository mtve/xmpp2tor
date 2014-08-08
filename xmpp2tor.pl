#! /usr/bin/perl

# simple xmpp server based on in.jabberd from inetdxtra by R. Rawson-Tetley

use warnings;
use strict;
use lib 'lib';

use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use AnyEvent::Log;

# start of configurable part

my $TOR_SERVICE_NAME	= 'qwe.onion';
my $TOR_SERVICE_ADDR	= '127.0.0.1';
my $TOR_SERVICE_PORT	= '5221';
my $TOR_SOCKS_ADDR	= '127.0.0.1';
my $TOR_SOCKS_PORT	= '9101';

my $XMPP_ADDR		= '127.0.0.1';
my $XMPP_PORT		= '5222';
my $XMPP_VER		= 'xmpp2tor 0.1';
my $XMPP_ROSTER_FILE	= 'roster.txt';

# end of configurable part

sub D($) {
	AE::log debug => ((caller 1)[3] || 'main') . " @_";
}

package on_destroy;

sub call(&) { bless \$_[0] }
sub DESTROY { ${$_[0]}->() }

package tor_service;

sub init {
	my ($host, $port) = ($TOR_SERVICE_ADDR, $TOR_SERVICE_PORT);
	AnyEvent::Socket::tcp_server $host, $port, \&handle;
	::D "started on $host:$port";
}

sub handle {
	my ($fh, $host, $port) = @_;
	
	::D "connected from $host:$port";
	my $h; $h = new AnyEvent::Handle (
		fh		=> $fh,
		_prevent_gc	=> \$h,
		on_error	=> sub {
			my ($h, $fatal, $message) = @_;

			$fatal ||= 0;
			::D "on_error fatal=$fatal $message";
			$h->destroy;
		},
		timeout		=> 20,
	);
	$h->push_read (line => \&first_line);
}

sub first_line {
	my ($h, $line) = @_;
	
	::D $line;

	if ($line =~ /^callme/) {
		# XXX callback ();
	} elsif ($line =~ /^callback/) {
		$h->push_write ("ok\n");
		$h->push_read (line => \&second_line);
	} else {
		AE::log error => "bad first line $line";
		$h->destroy;
	}
}

sub second_line {
	my ($h, $line) = @_;

	::D $line;
	if ($line =~ /^ok/) {
		# trusted now;
		$h->timeout (0); 
		read_message ($h);
	} else {
		AE::log error => "step 3 bad";
		$h->destroy;
	}
}

sub read_message {
	my ($h) = @_;

	$h->push_read (netstring => sub {
		my ($h, $string) = @_;

		process_message ($string);
		read_message ($h);
	});
}

sub process_message {
	my ($string) = @_;

	::D $string;

	# XXX
}

package tor_connect;

sub xxx_callme {
	my ($addr) = @_;

	my $h; $h = new AnyEvent::Handle (
#		connect 	=> [ $host, $port ],
		timeout		=> 60,
		on_error	=> sub {
			my ($h, $fatal, $message) = @_;

			$h->destroy;
		},
		on_connect	=> sub {
			my ($h) = @_;

			$h->push_write ("callme $addr");
		},
		on_drain	=> sub {
			my ($h) = @_;

			$h->push_shutdown;
		},
	);
}

package xmpp;

sub init {
	my ($host, $port) = ($XMPP_ADDR, $XMPP_PORT);
	AnyEvent::Socket::tcp_server $host, $port, \&handle;
	::D "started on $host:$port";
}

my $sid;

sub handle {
	my ($fh, $host, $port) = @_;
	
	::D "connected from $host:$port";
	my $h; $h = new AnyEvent::Handle (
		fh		=> $fh,
		on_error	=> sub {
			my ($h, $fatal, $message) = @_;

			$fatal ||= 0;
			::D "on_error fatal=$fatal " .
				"message='$message' buf=${\$h->rbuf }";
			$h->destroy;
		},
		timeout		=> 20,
		xmpp_prevent_gc	=> \$h,
	);
	$h->push_read (regex => qr!^ \s*
		<\? xml [^>]* > \s*
		< stream:stream [^>]* >
	!x, qr!.!, \&start_stream);
}

sub start_stream {
	my ($h, $data) = @_;

	::D $data;

	$data =~ /<stream:stream[^>]*\bto=["'](.*?)["']/;
	$h->{xmpp_servername} = $1 || '?';

	$sid++;
	$h->push_write (<<XML);
<?xml version='1.0'?>
<stream:stream xmlns:stream='http://etherx.jabber.org/streams'
 id='$sid' xmlns='jabber:client' from='$h->{xmpp_servername}'>
XML

	nextread ($h);
}

sub nextread {
	my ($h) = @_;

	# read eos or complete tag

	$h->push_read (regex => qr!^ \s* (
		</ stream:stream [^>]* > |
		< (\w+) \b [^>]* /> |
		< (\w+) \b [^>]* > .*? </ \3 > )
	!x, qr!.!, \&read_cb);
}

my $cur_h;

sub read_cb {
	my ($h, $data) = @_;

	::D "rx $data";

	$cur_h = $h;
	eval {
		local $_ = $data;

		s/^\s*//;

		die "eos" if m!^</!;

		/^<(\w+)/ or die "no tag";
		no strict 'refs';
		exists &{"do_$1"} or die "unknown tag $1\n";
		my $resp = &{"do_$1"} ();
		::D "tx $resp";
		$h->push_write ($resp);
		nextread ($h);
	};
	if ($@) {
		::D "error $@, closing";
		$h->destroy;
		return;
	}
}

sub do_iq {
	/^<iq[^>]*\bid=["'](.*?)["']/ or die "no id";

	my $result = "type='result' id='$1'";

	# auth
	/<query xmlns=['"]jabber:iq:auth\b/ && return <<XML;
<iq $result>${\iq_auth () }</iq>
XML

	$cur_h->{xmpp_userandresource} or die "not authorized yet";

	my $iq = "iq $result from='$cur_h->{xmpp_servername}' " .
		"to='$cur_h->{xmpp_userandresource}'";

	# ping
	/<ping/ && return <<XML;
<$iq />
XML

	# disco items
	m!<query xmlns=['"]http://jabber.org/protocol/disco#items! && return <<XML;
<$iq>
 <query xmlns='http://jabber.org/protocol/disco#items#' />
</iq>
XML

	# disco info
	m!<query xmlns=['"]http://jabber.org/protocol/disco#info! && return <<XML;
<$iq>
 <query xmlns='http://jabber.org/protocol/disco#info'>
  <identity category='services' type='jabber' name='$XMPP_VER' />
  <feature var='http://jabber.org/protocol/disco#info' />
  <feature var='http://jabber.org/protocol/disco#items' />
  <feature var='urn:xmpp:ping' />
  <feature var='jabber:iq:version' />
 </query>
</iq>
XML

	# vcard
	/<vcard/i && return <<XML;
<iq $result from='$cur_h->{xmpp_userandresource}'>
 <vCard xmlns='vcard-temp'/>
</iq>
XML

	# roster
	m!<query xmlns=["']jabber:iq:roster! && do {
		my $item = '';
		my $presence = '';
		open my $f, $XMPP_ROSTER_FILE
			or die "open $XMPP_ROSTER_FILE: $!";
		while (<$f>) {
			my ($jid, $name, $group) = split or next;

			$jid = "$jid\@$cur_h->{xmpp_servername}";

			$item .= <<XML;
<item jid='$jid' name='$name' subscription='both'>
 <group>$group</group>
</item>
XML
			$presence .= <<XML;
<presence type='unavailable' from='$jid' to='$cur_h->{xmpp_userandresource}' />
XML
		}
		return <<XML;
<iq $result from='$cur_h->{xmpp_userandresource}'>
 <query xmlns='jabber:iq:roster'>
  $item
 </query>
</iq>
$presence
XML
	};

	::D "unknown iq $_";
	return <<XML;
<$iq />
XML
}

sub iq_auth {
	my %a;
	for my $tag (qw( username resource password digest )) {
		$a{$tag} = m!<$tag>([^<>]*)</$tag>! ? $1 : '';
	}
	exists $a{username} or die "no username";

	if ($a{password}.$a{digest} &&
	    auth ($a{username}, $a{password}, $a{digest})) {
		$cur_h->{xmpp_userandresource} =
			"$a{username}\@$cur_h->{xmpp_servername}/$a{resource}";
		$cur_h->timeout (0); 
		return '';
	}

	return <<XML;
<query xmlns='jabber:iq:auth'>
 <username>$a{username}</username>
 <digest />
 <password />
 <resource />
</query>
XML
}

sub auth {
	my ($name, $pass, $digest) = @_;

	::D "name=$name pass=$pass digest=$digest";

	return 1;
}

sub do_presence { '<presence />' }

sub do_message {
	/^<message[^>]*\bto=["'](.*?)['"]/ or die "no to";

	# XXX
}

package main;

sub format_time($) {
	my ($ss, $mm, $hh, $d, $m, $y) = localtime $_[0];

	sprintf "%04d-%02d-%02d %02d:%02d:%02d",
		$y + 1900, $m + 1, $d, $hh, $mm, $ss;
}

# fix crappy log
do {
	no warnings 'redefine';
	*AnyEvent::Log::format_time = \&format_time;
};
$AnyEvent::Log::FILTER->level ('debug');

tor_service::init ();
xmpp::init ();

AnyEvent->condvar->recv;
