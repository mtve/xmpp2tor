#! /usr/bin/perl

=readme

P2P instant messaging over TOR, available from any jabber client

xmpp server is based on in.jabberd from inetdxtra by R. Rawson-Tetley

requirements:
- AnyEvent

tested with Miranda-IM

how-to use:
- create tor hidden service, it will be your address
- edit tor_socks_port and tor_service_name in xmpp2tor.conf
- run this script
- see line "
- connect with your jabber client, usually to 127.0.0.1 user/pass
- add test contact xxxx.onion and report version of your jabber client

TOR side sequence diagram:
 A->B: connect to b_addr.onion:5221
 A->B: "XMPP2TOR CALLME a_addr.onion key1 key2" CR LF
 B->A: disconnect
 B->A: connect to a_addr.onion:5221
 B->A: "XMPP2TOR CALLBACK key1" CR LF
 A->B: "OK key2" CR LF
 B->A: "OK" CR LF
 A<->B: XMPP messages as netstrings

=cut

use warnings;
use strict;
use lib 'lib';

use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use AnyEvent::Log;

my $CONFIG_FILE = $ARGV[0] || 'xmpp2tor.conf';

my %CFG = (
	LOG_LEVEL		=> 'debug',

	TOR_SERVICE_NAME	=> 'changeme.onion',
	TOR_SERVICE_VIRTPORT	=> 5221,
	TOR_SERVICE_ADDR	=> '127.0.0.1',
	TOR_SERVICE_PORT	=> 5221,
	TOR_SOCKS_ADDR		=> '127.0.0.1',
	TOR_SOCKS_PORT		=> 9101,

	XMPP_ADDR		=> '127.0.0.1',
	XMPP_PORT		=> 5222,

	XMPP_USER		=> 'user',
	XMPP_PASS		=> 'pass',
	XMPP_ROSTER_FILE	=> 'roster.txt',
	XMPP_BLACKLIST_GROUP	=> 'BlackList',
);

sub LOG { my $lvl = shift; AE::log $lvl, ((caller 2)[3] || 'main') . " @_" }
sub D($) { LOG (debug => @_) }
sub I($) { LOG (info  => @_) }
sub E($) { LOG (error => @_) }

my $CRLF = "\015\012";

package esc;

sub TIEHASH { bless {} }
sub FETCH { my $s = $_[1]; $s =~ s/[^ -~]/./g; $s }
tie %::esc, 'esc';

package h;

sub TIEHASH { bless {} }
sub FETCH { unpack 'H*', $_[1] }
tie %::h, 'h';

package on_destroy;

sub call(&) { bless \$_[0] }
sub DESTROY { ${$_[0]}->() }
sub cancel { undef ${$_[0]} }

package tor_service;

sub init {
	my ($host, $port) = ($CFG{TOR_SERVICE_ADDR}, $CFG{TOR_SERVICE_PORT});
	AnyEvent::Socket::tcp_server $host, $port, \&handle;
	::I "started on $host:$port";
}

sub handle {
	my ($fh, $host, $port) = @_;
	
	::D "connected from $host:$port";
	my $h; $h = new AnyEvent::Handle (
		fh		=> $fh,
		on_error	=> sub {
			my ($h, $fatal, $message) = @_;
			local *__ANON__ = 'handle.on_error';

			$fatal ||= 0;
			::D "fatal=$fatal $message";
			$h->destroy;
		},
		timeout		=> 20,
		_xmpp2tor_nogc	=> \$h,
	);
	$h->push_read (line => \&first_line);
}

sub first_line {
	my ($h, $line) = @_;
	
	::D "got $::esc{$line}";

	if ($line =~ /^XMPP2TOR CALLME ([!-~]+) ([!-~]+) ([!-~]+)$/i) {
		# XXX callback ();
	} elsif ($line =~ /^callback/) {
		$h->push_write ("ok\n");
		$h->push_read (line => \&second_line);
	} else {
		::E "bad $::esc{$line}";
		$h->destroy;
	}
}

sub second_line {
	my ($h, $line) = @_;

	::D "got $::esc{$line}";
	if ($line =~ /^ok/) {
		# trusted now;
		$h->timeout (0); 
		read_message ($h);
	} else {
		::E "bad $::esc{$line}";
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

	::D "got $::esc{$string}";
	# XXX
}

package tor_connect;

sub callme {
	my ($addr) = @_;

	connect ($addr, sub {
		my ($h, $ok) = @_;
		local *__ANON__ = 'callme.connected';

		my $req = "XMPP2TOR CALLME $CFG{TOR_SERVICE_NAME} key1 key2$CRLF";
		::D "send $req";
		$h->push_write ($req);
		$h->on_drain(sub {
			my ($h) = @_;
			local *__ANON__ = 'callme.on_drain';

			::I "requested callme from $h->{_xmpp2tor_addr}";
			$h->push_shutdown;
		});
	});
}

sub connect {
	my ($addr, $cb) = @_;

	::D "connecting to $addr";
	my $h; $h = new AnyEvent::Handle (
		connect 	=> [ $CFG{TOR_SOCKS_ADDR}, $CFG{TOR_SOCKS_PORT} ],
		timeout		=> 60,
		on_error	=> sub {
			my ($h, $fatal, $message) = @_;
			local *__ANON__ = 'callme.on_error';

			$fatal ||= 0;
			::D "fatal=$fatal $message";
			::E "connect to tor socks failed";
			$h->destroy;
		},
		on_connect	=> sub {
			my ($h) = @_;
			local *__ANON__ = 'callme.on_connect';

			::D "connected to socks";
			# v5, no auth
			$h->push_write (pack 'CCC', 5, 1, 0);
			$h->push_read (chunk => 2, \&socks_reply1);
		},
		_xmpp2tor_nogc	=> \$h,
		_xmpp2tor_addr	=> $addr,
		_xmpp2tor_cb	=> $cb,
		_xmpp2tor_guard	=> on_destroy::call { $cb->($h, 0) },
	);
}

sub socks_reply1 {
	my ($h, $data) = @_;

	::D "got $::h{$data}";

	# v5, accepted no auth
	if ($data eq pack 'CC', 5, 0) {
		# v5, connect, reserved, name, addr, port
		my $req = pack 'CCCC C/A n', 5, 1, 0, 3,
			$h->{_xmpp2tor_addr}, $CFG{TOR_SERVICE_VIRTPORT};
		::D "send $::h{$req}";
		$h->push_write ($req);
		$h->push_read (chunk => 10, \&socks_reply2);
	} else {
		::E "bad reply $::h{$data}";
		$h->destroy;
	}
}

sub socks_reply2 {
	my ($h, $data) = @_;

	::D "got $::h{$data}";

	# v5, success, reserved, ipv4, addr, port
	if ($data eq pack 'C10', 5, 0, 0, 1, 0,0,0,0, 0,0) {
		$h->{_xmpp2tor_guard}->cancel ();
		$h->{_xmpp2tor_cb}->($h, 1);
	} else {
		::I "connect to $h->{_xmpp2tor_addr} failed $::h{$data}";
		$h->destroy;
	}
}

package xmpp;

use Digest::SHA 'sha1_hex';

sub init {
	my ($host, $port) = ($CFG{XMPP_ADDR}, $CFG{XMPP_PORT});
	AnyEvent::Socket::tcp_server $host, $port, \&handle;
	::I "started on $host:$port";
}

sub handle {
	my ($fh, $host, $port) = @_;
	
	::D "connected from $host:$port";
	my $h; $h = new AnyEvent::Handle (
		fh		=> $fh,
		on_error	=> sub {
			my ($h, $fatal, $message) = @_;
			local *__ANON__ = 'handle.on_error';

			$fatal ||= 0;
			::D "fatal=$fatal $message buf=${\$h->rbuf }";
			$h->destroy;
		},
		timeout		=> 20,
		_xmpp2tor_nogc	=> \$h,
	);
	$h->push_read (regex => qr!^ \s*
		<\? xml [^>]* > \s*
		< stream:stream [^>]* >
	!x, qr!.!, \&start_stream);
}

sub start_stream {
	my ($h, $data) = @_;

	::D "got $::esc{$data}";

	$h->{xmpp_servername} =
	 	$data =~ /<stream:stream[^>]*\bto=["'](.*?)["']/ ?
			$1 : $CFG{XMPP_ADDR};
	$h->{xmpp_streamid} = int rand 1e9;

	$h->push_write (<<XML);
<?xml version='1.0'?>
<stream:stream xmlns:stream='http://etherx.jabber.org/streams'
 id='$h->{xmpp_streamid}' xmlns='jabber:client' from='$h->{xmpp_servername}'>
XML

	nextread ($h);
}

sub nextread {
	my ($h) = @_;

	# read eos or complete tag

	$h->push_read (regex => qr!^ \s* (
		</ stream:stream [^>]* > |
		< (\w+) \b [^>]* /> |
		< (\w+) \b [^>]* > \C*? </ \3 > )
	!x, qr!.!, \&read_cb);
}

my $cur_h;

sub read_cb {
	my ($h, $data) = @_;

	$cur_h = $h;
	eval {
		process ($data);
		nextread ($h);
	};
	if ($@) {
		::E "$::esc{$@} closing";
		$h->destroy;
	}
}

sub process {
	local $_ = $_[0];
	s/^\s*//;

	::D "got $::esc{$_}";
	if (m!^</!) {
		# end of stream
		::I "closed";
		$cur_h->destroy;
		return;
	}

	/^<(\w+)/ or die "no tag";
	no strict 'refs';
	exists &{"do_$1"} or die "unknown tag $1\n";
	my $resp = &{"do_$1"} ();

	::D "send $::esc{$resp}";
	$cur_h->push_write ($resp);
}

sub do_iq {
	/^<iq[^>]*\bid=["'](.*?)["']/ or die "no id";
	my $result = "type='result' id='$1'";

	# auth
	/<query xmlns=['"]jabber:iq:auth\b/ && return <<XML;
<iq $result>
 ${\iq_auth () }
</iq>
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
  <identity category='services' type='jabber' name='xmpp2tor' />
  <feature var='http://jabber.org/protocol/disco#info' />
  <feature var='http://jabber.org/protocol/disco#items' />
  <feature var='urn:xmpp:ping' />
  <feature var='jabber:iq:version' />
 </query>
</iq>
XML

	# roster
	m!<query xmlns=["']jabber:iq:roster! && return roster ($result);

	# vcard
	/<vcard/i && return <<XML;
<iq $result from='$cur_h->{xmpp_userandresource}'>
 <vCard xmlns='vcard-temp'/>
</iq>
XML

	::E "unknown iq $_";
	return <<XML;
<iq type='error' id='$1'>
 <error type='cancel'>
  <feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>
 </error>
</iq>
XML
}

sub iq_auth {
	my %a;
	for my $tag (qw( username resource password digest )) {
		$a{$tag} = m!<$tag>([^<>]*)</$tag>! ? $1 : '';
	}

	$a{password} || $a{digest} || return <<XML;
<query xmlns='jabber:iq:auth'>
 <username>$a{username}</username>
 <digest />
 <password />
 <resource />
</query>
XML

	die "bad username" if $a{username} ne $CFG{XMPP_USER};
	die "bad password" if $a{password} && $a{password} ne $CFG{XMPP_PASS};
	die "bad digest" if $a{digest} && lc $a{digest} ne
		lc sha1_hex ($cur_h->{xmpp_streamid} . $CFG{XMPP_PASS});

	::I "logged in $a{username}";
	$cur_h->{xmpp_userandresource} =
		"$a{username}\@$cur_h->{xmpp_servername}/$a{resource}";
	$cur_h->timeout (0); 
	return '';
}

sub roster {
	my ($result) = @_;

	my %roster;
	my $file = $CFG{XMPP_ROSTER_FILE};

	# read file
	open my $f, $file or die "open $file: $!";
	{
		local $_;
		while (<$f>) {
			s/\s*\z//;
			my ($jid, $name, $group) = split /,/ or next;
			::D "file $jid, $name, $group";
			$roster{$jid} = [ $name, $group ];
		}
	}

	# update from request
	while (m!
<item \b .*? \b jid=["'](.*?)[@"'] .*? \b subscription=["']remove["']
	!gx) {
		::D "remove $1";
		delete $roster{$1};
	}
	while (m!
<item \b .*? \b jid=["'](.*?)[@"'] .*? \b name=["'](.*?)["'] .*? (?: /> | >
 \C*?
  <group>(.*?)</group>
 \C*?
</item> )?
	!gx) {
		my ($jid, $name, $group) = ($1, $2, $3 || '');
		::D "add $jid, $name, $group";
		$roster{$jid} = [ $name, $group ];
	}

	# write file and prepare output
	my $item = '';
	my $presence = '';
	open $f, '>', "$file.tmp" or die "open $file: $!";
	for my $jid (sort keys %roster) {
		my ($name, $group) = @{ $roster{$jid} };

		print $f "$jid,$name,$group\n" or die "print: $!";

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
	close $f or die "close: $!";
	rename "$file.tmp", $file or die "rename $file.tmp to $file: $!";

	return <<XML;
<iq $result from='$cur_h->{xmpp_userandresource}'>
 <query xmlns='jabber:iq:roster'>
  $item
 </query>
</iq>
$presence
XML
}

sub do_presence { '<presence />' }

sub do_message {
	/^<message[^>]*\bto=["'](.*?)['"]/ or die "no to";

	::D "message $::esc{$_}";

	# XXX
	return '';
}

package main;

# AnyEvent does not allow rotate logfile
sub format_time($) {
	my ($ss, $mm, $hh, $d, $m, $y) = localtime $_[0];

	sprintf "%04d-%02d-%02d %02d:%02d:%02d",
		$y + 1900, $m + 1, $d, $hh, $mm, $ss;
}

{ no warnings 'redefine'; *AnyEvent::Log::format_time = \&format_time; }

if (open my $f, $CONFIG_FILE) {
	while (<$f>) {
		next if /^[;#\*]|^\s*$/;
		/^\s*(\S*)\s*=\s*(.*?)\s*$/ or die "bad config line $_";
		$CFG{uc $1} = $2;
	}
} else {
	::E "open $CONFIG_FILE: $!";
}

$AnyEvent::Log::FILTER->level ($CFG{LOG_LEVEL});
$AnyEvent::Log::LOG->log_to_file ($CFG{LOG_FILE}) if $CFG{LOG_FILE};

if ($CFG{PID_FILE}) {
	open my $f, '>', $CFG{PID_FILE} or die "open $CFG{PID_FILE}: $!";
	print $f "$$\n";
}
my $pid_guard = on_destroy::call { unlink $CFG{PID_FILE} or die $! };

tor_service::init ();

#xmpp::init ();
tor_connect::callme ($CFG{TOR_SERVICE_NAME});

::I "started";

AnyEvent->condvar->recv; # forever
