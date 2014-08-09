#! /usr/bin/perl

=readme

P2P instant messaging over TOR, available from any jabber client

modules required:
- AnyEvent

tested with Miranda-IM

xmpp server is based on in.jabberd from inetdxtra by R. Rawson-Tetley

how-to use:
- plan your tcp ports or use default 5222 for xmpp, 5221 for tor service
- create tor hidden service with torrc additional configuration like this:
     HiddenServiceDir </path/>
     HiddenServicePort 8221 <tor_service_addr>:<tor_service_port>
- edit xmpp2tor.conf parameters tor_socks_port, tor_service_name
- run this program
- connect with your jabber client, usually to 127.0.0.1 user/pass
- add test contact xxxx.onion and report version of your jabber client

TOR service sequence diagram:
 A->B: connect to b_addr.onion:5221
 A->B: "XMPP2TOR CALLME a_addr.onion key1 key2" CR LF
 B->A: disconnect
 B->A: connect to a_addr.onion:5221
 B->A: "XMPP2TOR CALLBACK b_addr.onion key1" CR LF
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

my %C = (
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
	XMPP_NEWCONTACTS_GROUP	=> 'NewContacts',
);

sub LOG { my $lvl = shift; AE::log $lvl, ((caller 2)[3] || 'main') . " @_" }
sub D($) { LOG (debug => @_) }
sub I($) { LOG (info  => @_) }
sub E($) { LOG (error => @_) }

my $CRLF = "\015\012";

my $INIT;
my %local;
my %remote;

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
sub DESTROY { ${$_[0]} && ${$_[0]}->() }
sub cancel { undef ${$_[0]} }

package handler;

sub gc {
	my ($h) = @_;

	delete $h->{_xmpp2tor_nogc};
	my $id = $h->{_xmpp2tor_id};
	$h->{_xmpp2tor_close} = on_destroy::call {
		local *__ANON__ = 'gc.destroyed';
		::D "$id ok";
	};
	return $h;
}

package tor_service;

sub init {
	my ($host, $port) = ($C{TOR_SERVICE_ADDR}, $C{TOR_SERVICE_PORT});
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
			::D "$h->{_xmpp2tor_id} fatal=$fatal $message";
			handler::gc ($h)->destroy;
		},
		timeout		=> 20,
		_xmpp2tor_nogc	=> \$h,
		_xmpp2tor_id	=> "tor-from-$host:$port",
	);
	$h->push_read (line => \&first_line);
}

sub first_line {
	my ($h, $line) = @_;
	
	::D "$h->{_xmpp2tor_id} got $::esc{$line}";

	if ($line =~ /^XMPP2TOR CALLME ([a-z0-9]+\.onion) (\w+) (\w+)$/i) {
		my ($addr, $key1, $key2) = (lc $1, $2, $3);
		if ($addr eq $C{TOR_SERVICE_NAME}) {
			if ($remote{$addr}{key1} eq $key1 &&
			    $remote{$addr}{key2} eq $key2) {
				delete $remote{$addr};
				$INIT->send;
			} else {
				::E "somebody pretending myself";
			}
		} else {
			if ($INIT->ready) {
				callback_out ($addr, $key1, $key2);
			} else {
				::E "somebody called but not ready yet";
			}
		}
		handler::gc ($h)->destroy;
	} elsif ($line =~ /^XMPP2TOR CALLBACK (\w+) (\w+)$/i) {
		callback_in ($h, lc $1, $2);
	} else {
		::E "$h->{_xmpp2tor_id} bad $::esc{$line}";
		handler::gc ($h)->destroy;
	}
}

sub callback_in {
	my ($h, $addr, $key1) = @_;

	if (!exists $remote{$addr}) {
		::E "$h->{_xmpp2tor_id} $addr not asked";
		handler::gc ($h)->destroy;
		return;
	}
	if ($remote{$addr}{key1} ne $key1) {
		::E "$h->{_xmpp2tor_id} $addr bad key $key1 != $remote{$addr}{key1}";
		handler::gc ($h)->destroy;
		return;
	}

	$h->push_write ("OK $remote{$addr}{key2}$CRLF");
	$h->push_read (line => sub {
		my ($h, $line) = @_;
		local *__ANON__ = 'callback_in.reply';

		::D "$h->{_xmpp2tor_id} $addr got $::esc{$line}";
		if ($line =~ /^OK$/) {
			peer_connected ($h, $addr);
		} else {
			::E "$h->{_xmpp2tor_id} $addr bad $::esc{$line}";
			handler::gc ($h)->destroy;
		}
	});
}

sub peer_connected {
	my ($h, $addr) = @_;

	::I "peer $addr confirmed";
	$h->timeout (0); 
	$remote{$addr}{h} = $h;
	$h->{_xmpp2tor_disconnect} = on_destroy::call {
		delete $remote{$addr}{h};
	};
	read_message ($h);
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

sub callback_out {
	my ($addr, $key1, $key2) = @_;

	::D "calling back $addr with $key1, $key2";

	# XXX blacklist

	tor_connect::socks ($addr, sub {
		my ($h) = @_;
		local *__ANON__ = 'callback.connected';
	
		my $req = "XMPP2TOR CALLBACK $C{TOR_SERVICE_NAME} $key1$CRLF";
		::D "$addr send $req";
		$h->push_write ($req);
		$h->push_read (line => sub {
			my ($h, $line) = @_;
			local *__ANON__ = 'callback.reply';

			::D "$addr got $::esc{$line}";
			if ($line =~ /^OK \Q$key2\E$/) {
				my $req = "OK$CRLF";
				::D "$addr send $req";
				$h->push_write ($req);
				peer_connected ($h, $addr);
			} else {
				handler::gc ($h)->destroy;
			}
		});
	}, sub {
		local *__ANON__ = 'callback.not_connected';
		::D "$addr";
	});
}

package tor_connect;

sub rand_hex { sprintf '%02x'x8, map rand 256, 1..8 }

sub callme {
	my ($addr) = @_;

	die "wtf" if exists $remote{$addr};

	$remote{$addr} = {
		key1	=> rand_hex (),
		key2	=> rand_hex (),
		state	=> 'trying',
	};

	socks ($addr, sub {
		my ($h) = @_;
		local *__ANON__ = 'callme.connected';

		my $req = "XMPP2TOR CALLME $C{TOR_SERVICE_NAME} " .
			"$remote{$addr}{key1} $remote{$addr}{key2}$CRLF";
		::D "$addr send $req";
		$h->push_write ($req);
		::I "$addr requested callme";
		handler::gc ($h)->push_shutdown;
		$remote{$addr}{state} = 'called';
	}, sub {
		local *__ANON__ = 'callme.not_connected';
		::D "$addr";
		if ($addr eq $C{TOR_SERVICE_NAME}) {
			::E "could not call myself, something is wrong with tor";
			exit;
		}
	});
}

sub socks {
	my ($addr, $cb, $cb_err) = @_;

	::D "connecting to $addr";
	my $h; $h = new AnyEvent::Handle (
		connect 	=> [ $C{TOR_SOCKS_ADDR}, $C{TOR_SOCKS_PORT} ],
		timeout		=> 60,
		on_error	=> sub {
			my ($h, $fatal, $message) = @_;
			local *__ANON__ = 'socks.on_error';

			$fatal ||= 0;
			::D "fatal=$fatal $message";
			::E "connect to tor socks failed";
			handler::gc ($h)->destroy;
		},
		on_connect	=> sub {
			my ($h) = @_;
			local *__ANON__ = 'socks.on_connect';

			::D "connected to socks";
			# v5, no auth
			$h->push_write (pack 'CCC', 5, 1, 0);
			$h->push_read (chunk => 2, \&socks_reply1);
		},
		_xmpp2tor_nogc	=> \$h,
		_xmpp2tor_addr	=> $addr,
		_xmpp2tor_cb	=> $cb,
		_xmpp2tor_guard	=> on_destroy::call { $cb_err && $cb_err->() },
		_xmpp2tor_id	=> "tor-to-$addr",
	);
}

sub socks_reply1 {
	my ($h, $data) = @_;

	::D "$h->{_xmpp2tor_id} got $::h{$data}";

	# v5, accepted no auth
	if ($data eq pack 'CC', 5, 0) {
		# v5, connect, reserved, name, addr, port
		my $req = pack 'CCCC C/A n', 5, 1, 0, 3,
			$h->{_xmpp2tor_addr}, $C{TOR_SERVICE_VIRTPORT};
		::D "$h->{_xmpp2tor_id} send $::h{$req}";
		$h->push_write ($req);
		$h->push_read (chunk => 10, \&socks_reply2);
	} else {
		::E "$h->{_xmpp2tor_id} bad reply $::h{$data}";
		handler::gc ($h)->destroy;
	}
}

sub socks_reply2 {
	my ($h, $data) = @_;

	::D "$h->{_xmpp2tor_id} got $::h{$data}";

	# v5, success, reserved, ipv4, addr, port
	if ($data eq pack 'C10', 5, 0, 0, 1, 0,0,0,0, 0,0) {
		::D "$h->{_xmpp2tor_id} connected";
		$h->{_xmpp2tor_guard}->cancel ();
		$h->{_xmpp2tor_cb}->($h);
	} else {
		::E "$h->{_xmpp2tor_id} connect failed $::h{$data}";
		handler::gc ($h)->destroy;
	}
}

package xmpp;

use Digest::SHA 'sha1_hex';

sub init {
	my ($host, $port) = ($C{XMPP_ADDR}, $C{XMPP_PORT});
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
			::D "$h->{_xmpp2tor_id} fatal=$fatal $message buf=${\$h->rbuf }";
			handler::gc ($h)->destroy;
		},
		timeout		=> 20,
		_xmpp2tor_nogc	=> \$h,
		_xmpp2tor_id	=> "xmpp-from-$host:$port",
	);
	$h->push_read (regex => qr!^ \s*
		<\? xml [^>]* > \s*
		< stream:stream [^>]* >
	!x, qr!.!, \&start_stream);
}

sub start_stream {
	my ($h, $data) = @_;

	::D "$h->{_xmpp2tor_id} got $::esc{$data}";

	$h->{xmpp_servername} =
	 	$data =~ /<stream:stream[^>]*\bto=["'](.*?)["']/ ?
			$1 : $C{XMPP_ADDR};
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
		::E "$h->{_xmpp2tor_id} $::esc{$@} closing";
		handler::gc ($h)->destroy;
	}
}

sub process {
	local $_ = $_[0];
	s/^\s*//;

	::D "$cur_h->{_xmpp2tor_id} got $::esc{$_}";
	if (m!^</!) {
		# end of stream
		::I "$cur_h->{_xmpp2tor_id} closed";
		handler::gc ($cur_h)->destroy;
		return;
	}

	/^<(\w+)/ or die "no tag";
	no strict 'refs';
	exists &{"do_$1"} or die "unknown tag $1\n";
	my $resp = &{"do_$1"} ();

	::D "$cur_h->{_xmpp2tor_id} send $::esc{$resp}";
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

	::E "$cur_h->{_xmpp2tor_id} unknown iq $_";
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

	die "bad username" if $a{username} ne $C{XMPP_USER};
	die "bad password" if $a{password} && $a{password} ne $C{XMPP_PASS};
	die "bad digest" if $a{digest} && lc $a{digest} ne
		lc sha1_hex ($cur_h->{xmpp_streamid} . $C{XMPP_PASS});

	::I "$cur_h->{_xmpp2tor_id} logged in $a{username}";
	$cur_h->{xmpp_userandresource} =
		"$a{username}\@$cur_h->{xmpp_servername}/$a{resource}";
	$cur_h->timeout (0); 
	return '';
}

sub roster {
	my ($result) = @_;

	my %roster;
	my $file = $C{XMPP_ROSTER_FILE};

	# read file
	if (open my $f, $file) {
		local $_;
		while (<$f>) {
			s/\s*\z//;
			my ($jid, $name, $group) = split /,/ or next;
			::D "file $jid, $name, $group";
			$roster{$jid} = [ $name, $group ];
		}
		close $f;
	} else {
		::I "no roster file $file, will create";
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
	open my $f, '>', "$file.tmp" or die "open $file: $!";
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
		$C{uc $1} = $2;
	}
} else {
	::E "open $CONFIG_FILE: $!";
}

$AnyEvent::Log::FILTER->level ($C{LOG_LEVEL});
$AnyEvent::Log::LOG->log_to_file ($C{LOG_FILE}) if $C{LOG_FILE};

::I "starting on perl $^V system $^O";

if ($C{PID_FILE}) {
	open my $f, '>', $C{PID_FILE} or die "open $C{PID_FILE}: $!";
	print $f "$$\n";
}
my $pid_guard = on_destroy::call { unlink $C{PID_FILE} or die $! };

$INIT = AnyEvent->condvar;
tor_service::init ();
tor_connect::callme ($C{TOR_SERVICE_NAME});
$INIT->recv;
::I "tor check successful";

xmpp::init ();
::I "started";

AnyEvent->condvar->recv; # forever
