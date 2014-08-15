#! /usr/bin/perl

=readme

P2P instant messaging over TOR, available from any jabber client

modules required:
- AnyEvent

tested with Miranda-IM

xmpp server is based on in.jabberd from inetdxtra by R. Rawson-Tetley

how-to use:
- plan your tcp ports, or use default 5222 for xmpp and 5221 for tor service
- create tor hidden service with torrc additional configuration like this:
     HiddenServiceDir </path/>
     HiddenServicePort 8221 <tor_service_addr>:<tor_service_port>
- edit xmpp2tor.conf parameters tor_socks_port, tor_service_name
- run the program
- connect with your jabber client, usually to 127.0.0.1 with user/pass
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
use Digest::SHA;

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
my $ONION_RE = qr/[a-z0-9]+\.onion/;

my $INIT;
my %local;
my %remote;
my $local_presence;

package esc;

sub TIEHASH { bless {} }
sub FETCH { my $s = $_[1]; $s =~ s/[^ -~]/./g; $s }
tie %::esc, 'esc';

package hex;

sub TIEHASH { bless {} }
sub FETCH { unpack 'H*', $_[1] }
tie %::hex, 'hex';

package on_destroy;

sub call(&) { bless \$_[0] }
sub DESTROY { ${$_[0]} && ${$_[0]}->() }
sub cancel { undef ${$_[0]} }

package handle;

sub new {
	my (@arg) = @_;

	my $h = new AnyEvent::Handle (@arg);
	$h->{_xmpp2tor_nogc} = $h;
	my $id = $h->{_xmpp2tor_id};
	$h->{_xmpp2tor_close} = on_destroy::call {
		local *__ANON__ = 'new.destroyed';
		::D "$id ok";
	};
	return $h;
}

sub gc {
	my ($h) = @_;

	delete $h->{_xmpp2tor_nogc};
	return $h;
}

sub destroy {
	my ($h) = @_;

	gc ($h)->destroy;
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
	handle::new (
		fh		=> $fh,
		on_error	=> sub {
			my ($h, $fatal, $message) = @_;
			local *__ANON__ = 'handle.on_error';

			$fatal ||= 0;
			::D "$h->{_xmpp2tor_id} fatal=$fatal $message";
			handle::destroy ($h);
		},
		timeout		=> 20,
		_xmpp2tor_id	=> "tor-from-$host:$port",
	)->push_read (line => \&first_line);
}

sub first_line {
	my ($h, $line) = @_;
	
	::D "$h->{_xmpp2tor_id} got $::esc{$line}";

	if ($line =~ /^XMPP2TOR CALLME ($ONION_RE) (\w+) (\w+)$/i) {
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
				::E "somebody called but we are not ready yet";
			}
		}
		handle::destroy ($h);
	} elsif ($line =~ /^XMPP2TOR CALLBACK ($ONION_RE) (\w+)$/i) {
		callback_in ($h, lc $1, $2);
	} else {
		::E "$h->{_xmpp2tor_id} bad $::esc{$line}";
		handle::destroy ($h);
	}
}

sub callback_in {
	my ($h, $addr, $key1) = @_;

	if (!exists $remote{$addr}) {
		::E "$h->{_xmpp2tor_id} $addr not asked";
		handle::destroy ($h);
		return;
	}
	if ($remote{$addr}{key1} ne $key1) {
		::E "$h->{_xmpp2tor_id} $addr bad key $key1 != $remote{$addr}{key1}";
		handle::destroy ($h);
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
			handle::destroy ($h);
		}
	});
}

sub peer_connected {
	my ($h, $addr) = @_;

	::I "$addr confirmed";
	$h->timeout (0); 
	$h->{_xmpp2tor_addr} = $addr;
	$remote{$addr}{h} = handle::gc ($h);
	if (!$remote{$addr}{group}) {
		$remote{$addr}{group} = $C{XMPP_NEWCONTACTS_GROUP};
		$remote{$addr}{name} = $addr;
		xmpp::send_roster_subscribe ($addr);
	}
	send_message ($h, $local_presence);
	my $id = $h->{_xmpp2tor_id};
	$h->{_xmpp2tor_disconnect} = on_destroy::call {
		local *__ANON__ = 'peer.destroyed';
		::D "$id $addr ok";
		if (exists $remote{$addr}) {
			delete $remote{$addr}{h};
			xmpp::unavail ($addr);
		}
	};
	read_message ($h);
}

sub read_message {
	my ($h) = @_;

	$h->push_read (netstring => sub {
		my ($h, $string) = @_;
		local *__ANON__ = 'read_message.read';

		::D "$h->{_xmpp2tor_id} got $::esc{$string}";
		eval {
			xmpp::from_tor ($h->{_xmpp2tor_addr}, $string);
		};
		if ($@) {
			::E "$h->{_xmpp2tor_id} error $::esc{$@}";
			handle::destroy ($h);
			return;
		}
		read_message ($h);
	});
}

sub callback_out {
	my ($addr, $key1, $key2) = @_;

	::D "calling back $addr with $key1, $key2";

	return if xmpp::is_blacklisted ($addr);

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
				handle::destroy ($h);
			}
		});
	}, sub {
		local *__ANON__ = 'callback.not_connected';
		::D "$addr";
	});
}

sub rand_hex { sprintf '%02x'x8, map rand 256, 1..8 }

sub callme {
	my ($addr) = @_;

	return if xmpp::is_blacklisted ($addr);

	$remote{$addr}{key1} = rand_hex ();
	$remote{$addr}{key2} = rand_hex ();

	tor_connect::socks ($addr, sub {
		my ($h) = @_;
		local *__ANON__ = 'callme.connected';

		my $req = "XMPP2TOR CALLME $C{TOR_SERVICE_NAME} " .
			"$remote{$addr}{key1} $remote{$addr}{key2}$CRLF";
		::D "$addr send $req";
		$h->push_write ($req);
		::I "$addr requested callme";
		handle::gc ($h)->push_shutdown;
	}, sub {
		local *__ANON__ = 'callme.not_connected';
		::D "$addr";
		if ($addr eq $C{TOR_SERVICE_NAME}) {
			::E "could not call myself, problems with tor";
			exit;
		}
	});
}

sub send_message {
	my ($h, $message) = @_;

	::D "$h->{_xmpp2tor_id} send $::esc{$message}";
	$h->push_write (netstring => $message);
}

sub send_one {
	my ($addr, $message) = @_;

	my $h = $remote{$addr}{h} or die;
	send_message ($h, $message);
}

sub send_all {
	my ($message) = @_;

	for (values %remote) {
		my $h = $_->{h} or next;
		send_message ($h, $message);
	}
}

package tor_connect;

sub socks {
	my ($addr, $cb, $cb_err) = @_;

	::D "connecting to $addr";
	handle::new (
		connect 	=> [ $C{TOR_SOCKS_ADDR}, $C{TOR_SOCKS_PORT} ],
		timeout		=> 60,
		on_error	=> sub {
			my ($h, $fatal, $message) = @_;
			local *__ANON__ = 'socks.on_error';

			$fatal ||= 0;
			::D "fatal=$fatal $message";
			::E "connect via tor socks failed";
			handle::destroy ($h);
		},
		on_connect	=> sub {
			my ($h) = @_;
			local *__ANON__ = 'socks.on_connect';

			::D "connected to socks";
			# v5, no auth
			$h->push_write (pack 'CCC', 5, 1, 0);
			$h->push_read (chunk => 2, \&socks_reply1);
		},
		_xmpp2tor_addr	=> $addr,
		_xmpp2tor_cb	=> $cb,
		_xmpp2tor_guard	=> on_destroy::call { $cb_err && $cb_err->() },
		_xmpp2tor_id	=> "tor-to-$addr",
	);
}

sub socks_reply1 {
	my ($h, $data) = @_;

	::D "$h->{_xmpp2tor_id} got $::hex{$data}";

	# v5, accepted no auth
	if ($data eq pack 'CC', 5, 0) {
		# v5, connect, reserved, name, addr, port
		my $req = pack 'CCCC C/A n', 5, 1, 0, 3,
			$h->{_xmpp2tor_addr}, $C{TOR_SERVICE_VIRTPORT};
		::D "$h->{_xmpp2tor_id} send $::hex{$req}";
		$h->push_write ($req);
		$h->push_read (chunk => 10, \&socks_reply2);
	} else {
		::E "$h->{_xmpp2tor_id} bad reply $::hex{$data}";
		handle::destroy ($h);
	}
}

sub socks_reply2 {
	my ($h, $data) = @_;

	::D "$h->{_xmpp2tor_id} got $::hex{$data}";

	# v5, success, reserved, ipv4, addr, port
	if ($data eq pack 'C10', 5, 0, 0, 1, 0,0,0,0, 0,0) {
		::D "$h->{_xmpp2tor_id} connected";
		$h->{_xmpp2tor_guard}->cancel ();
		$h->{_xmpp2tor_cb}->($h);
	} else {
		::E "$h->{_xmpp2tor_id} connect failed $::hex{$data}";
		handle::destroy ($h);
	}
}

package xmpp;

sub is_blacklisted {
	my ($addr) = @_;

	my $res = ($remote{$addr}{group} || '') eq $C{XMPP_BLACKLIST_GROUP};
	::D $addr if $res;
	return $res;
}

sub init {
	my ($host, $port) = ($C{XMPP_ADDR}, $C{XMPP_PORT});
	AnyEvent::Socket::tcp_server $host, $port, \&handle;
	::I "started on $host:$port";
}

sub handle {
	my ($fh, $host, $port) = @_;
	
	::D "connected from $host:$port";
	handle::new (
		fh		=> $fh,
		on_error	=> sub {
			my ($h, $fatal, $message) = @_;
			local *__ANON__ = 'handle.on_error';

			$fatal ||= 0;
			::D "$h->{_xmpp2tor_id} fatal=$fatal $message " .
				"buf=$esc::{${\$h->rbuf }}";
			handle::destroy ($h);
		},
		timeout		=> 20,
		_xmpp2tor_id	=> "xmpp-from-$host:$port",
	)->push_read (regex => qr!^ \s*
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
		::E "$h->{_xmpp2tor_id} $::esc{$@}, closing";
		handle::destroy ($h);
	}
}

sub process {
	local $_ = $_[0];
	s/^\s*//;

	::D "$cur_h->{_xmpp2tor_id} got $::esc{$_}";
	if (m!^</!) {
		# end of stream
		::I "$cur_h->{_xmpp2tor_id} closed";
		handle::destroy ($cur_h);
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
	die "bad digest" if $a{digest} && lc $a{digest} ne lc
		Digest::SHA::sha1_hex ($cur_h->{xmpp_streamid} . $C{XMPP_PASS});

	my $id = $cur_h->{_xmpp2tor_id};

	::I "$id logged in $a{username}";
	$cur_h->{xmpp_userandresource} =
		"$a{username}\@$cur_h->{xmpp_servername}/$a{resource}";
	$cur_h->timeout (0); 
	$local{$id} = handle::gc ($cur_h);
	$cur_h->{_xmpp2tor_close} = on_destroy::call {
		delete $local{$id};
		if (!keys %local) {
			$local_presence =
				presence_unavailable ($C{TOR_SERVICE_NAME});
			tor_service::send_all ($local_presence);
		}
	};
	return '';
}

sub roster {
	my ($result) = @_;

	# update from request
	while (m!
<item \b .*? \b jid=["'](.*?)[@"'] .*? \b subscription=["']remove["']
	!gx) {
		::D "remove $1";
		delete $remote{$1};
	}

	while (m!
<item \b .*? \b jid=["'](.*?)[@"'] .*? \b name=["'](.*?)["'] .*? (?: /> | >
 \C*?
  <group>(.*?)</group>
 \C*?
</item> )?
	!gx) {
		my ($addr, $name, $group) = ($1, $2, $3 || '');

		$addr =~ s/\@.*//;
		$addr .= ".onion" if $addr !~/\./;
		if ($addr =~ $ONION_RE) {
			::D "add $addr, $name, $group";
			$remote{$addr}{name} = $name;
			$remote{$addr}{group} = $group;

			tor_service::callme ($addr);
		} else {
			::E "will not add $::esc{$addr}";
		}
	}

	roster_write ();

	# prepare output
	my $item = '';
	my $presence = '';
	for (sort keys %remote) {
		my $jid = "$_\@$cur_h->{xmpp_servername}";

		$item .= <<XML;
  <item jid='$jid' name='$remote{$_}{name}' subscription='both'>
   <group>$remote{$_}{group}</group>
  </item>
XML
		$presence .= $remote{$_}{presence} if $remote{$_}{presence};
	}

	return <<XML;
<iq $result from='$cur_h->{xmpp_userandresource}'>
 <query xmlns='jabber:iq:roster'>
  $item
 </query>
</iq>
$presence
XML
}

sub roster_read {
	my $file = $C{XMPP_ROSTER_FILE};

	# read file
	if (open my $f, $file) {
		local $_;
		while (<$f>) {
			s/\s*\z//;
			my ($jid, $name, $group) = split /,/ or next;
			::D "file $jid, $name, $group";
			$remote{$jid}{name}  = $name;
			$remote{$jid}{group} = $group;
		}
		close $f;
	} else {
		::I "no roster file $file";
	}
}

sub roster_write {
	my $file = $C{XMPP_ROSTER_FILE};

	open my $f, '>', "$file.tmp" or die "open $file: $!";
	print $f "$_,$remote{$_}{name},$remote{$_}{group}\n"
		for sort keys %remote;
	close $f or die "close: $!";
	rename "$file.tmp", $file or die "rename $file.tmp to $file: $!";
}

sub send_roster_subscribe {
	my ($addr) = @_;

	::D "$addr";
	send_all (<<XML);
<iq from='$addr' id='xmpp_tor_roster_${\int rand 1e9 }' type='set'>
  <query xmlns='jabber:iq:roster'>
    <item jid='$addr' name='$remote{$addr}{name}'>
      <group>$remote{$addr}{group}</group>
    </item>
  </query>
</iq>
XML
}

sub do_presence {
	::D "presence $::esc{$_}";
	$local_presence = $_;
	tor_service::send_all ($local_presence);
	return '<presence />';
}

sub presence_unavailable {
	my ($jid) = @_;

	return <<XML;
<presence type='unavailable' from='$jid' />
XML
}

sub do_message {
	::D "message $::esc{$_}";

	my %a;
	for my $tag (qw( from to id )) {
		($a{$tag}) = /^[^>]*\b$tag=["'](.*?)['"]/ or die "no $tag";
	}

	exists $remote{$a{to}} && exists $remote{$a{to}}{h} or return <<XML;
<message from='$a{to}' id='$a{id}' to='$a{from}' type='error'>
  <error by='$cur_h->{xmpp_servername}' type='cancel'>
    <gone xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' />
  </error>
</message>
XML
	tor_service::send_one ($a{to}, $_);

	return '';
}

sub from_tor {
	my ($from, $msg) = @_;

	# some protection
	$msg =~ m!^< (message|presence) \b [^<>]* ( / | >\C*</\1 ) > \s* \z!x
		or die "bad tag";
	$msg =~ /^ [^>]* \s from=('|")\Q$from\E\1 /
		or die "bad from";

	$remote{$from}{presence} = $msg if $msg =~ /^<presence\b/;

	send_all ($msg);
}

sub send_all {
	my ($msg) = @_;

	for (values %local) {
		::D "$_->{_xmpp2tor_id} send $::esc{$msg}";
		$_->push_write ($msg);
	}
}

sub unavail {
	my ($addr) = @_;

	my $un = presence_unavailable ($addr);
	$remote{$addr}{presence} = $un;
	send_all ($un);
}

package main;

{
	open my $f, $CONFIG_FILE or die "open $CONFIG_FILE: $!\n";
	while (<$f>) {
		next if /^[;#\*]|^\s*$/;
		/^\s*(\S*)\s*=\s*(.*?)\s*$/ or die "bad config line $_\n";
		$C{uc $1} = $2;
	}
}

# AnyEvent does not allow rotate logfile
sub format_time($) {
	my ($ss, $mm, $hh, $d, $m, $y) = localtime $_[0];

	sprintf "%04d-%02d-%02d %02d:%02d:%02d",
		$y + 1900, $m + 1, $d, $hh, $mm, $ss;
}

{ no warnings 'redefine'; *AnyEvent::Log::format_time = \&format_time; }

$AnyEvent::Log::FILTER->level ($C{LOG_LEVEL});
$AnyEvent::Log::LOG->log_to_file ($C{LOG_FILE}) if $C{LOG_FILE};

::I "starting pid=$$ on perl $^V system $^O";
if ($C{PID_FILE}) {
	open my $f, '>', $C{PID_FILE} or die "open $C{PID_FILE}: $!";
	print $f "$$\n";
	::D "pid file created";
}
my $pid_guard = on_destroy::call { unlink $C{PID_FILE} or die $! };

$INIT = AnyEvent->condvar;
tor_service::init ();
::D "calling myself";
tor_service::callme ($C{TOR_SERVICE_NAME});
$INIT->recv;
::I "tor check successful";

xmpp::roster_read ();
$local_presence = xmpp::presence_unavailable ($C{TOR_SERVICE_NAME});
tor_service::callme ($_) for sort keys %remote;
xmpp::init ();
::I "started";

AnyEvent->condvar->recv; # forever
