#!/usr/bin/perl
# This script is for Slingbox 350/500 models

use IO::Select;
use IO::Socket::INET;
use Crypt::Tea_JS;
use Getopt::Long;

BEGIN { $| = 1 } # Flush stdout right away

### START  MAIN ###
$ip = '192.168.10.186';        # slingbox ip
$port = '5201';                # slingbox port
$user = 'admin';               # set to 'admin' or 'guest' as desired
$pass = 'secret';              # change this to your slingbox password
$vbw = 4000;                   # video bandwidth, kbps
$vsm = 63;                     # smoothness, 1 .. 64
$vs = 16;                      # video size, 3 for QVGA, 4 for 640x240, 5 for VGA, 15 for 1920x544, 16 for 1920x1080
$fr = 30;                      # frame rate, fps, must be 10, 15, 20, 30 or 60
$sleep = 0;                    # sleep time in seconds before starting capture
$chan = '';                    # tune to a channel before capture
$dur = 0;                      # duration in seconds you want to capture
$output = "rec350.asf";        # output file (use -stdout option for stdout)
$stdout = 0;

# Parse command line arguments
my $ok = GetOptions(
   "chan=s"   => sub {$chan = $_[1];},
   "dur=s"    => sub {$dur = $_[1];},
   "ip=s"     => sub {$ip = $_[1];},
   "fr=s"     => sub {$fr = $_[1];},
   "output=s" => sub {$output = $_[1];},
   "port=s"   => sub {$port = $_[1];},
   "pass=s"   => sub {$pass = $_[1];},
   "h"        => sub {&useage(); exit(0);},
   "sleep=s"  => sub {$sleep = $_[1];},
   "stdout"   => sub {$stdout = 1;},
   "user=s"   => sub {$user = $_[1];},
   "vbw=s"    => sub {$vbw = $_[1];},
   "vsm=s"    => sub {$vsm = $_[1];},
   "vs=s"     => sub {$vs = $_[1];},
);
if (! $ok) {
   &useage();
   exit(1);
}

$slingip = "${ip}:${port}";
sleep($sleep) if $sleep;
$skey = pack("H*", 'AAAADEBCBABBFB87FACFCC7CBCAADDDD'); # start with fixed key,
$smode = 0x2000;                # basic cipher mode,
$sid = $seq = 0;                # no session ID, seq 0
$s_ctrl = sling_open("Control"); # open control connection to SB
$sel = new IO::Select($s_ctrl);  # to test
sling_cmd(0x67, pack("V a32 a32 x132", 0, futf16($user), futf16($pass))); # log in to SB
$rand = pack("H*", 'feedfacedeadbeef1111222233334444'); # 'random' challenge
sling_cmd(0xc6, pack("V a16 x36", 1, $rand)); # setup dynamic key on SB
$skey = dynk($rand, $sid, 2, 3) ^ dynk(substr($dbuf, 0, 16), $sid, -1, -4);
$smode = 0x8000;                # use dynamic key from now on
sling_cmd(0x7e, pack("V V", 1, 0)); # stream control
die "box in use" if $stat;
sling_cmd(0xa6, pack("v10 x76", 0x1cf, 0, 0x40, 0x10, 0x5000, 0x180, 1, 0x1e,
                      0, 0x3d));
if ($chan) {         # want to tune to a channel
    $ircmds = '';
    for $chdigit (split(//, sprintf("%04d", $chan))) {
        $ircmds .= pack("v2", $chdigit ? $chdigit + 8 : 18, 500);
    }
    sling_cmd(0x87, $ircmds . pack("x456 v4", 3, 0, 0, 0));
}
sling_cmd(0xb5, pack("V11 a16 V2 x92", 0xff, 0xff, $vs, 1,
                     0x05000000 + ($fr << 16) + $vbw, 0x10001 + ($vsm << 8), 3, 1,
                     0x40, 0x4f, 1, $rand, 0x1012020, 1)); # set stream params
$s_stream = sling_open("Stream"); # open stream connection to SB
$s_stream->sockopt(SO_RCVBUF, 524288) or die "Sockopt: $!\n";

$pktsiz = 3072;         # SB 350 always? uses 3072 byte packets
read($s_stream, $ibuf, $pktsiz) == $pktsiz or die; # read Header Object and data header
($pos = index($ibuf, pack("H*", "3626b2758e66cf11a6d900aa0062ce6c"))) > 0 or die; # find data hdr
$pos += 50;                     # end of data hdr
print STDERR "stream started\n" unless $sleep;
my $out;
if ($stdout) {
   $out = *STDOUT
} else {
   open($out, ">$output") or die "failed to write to output file: $output\n";
}
binmode($out);
print $out substr($ibuf, 0, $pos); # write headers to file
read($s_stream, $tbuf, $pos);     # get rest of 1st data packet
$ibuf = substr($ibuf, $pos) . $tbuf; # assemble 1st data packet
# now, read data packets from SB, decrypt as needed, write to output file
$| = 1;
$pktn = $runt = 0; # no packets, runtime
while (1) {
    print $out $ibuf;    # output the whole buffer
    ($pmode, $pad, $pktt, $pad) = unpack("N x V2 x2 C", $ibuf);
    last if ($pmode & ~1) != 0x82000018; # unexpected or corrupted data
    if (++$pktn % 1000 == 0) {  # every 1000 packets
        $runt = int($pktt / 1000); # convert ms to seconds
        if ($sel->can_read(0)) {   # control socket has data
            last unless sysread($s_ctrl, $hbuf, 999); # read but ignore replies
        }
        sling_cmd(0x66, ''); # send a keepalive
        printf(STDERR "\r%02d:%02d:%02d pkts:%d", int($runt / 3600), int($runt / 60) % 60, $runt % 60, $pktn) unless $sleep; # show stats
        last if $dur && $runt > $dur;
    }
    last unless read($s_stream, $ibuf, $pktsiz) == $pktsiz; # get next packet from stream
}
### END MAIN ###

sub tea {                       # en(de)crypt buf, calling Tea_JS for each 8-byte block
    my ($buf, $key, $enc) = @_;
    my @keys = unpack("V*", $key);
    my @longs = unpack("V*", $buf);
    my $sub = $enc ? \&Crypt::Tea_JS::oldtea_code : \&Crypt::Tea_JS::oldtea_decode;
    for (my $j = 0; $j < @longs; $j += 2) {
        ($longs[$j], $longs[$j+1]) = &$sub($longs[$j], $longs[$j+1], @keys);
    }
    return pack("V*", @longs);
}

sub dynk {                      # hash function for dynamic key
    my ($t, $s, $v, $r) = (unpack("b*", $_[0]), unpack("b*", pack("v",$_[1])));
    $v^=$t=substr($t,$r=$_*$_[($_[1]>>$_-1&1)+2]).substr($t,0,$r)^$s for (1..16);
    pack("b*", $v);
}

sub sling_cmd {                 # send message to SB, check response
    my ($opcode, $data) = @_;
    my $parity = 0;
    if ($smode == 0x8000) {     # using a dynamic key
        $parity ^= $_ for (unpack("C*", $data)); # compute integrity check
    }
    print $s_ctrl pack("v5 x6 v2 x4 v x6", 0x101, $sid, $opcode, 0, ++$seq, length($data),
                       $smode, $parity) . tea($data, $skey, 1); # encrypt body
    return if $opcode == 0x66;                                  # don't wait for keepalive result
    sysread($s_ctrl, $hbuf, 32) == 32 or die "missing or bad response header";
    ($sid, $stat, $dlen) = unpack("x2 v x8 v x2 v", $hbuf);
    die "cmd: $opcode err: $stat $dlen" if $stat && $stat != 0x0d && $stat != 0x13; # error code from SB
    if ($dlen) {
        sysread($s_ctrl, $dbuf, 512) == $dlen or die "missing or bad response data";
        $dbuf = tea($dbuf, $skey, 0); # decrypt body
    }
}

sub sling_open {                # open a connection to SB, send HTTP header
    my $sock = IO::Socket::INET->new($slingip) or die $!; # open socket
    print $sock "GET /stream.asf HTTP/1.1\r\nAccept: */*\r\n" # send HTTP header
        . "Pragma: Sling-Connection-Type=$_[0], Session-Id=$sid\r\n\r\n";
    return $sock;
}

sub futf16 { pack("v*", unpack("C*", $_[0])) } # fake UTF-16

sub useage {
   print "$0 [options]\n";
   print "OPTIONS:\n";
   print "-h                    print program useage/options\n";
   print "-output file          output to named file (defaults to rec350.asf)\n";
   print "-stdout               output to stdout instead of a file\n";
   print "-ip IP                slingbox IP to use\n";
   print "-port port            slingbox port (defaults to 5201)\n";
   print "-user name            slingbox username to use (admin or guest)\n";
   print "-pass password        slingbox password\n";
   print "-vbw rate             video bit rate (defaults to 4000)\n";
   print "-vsm smoothness       video smoothness (1:64, defaults to 63)\n";
   print "-vs size              video resolution(3=QVGA,4=640x240,5=640x480,16=1920x1080)\n";
   print "-fr fps               video frame rate (10,15,20,30,60, defaults to 30 fps)\n";
   print "-sleep secs           wait this many seconds before starting capture(defaults to 0)\n";
   print "-dur secs             capture only this many seconds (defaults to unlimited)\n";
   print "-chan channelNum      tune to this channel before capturing\n";
}
