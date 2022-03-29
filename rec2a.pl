#!/usr/bin/perl
# This script is for Slingbox Solo, Pro and Pro HD models

use IO::Socket::INET;
use Crypt::Tea_JS;
use Getopt::Long;

BEGIN { $| = 1 } # Flush stdout right away

### START  MAIN ###
$ip = '192.168.10.254';         # slingbox ip
$port = '5001';                 # slingbox port
$pass = 'secret';               # change this to your SB admin password
$vbw = 4000;                    # video bandwidth, kbps
$hd = 1;                        # 0 for SD, 1 for HD
$vsm = 63;                      # smoothness, 1 .. 64
$vs = 5;                        # SD res, 3 for QVGA, 4 for 640x240, 5 for VGA
$sleep = 0;                     # sleep time in seconds before starting capture
$dur = 0;                       # duration in seconds you want to capture
$chan = '';                     # tune to a channel before capture
$output = "rec2.asf";           # output file (use -stdout option for stdout)
$irparm = 2;			# change this to 2 if you get cmd 135 errors
$stdout = 0;

# Parse command line arguments
my $ok = GetOptions(
   "chan=s"   => sub {$chan = $_[1];},
   "dur=s"    => sub {$dur = $_[1];},
   "hd=s"     => sub {$hd = $_[1];},
   "ip=s"     => sub {$ip = $_[1];},
   "output=s" => sub {$output = $_[1];},
   "port=s"   => sub {$port = $_[1];},
   "pass=s"   => sub {$pass = $_[1];},
   "h"        => sub {&useage(); exit(0);},
   "sleep=s"  => sub {$sleep = $_[1];},
   "stdout"   => sub {$stdout = 1;},
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
sling_cmd(0x67, pack("V a32 a32 x132", 0, futf16("admin"), futf16($pass))); # log in to SB
$rand = pack("H*", 'feedfacedeadbeef1111222233334444'); # 'random' challenge
sling_cmd(0xc6, pack("V a16 x36", 1, $rand)); # setup dynamic key on SB
$skey = dynk($rand, $sid, 2, 3) ^ dynk(substr($dbuf, 0, 16), $sid, -1, -4);
$smode = 0x8000;                # use dynamic key from now on
sling_cmd(0x7e, pack("V V", 1, 0)); # stream control
if ($stat) {                        # box in use
    sling_cmd(0x93, pack("a32 a32 x8", futf16("admin"), futf16($pass))); # grab SB
    sling_cmd(0x66, '');                # wait for grab?
    sling_cmd(0x6a, pack("V x172", 1)); # unk fn
    sling_cmd(0x7e, pack("V V", 1, 0)); # reissue stream control
    die "could not grab box" if $stat;
}
sling_cmd(0xa6, pack("v10 x76", 0x1cf, 0, 0x40, 0x10, 0x5000, 0x180, 1, 0x1e,
                      0, 0x3d));
if ($chan) {         # want to tune to a channel
    $ircmds = '';
    for $chdigit (split(//, $chan)) {
        $ircmds .= pack("v2", $chdigit ? $chdigit + 8 : 18, 500);
    }
    $irpad = 472 - length($ircmds);
    sling_cmd(0x87, $ircmds . pack("x$irpad v4", $irparm, 0, 0, 0));
}
sling_cmd(0xb5, pack("V11 a16 V2 x92", 0xff, 0xff, $hd ? 0x0f : $vs, 1, 0x051e0000 + $vbw, 0x10001 + ($vsm << 8), 3, 1,
                      0x40, 0x4f, 1, $rand, 0x1012020, 1)); # set stream params
$s_stream = sling_open("Stream"); # open stream connection to SB
$s_stream->sockopt(SO_RCVBUF, 524288) or die "Sockopt: $!\n";
$pktsiz = 3000;                 # SB always? uses 3000 byte packets
read($s_stream, $ibuf, $pktsiz) == $pktsiz or die; # read Header Object and data header
($pos = index($ibuf, pack("H*", "3626b2758e66cf11a6d900aa0062ce6c"))) > 0 or die; # find data hdr
$pos += 50;                     # end of data hdr
($apos = index($ibuf, pack("H*", "9107DCB7B7A9CF118EE600C00C20536572"))) > 0 or die; # find audio hdr
substr($ibuf, $apos + 0x60, 10) = pack("v x8", 0x9012); # fix audio header so VLC will play
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
$bts = $bco = $pktn = $runt = 0; # no bytes yet to save, carried over, packets, runtime
$dco = '';                      # no data yet carried over
while (!$pktn || read($s_stream, $ibuf, $pktsiz) == $pktsiz) { # read packet from stream
    ($pmode, $pad, $pktt, $pcnt) = unpack("N x V2 x2 C", $ibuf);
    last if ($pmode & ~1) != 0x82000018; # unexpected or corrupted data
    $off = 16;
    $off = 15, $pcnt = 1 unless $pmode & 1; # if single payload packet
    for ($p = 0; $p < ($pcnt & 63); $off += $len, ++$p) { # check each payload
        ($sn, $objoff, $objsiz, $len) = unpack("x$off C x V x V x4 v", $ibuf);
        $off += 17;
        $off -= 2, $len = $pktsiz - 30 - $pad unless $pmode & 1;
        next unless $sn == 0x82 || ($sn & 63) == 1; # process only video key frame and audio
        $tbd = $objsiz & ~15 if $objoff == 0; # total bytes to decrypt in this frame
        $bts = ($bco + $len) & 15; # bytes to save (unless last payload in object)
        if ($cbd = ($bco + $len) & ~15) { # current bytes to decrypt in this payload
            if ($bco) {         # we have bytes carried over from previous packet
                $buf = tea($dco . substr($ibuf, $off, $cbd - $bco), $skey, 0); # decrypt
                $dco = substr($buf, 0, $bco); # fix data carried over
                substr($ibuf, $off, $cbd - $bco) = substr($buf, $bco); # fix current packet
                $bco = 0;
            }
            else {              # no carry over, just decrypt current payload
                substr($ibuf, $off, $cbd) = tea(substr($ibuf, $off, $cbd), $skey, 0);
            }
        }
        $bts = 0 unless ($tbd -= $cbd) > 0; # unless more to decrypt
        next unless $sn == 0x82 && $objoff == 0; # unless new KF
        $runt = int($pktt / 1000); # convert ms to seconds
        printf(STDERR "\r%02d:%02d:%02d pkts:%d", int($runt / 3600), int($runt / 60) % 60, $runt % 60, $pktn) unless $sleep; # show stats
    }
    ++$pktn;
    print $out $dco if $dco ne ''; # output (now decrypted) data carried from previous pkt
    if ($bco = $bts) {          # data to carry to next pkt
        print $out substr($ibuf, 0, -$bts); # output the stuff already decrypted
        $dco = substr($ibuf, -$bts, $bts); # save the last few bytes
    }
    else {                      # no carry-over
        print $out $ibuf;        # output the whole buffer
        $dco = '';
    }
    last if $dur && $runt > $dur;
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
   print "-hd flag              1 for Pro HD, 0 for Pro SD\n";
   print "-ip IP                slingbox IP to use\n";
   print "-port port            slingbox port (defaults to 5201)\n";
   print "-pass password        slingbox password\n";
   print "-vbw rate             video bit rate (defaults to 4000)\n";
   print "-vsm smoothness       video smoothness (1:64, defaults to 63)\n";
   print "-vs size              video resolution(3=QVGA,4=640x240,5=640x480,16=1920x1080)\n";
   print "-sleep secs           wait this many seconds before starting capture(defaults to 0)\n";
   print "-dur secs             capture only this many seconds (defaults to unlimited)\n";
   print "-chan channelNum      tune to this channel before capturing\n";
}
