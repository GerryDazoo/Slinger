import os
import sys
import socket
import sys
import time
import select
import binascii
import queue
from threading import Thread, get_ident
import platform
import datetime
import traceback
import requests
import re
from struct import pack, unpack, calcsize
from configparser import ConfigParser
from ctypes import *

version='3.07'

def encipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sum = c_uint32(0)
    delta = 0x61C88647
    n = 32
    w = [0,0]

    while(n>0):
        sum.value -= delta
        y.value += ( z.value << 4 ) + k[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1]
        z.value += ( y.value << 4 ) + k[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3]
        n -= 1

    w[0] = y.value
    w[1] = z.value
    return w

def decipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sum = c_uint32(0xc6ef3720)
    delta = 0x9e3779b9
    n = 32
    w = [0,0]

    while(n>0):
        z.value -= ( y.value << 4 ) + k[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3]
        y.value -= ( z.value << 4 ) + k[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1]
        sum.value -= delta
        n -= 1

    w[0] = y.value
    w[1] = z.value
    return w

def Crypt( data, key ):
    bytes = b''
    info = [int.from_bytes(data[i:i+4],byteorder='little')  for i in range(0, len(data), 4)]
    for i in range(0, len(info), 2):
        chunk = [info[i], info[i+1]]
        ciphertext = encipher(chunk, key)
        bytes = bytes + ciphertext[0].to_bytes(4, byteorder='little') + ciphertext[1].to_bytes(4, byteorder='little')
    return bytes

def Decrypt( data, key ):
    bytes = b''
    info = [int.from_bytes(data[i:i+4],byteorder='little')  for i in range(0, len(data), 4)]
    for i in range(0, len(info), 2):
        chunk = [info[i], info[i+1]]
        cleartext = decipher(chunk, key)
        bytes = bytes + cleartext[0].to_bytes(4, byteorder='little') + cleartext[1].to_bytes(4, byteorder='little')
    return bytes

def ts():
    return '%s ' % datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

def find_slingbox_info():
    import netifaces
    def ip4_addresses():
        ips = []
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addresses = netifaces.ifaddresses(interface)
            for address in addresses:
                info = addresses[address][0]
                if 'broadcast' in info:
                    ips.append((info['addr'],info['broadcast'])) 
        return ips

    boxes = []

    query =  [0x01, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

    ip = ''
    port = 0
    boxes = []
    print('No valid slingbox ip info found in config.ini')
    for local_ip, broadcast in ip4_addresses():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            print('Finding Slingbox on local network. My IP Info = ', local_ip)
            try:
                s.bind((local_ip, 0))
            except: continue
         
            s.sendto( bytearray(query), (broadcast, 5004 ))
            while True:
                try:
                    msg, source = s.recvfrom(128)
                    if len( msg ) == 124 :
                        data = unpack('62H', msg)
                        port = data[60]
                        name = ''
                        for i in range( 28, 60): name = name + chr(data[i])
                        print('Slingbox Found', source[0], port, '"',name, '"')
                        boxes.append((source[0], port, name))
                except :
                    break
    return boxes    

def closeconn( s ):
    if s :
 #       print('Closing Connection')
        try:
            s.shutdown(socket.SHUT_RDWR)
        except: pass
        s.close()
    return None

def register_slingboxes():
    global finderids
    
    def ping(addr):
        try:
 #          print('Pinging', addr)
           s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           s.connect(addr)
           s.sendall(b'PINGER')
 #          print('Good PING', addr)
           return True
        except Exception as e: 
           print('PING failure', addr, e)
           
        return False
        
    def get_external_ip(): 
        my_ip = ''
        while not my_ip: # wait for an IPADDRESS
           print('Getting external IP address')
           try:
               s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
               s.settimeout(10)
               s.connect(redirector)
               s.sendall(b'IPADDRESS')
               my_ip = s.recv(512).decode("utf-8") 
               s.close()
           except:
               print('Register: Error Getting Exteral IP Address, Retrying in 10 minutes')
               s.close()
               time.sleep(600)
               my_ip = ''
        print('Redirector, my external IP address', my_ip)
        return my_ip
 
    ############################################### 
    redirector = ('sbfinder.dazoo.net', 54321 )
    while True: 
        print(ts(), 'Registering Slingboxes', finderids)
        my_ip = get_external_ip()
        message = ''
        good_ping_addr = ''
        for id,port in finderids.items():
            pingaddr = (my_ip, port)
            if ping(pingaddr):
                good_ping_addr = pingaddr
                message = message + id + ':' + str(port) + '\r\n'
                
        if message :
            try:
                print('Registering', message )
                message = 'REGISTER\r\n' + message
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect(redirector)
                s.sendall( bytes(message, 'utf-8'))
                resp = s.recv(512)
                s.close()
            except: 
                print('Error connecting to cloud server retrying in 10 minutes', redirector)
                s.close()
                time.sleep(600)
                continue
        else:
            print('No working external portmaps. Not registering slingboxes')
            print('Retrying in 10 minutes')
            time.sleep(600)
            continue
        
        if resp != b'OK' : 
            print('Not OK, pausing 10 minutes')
            time.sleep(600)
            continue
        else:  
            print('Register Successful')
            ## Starting pinging every minute until failure (External IP address change or could be a messed up Portmap on the router.      
            fail_count = 0
            while fail_count < 3: 
                if good_ping_addr :
                    if ping(good_ping_addr): 
                        fail_count = 0 
                    else : 
                        fail_count = fail_count + 1
                        good_ping_addr = ''
                    time.sleep(60)
                else: 
                    print('Finding a good ping port')
                    for port in finderids.values():  # Find a working port
                        pingaddr = (my_ip, port)
                        if ping(pingaddr): 
                            good_ping_addr = pingaddr
                            print('Pinger, Found good port', good_ping_addr)
                            break
                    if good_ping_addr :
                        time.sleep(60)
                        continue
                    else: break
                    
            if not good_ping_addr :
                print('Ping failed on all ports. External IP address changed?')
                new_ip = get_external_ip()
                if new_ip == my_ip :
                    print('''!!!!!! No open ports or bad port maps on router !!!!!
No external access is possible. Giving up''')
                    return
                                              
               
def streamer(maxstreams, config_fn, server_port):
    global streamer_qs, stati
    smode = 0x2000               # basic cipher mode,
    sid = 0
    seq = 0
    tbd = 0
    dco = b''
    bco = 0
    bts = 0
    s_ctl = None
    stream = None
    dbuf = None
    skey = None
    stat = 0
    streams = []
    stream_header = None

    def pbuf(s):
  #      print(s)
        s = str(binascii.hexlify(s, ' ', 1))[2:-1].lower()
        cnt = 0
        out = ''
        for i in range(0, len(s), 48):
            ss = s[i:i+48]
 #           print( "%06d" % (cnt,), ss )
            out = out + "%06d " % (cnt,) + ss + '\r\n'
            cnt += 16
        return out

    def new_key( sid, rand, challange ):    
        def bits2bytes(bits):
            def abyte( b ):
                n = 0
                for abit in b[::-1]:
                    n = (n << 1) + abit
                return n
                
            ba = bytearray()
            for i in range(0,len(bits), 8 ):
                ba.append(abyte(bits[i:i+8]))     
            return ba     
               
        def xor( b1, b2 ):
            br = bytearray()
            l = len(b2)
            for i in range(0,l):
                br.append( b1[i] ^ b2[i])  
            return br + b1[l:]
                
        def dynk( rand, sid, a, b ): # hash function for dynamic key 
           
            def p(ba):  # make string from bits
                z = ord('0')
                out = ''
                for b in ba : out = out + chr(z+b)
                return out

            def bytes2bits( buf ):
                t = ''
                for b in buf:
                    t = t + '{:08b}'.format(b)[::-1]
                ba = bytearray()
                for c in t:
                    ba.append( ord(c) & 1 )
                return ba
                
        #******************************
            t = bytes2bits(rand)  
            s = bytes2bits(pack('H', sid ))
            td = [a, b]
            v = bytearray()    
            for i in range(1,17):
                r = i * td[((sid >> (i - 1)) & 1)]
                z = t[r:] + t[0:r]
                t = xor(z,s)
                v = xor(t, v)
            return v

 #       rand = bytearray.fromhex('feedfacedeadbeef1111222233334444')
 #       c = bytearray.fromhex( challange )
        my_key = xor( dynk(rand, sid, 2, 3), dynk(challange, sid, -1, -4))
  #      print( 'SKEY', pbuf(bits2bytes(my_key)) )
        return list(unpack('IIII', bits2bytes(my_key)))
        
    def futf16(in_str):
        out_str = ''
        for c in in_str: out_str = out_str + c + chr(0)
        return bytes(out_str, 'utf-8')

    def sling_cmd( opcode, data, msg_type=0x0101 ):
        nonlocal sid, seq, s_ctl, dbuf, skey, stat, smode
        parity = 0
        if smode == 0x8000 :
            for x in data:
              parity ^= x
#        print( 'Sending to Slingbox ', hex(opcode), hex(parity), '\r\n')
        seq += 1
        try:
            cmd = pack("<HHHHH 6x HH 4x H 6x", msg_type, sid, opcode, 0, seq, len(data), smode, parity) + Crypt(data, skey)
            s_ctl.sendall( cmd )
        except Exception as e:
            print('EXCEPTION', e, hex(msg_type), sid, hex(opcode), 0, seq, len(data), hex(smode), hex(parity))
            exit(1)

        if opcode == 0x66 : return

        response = s_ctl.recv(32)
        sid, stat, dlen = unpack("2x H 8x H 2x H", response[0:18] ) # "x2 v x8 v x2 v", $hbuf);
#        print( 'Sent to Slingbox ', hex(opcode), hex(parity), hex(len(data)))
#        print( 'Received from Slingbox', sid, hex(stat), dlen )
#        print('RESP', pbuf(response))
        if stat & stat != 0x0d & stat != 0x13 :
            print( "cmd:", hex(opcode), "err:",  hex(stat), dlen )
        if dlen > 0 :
            in_buf = s_ctl.recv( 512 )
            dbuf = Decrypt(in_buf, skey)
#            print('DBUF', hex(opcode), pbuf(dbuf))

    def sling_open(addr, connection_type):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024*1024*8)
        print('Connecting...', addr, connection_type )
        s.connect(addr)
        s.sendall(str.encode('GET /stream.asf HTTP/1.1\r\nAccept: */*\r\nPragma: Sling-Connection-Type=%s, Session-Id=%d\r\n\r\n' % (connection_type, sid)))
        return s

    def SetVideoParameters(resolution, FrameRate, VideoBandwidth, VideoSmoothness, IframeRate, AudioBitRate ):
        rand = bytearray.fromhex('feedfacedeadbeef1111222233334444') # 'random' challenge
        print('VideoParameters: Resolution=',resolution, 'FrameRate=', FrameRate,
              'VideoBandwidth=', VideoBandwidth, 'VideoSmoothness=', VideoSmoothness,
              'IframeRate=', IframeRate, 'AudioBitRate=', AudioBitRate)
        sling_cmd(0xb5, pack("11I 16s 2I 92x",
                         0xff,
                         0xff,
                         resolution, # Screen Size
                         1,
                         (IframeRate << 24 ) + (FrameRate << 16) + VideoBandwidth,
                          0x10001 + (VideoSmoothness << 8), #Video Smoothness
                         3, #fixed
                         1, #fixed
                         AudioBitRate,
#                         3,
                         0x4f,
                         1,
                         rand,
                         0x1012020,
                         1)); # set stream params
 
    def start_slingbox_session(streams):
        nonlocal stream_header, sid, seq, s_ctl, dbuf, skey, stat, smode
        global stati
        skey = [0xBCDEAAAA,0x87FBBBBA,0x7CCCCFFA,0xDDDDAABC]
 #       print('skey', skey )
        smode = 0x2000               # basic cipher mode,
        sid = seq = 0                # no session ID, seq 0
 #       print(name, 'Opening Control stream', hex(smode), sid, seq)
        s_ctl = sling_open(sling_net_address, 'Control') # open control connection to SB
        sling_cmd(0x67, pack('I 32s 32s 132x', 0, futf16('admin'), futf16(password))) # log in to SB
        rand = bytearray.fromhex('feedfacedeadbeef1111222233334444') # 'random' challenge
        try:
            sling_cmd(0xc6, pack('I 16s 36x', 1, rand)) # setup dynamic key on SB
        except:
            print(name,'Error Starting Session. Check your admin password in config.ini file!')
            return None, None
           
        skey = new_key(sid, rand, dbuf[0:16])
#        print('New Key ', skey)
        smode = 0x8000                # use dynamic key from now on
        try:
            sling_cmd(0x7e, pack("I I", 1, 0)) # stream control
        except:
            print(name,'Error with new encryption keys. Deleting keys.dat\r\n Please try again.')
            os.remove(keysfile) 
            return (None,None)
        while stat:
            print(name,'Box in use! Kicking off other user.' )
            stati[server_port] = name + ' Slingbox in Use! Cannot start session, kicking off other user..'
            sling_cmd(0x93, pack('32s 32s 8x', futf16('admin'), futf16(password)))
            time.sleep(1)
            sling_cmd(0x6a, pack("I 172x", 1)); # unk fn
            sling_cmd(0x7e, pack("I I", 1, 0)) # stream control
        
        ## Select input
        if VideoSource :
            print(name,'Selecting Video Source', VideoSource)
            source = int(VideoSource)
            sling_cmd(0x85, pack('4h', source, 0, 0, 0 ))          
            sling_cmd( 0x86, pack("h 254x", 0x0400 + source )) # Get Key Codes
            if len(dbuf) > 1 :
                i = 1
                codes = []
                while dbuf[i] != 0 and i < len(dbuf): 
                    codes.append(dbuf[i])
                    i += 1
                codes.sort()
                print('Keycodes=', codes)            
            
        sling_cmd(0xa6, pack("10h 76x", 0x1cf, 0, 0x40, 0x10, 0x5000, 0x180, 1, 0x1e,  0, 0x3d))
        SetVideoParameters(resolution, FrameRate, VideoBandwidth, VideoSmoothness, IframeRate, AudioBitRate )
        stream = sling_open(sling_net_address, 'Stream')
        first_buffer = bytearray(stream.recv(pksize, socket.MSG_PEEK))
#        print( 'FIRST', type(first_buffer), pbuf(first_buffer))
        h264_header = b'\x36\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c'
        h264_header_pos = first_buffer.find( h264_header ) + 50
 #       print( 'h246_header_pos', h264_header_pos, len( first_buffer ))
        if Solo:
            tbd = 0
            audio_header = b'\x91\x07\xDC\xB7\xB7\xA9\xCF\x11\x8E\xE6\x00\xC0\x0C\x20\x53\x65\x72'
            audio_header_pos = first_buffer.find( audio_header ) + 0x60 # find audio hdr
            first_buffer[audio_header_pos:audio_header_pos+10] = pack("H 8x", 0x9012)
            
        stream_header = first_buffer[0:h264_header_pos]
        #print( 'SH', type(stream_header), pbuf(stream_header))
        
        print(name,'Stream started at', ts(), len(stream_header), len(first_buffer[h264_header_pos:]))
        for s in streams :
            s.sendall(stream_header)
        # flush header from socket
        stream.recv(h264_header_pos)

        return s_ctl, stream

    def parse_cmd(msg):
        if msg[0] == 0x00 :
            return msg[1:].decode('utf-8').split('=')
        else:
            return 'IR', msg

    def start_new_stream(sock):
        time.sleep(1)
        streams.append(sock)

    def check_ip( sling_net_address):
        print('Checking for slingbox at', sling_net_address)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect(sling_net_address)
            print(sling_net_address, 'OK')
            return True
        except: 
            print('Error connecting to ', sling_net_address) 
            return False

    ################## START of Streamer Execution
    print('Streamer Running: ', maxstreams, config_fn, server_port)
    OK = b'HTTP/1.0 200 OK\r\nContent-type: application/octet-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n'
    ERROR =b'HTTP/1.0 503 ERROR\r\nContent-type: application/octet-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n'
    streamer_q = queue.Queue()
    streamer_qs[server_port] = streamer_q
    stream_clients = {}
    cp = ConfigParser()
    cp.read(config_fn)
    slinginfo = cp['SLINGBOX']
    slingip =  slinginfo.get('ipaddress', '' )
    slingport = int(slinginfo.get('port', '5201'))
    name = slinginfo.get('name', '' )
    finderid = slinginfo.get('finderid', '' )
    if finderid :
        # sanity checks
        finderid = finderid.strip().upper().split(':')
        ext_port = -1
        if len(finderid) == 2:
            try:
                ext_port = int(finderid[1], 10)
                if ext_port > 65535: raise
            except:
                print(name, 'ERROR: Finderid External Port must be between 0-65535')
                ext_port = -1
        else:
            ext_port = server_port
                
        if ext_port != -1:
            try:
                if (len(finderid[0]) == 32) and int(finderid[0],16): 
                    finderids[ finderid[0]] = ext_port
                else : print(name, 'ERROR: Invalid Finderid length. Must be 32 characters', finderid)
            except: print(name, 'ERROR: Finderid must only contain hexadecimal characters', finderid)
            
    bts = bco = runt = 0

    sling_net_address = (slingip, slingport)
    if not slingip == '' : 
        if not check_ip(sling_net_address): slingip = ''
    if not slingip:
        time.sleep(1)
        boxes = find_slingbox_info()
        if len(boxes):        
            if len(boxes)>1:
                print("""Found more than one slingbox on the local network.
Please select the one you want to use and update the config.ini accordingly.
\nGiving up. Sorry..""")
                return
            slingip = boxes[0][0]
            slingport = boxes[0][1]
            sling_net_address = (slingip, slingport)
    
    if not slingip:
        for port in stati.keys:
            msg =  "Can't find a slingbox on network. Please make sure it's plugged in and connected. Check config.ini"
            stati[port] = msg
        print(msg)
        time.sleep(10)

    def readnbytes(sock, n):
#        print( 'Reading', n )
        buff = b''
        try:
            while n > 0:
                b = sock.recv(n)
                buff += b
                if len(b) == 0:
                    return b          # peer socket has received a SH_WR shutdown
                n -= len(b)
        except:
            print('Error Reading video stream')
            buff = b''
        return buff

    def process_solo_msg( msg ):
    
        def cs( mybuf ):
            sum = 0
            for byte in mybuf:
                sum = sum + byte
            return sum
            
        nonlocal tbd, dco, bco, pc, bts
#        print('MSG', pbuf(msg[0:16]))
        msg = bytearray( msg )
        pmode = unpack(">I", msg[0:4])[0]
        pad, pktt, pcnt = unpack("<x I I 2x B", msg[4:16])
 #       print('pmode..', pc, hex(pmode), pad, pktt, pcnt)
        if ( pmode & 0xFFFFFFFE ) != 0x82000018 :
            print('Bad Pmode')
            return b''            

        off = 16
        if pmode == 0x82000018 :
            off = 15
            pcnt = 1
            
        p = 0
        while p < (pcnt & 63) :
 #           print( "loop", p, off, pcnt & 63); 
            fmt = "<B x I x I 4x H"
            size = calcsize(fmt)
            if off > 3000 - size : break 
            sn, objoff, objsiz, length = unpack(fmt, msg[off:off+size]);
 #           print( 'info', off, sn, objoff, objsiz, length )  
            off += 17
            if not pmode & 1 :
                off -= 2
                length = 2970 - pad   
            if ( sn == 0x82 or (sn & 63 == 1 )) : 
                if objoff == 0 : tbd = objsiz & ~15
                bts = (bco + length ) & 15
                cbd = (bco + length) & ~15
                if (cbd):
 #                  print( 'SN', sn, off, tbd, bts, objsiz, objoff, cbd, bco )

                   if (bco):
     #                  print('Decrypting',  bco, off, cbd)
                       buf = Decrypt(dco + msg[off:off + (cbd - bco)], skey); 
                       dco = buf[0:bco] # fix data carried over
                       msg[off:off+(cbd - bco)] = buf[bco:] # fix current packet
                       bco = 0;
                   else:
     #                  print('DEcrypting', off, cbd, len(msg), pbuf(msg[off:off+cbd]))
                       buf = Decrypt(msg[off:off+cbd], skey) # decrypt
    #                   print('DEcrypted', pbuf(buf))
                       msg[off:off+cbd] = buf
                tbd -= cbd
                if tbd == 0 : bts = 0
                if sn == 0x82 and objoff == 0:
                   break
               
            off += length
            p += 1 
        
#        print $out $dco if $dco ne '';
        msg = dco + msg
        bco = bts
        if bco > 0 : 
            dco = msg[-bts:]
            msg = msg[0:-bts]
 #           print('DCO', bts, pbuf(dco)[7:-2])
        else:
            dco = b''
            
        return msg
                                                       
    print('Using slingbox at ', sling_net_address)
    while True:
        stream_header = None
        streams = []
        # Wait for first stream request to arrive
        cp = ConfigParser()
        cp.read(config_fn)
        slinginfo = cp['SLINGBOX']
        name = slinginfo.get('name', '').strip()
        print('Streamer: ', name, 'Waiting for first stream, flushing any IR requests that arrive while not connected to slingbox')
        stati[server_port] = 'Waiting for first client. Slingbox at ' + str(sling_net_address)
        while True:
            cmd, value = parse_cmd(streamer_q.get())
            if cmd == 'STREAM': break
            if cmd == 'RESOLUTION' :
                print('Changing Resolution', value)
                resolution= int(value)
        cp.read(config_fn)
        slinginfo = cp['SLINGBOX']
        sbtype = slinginfo.get('sbtype', "350/500").strip()
        Solo = 'Solo' in sbtype
        password = slinginfo['password'].strip()
        name = slinginfo.get('name', '').strip()
        keysfile = str(server_port) + '.dat'
        resolution = int(slinginfo.get('Resolution', 12 )) & 15
        if resolution == 0 : 
            print(name, 'Invalid Resolution', resolution, 'Defaulting to 640x480')
            resolution = 5;
        FrameRate = int(slinginfo.get('FrameRate', 30 ))
        VideoBandwidth = int(slinginfo.get('VideoBandwidth', 2000 ))
        VideoSmoothness = int(slinginfo.get('VideoSmoothness', 63 ))
        IframeRate = int(slinginfo.get('IframeRate', 5 ))
        AudioBitRate = int(slinginfo.get('AudioBitRate', 64 ))
        VideoSource = slinginfo.get('VideoSource', '' )
        pksize = 3072
        if Solo : pksize = 3000
        print( '\r\nSlinginfo ', sbtype, password, resolution, FrameRate, slingip, slingport, pksize )

        client_addr = str(value)
        print(name, 'Starting Stream for ', client_addr)
        client_socket = (streamer_q.get()) ## Get the socket to stream o
        stream_clients[client_socket] = client_addr
        streams.append(client_socket)
        try: 
            client_socket.sendall(OK)
            s_ctl, stream  = start_slingbox_session(streams)
        except Exception as e:
            print(name, 'Badness starting slingbox session ', e, traceback.print_exc())
            killmyself()
        if s_ctl and stream :
            pc = 0
            lasttick = laststatus = lastkeepalive = last_remote_command_time = time.time()
            while streams:
                msg = readnbytes(stream, pksize)
                if Solo and len(msg) > 0: 
                    try:
                        msg = process_solo_msg( msg )
                    except:
                        print(name, 'Error Processing Solo Message, switching to 500')
                        Solo = False
                    if len(msg) == 0 :
                        print(ts(), name, 'Bad or Corrupted Solo message')
                
                if len(msg) == 0 :
                    print(ts(), name, 'Stream Stopped Unexpectly, possible slingbox video format change')
                    stream = closeconn(stream)
                    s_ctl = closeconn(s_ctl)
                    break
                    
                pc += 1
                for stream_socket in streams:                    
                    try:
                        sent = stream_socket.send(msg)
                    except Exception as e:
                        print(ts(), name, 'Stream Terminated for ', stream_clients[stream_socket], e)
                        del stream_clients[stream_socket]
                        streams.remove(stream_socket)
                        closeconn(stream_socket)
                        continue
                msg = b''
                curtime = time.time()
                if curtime - lasttick > 10.0 :
                    print('.', end='')
                    stati[server_port] = name + ' Slingbox Streaming %d clients. Resolution=%d Packets=%d' % (len(streams), resolution, pc)
                    lasttick = curtime
                    sys.stdout.flush()

                if curtime - laststatus > 90.0 :
                    print( ts(), name, '%d Clients.' % len(streams), end='')
                    for c in stream_clients.values(): print( c, end=' ')
                    print('')
                    laststatus = curtime
                    sys.stdout.flush()

                if curtime - lastkeepalive > 10.0 :
    #                  print('Sending Keep Alive' )
                    sling_cmd(0x66, '') # send a keepalive
                    lastkeepalive = curtime
                    socket_ready, _, _ = select.select([s_ctl], [], [], 0.0 )
                    if socket_ready : s_ctl.recv(8192)

                if (not streamer_q.empty()) and (curtime - last_remote_command_time > 0.5):
                    cmd, data = parse_cmd(streamer_q.get())
                    print( name, 'Got Streamer Control Message', cmd, data )
                    if cmd == 'RESOLUTION' :
                        resolution = int(value)
                        s_ctl = closeconn(s_ctl)
                        stream = closeconn(stream)
                        pc = 0
                        s_ctl, stream = start_slingbox_session(streams)
                    elif cmd == 'STREAM' :
                        new_stream = streamer_q.get()
                        if len(streams) == maxstreams :
                            new_stream.sendall(ERROR)
                            closeconn(new_stream)
                        else:
                            new_stream.sendall(OK)
                            stream_clients[new_stream] = data
                            #streams.append(new_stream)
                            new_stream.sendall(stream_header)
                            print('New Stream Starting')
                            Thread(target=start_new_stream, args=(new_stream,)).start()
                    elif cmd == 'IR':
                        print(name,'Sending IR command', data[0:4])
                        sling_cmd(0x87, data[0:4] + pack('467x 4h', data[3], 0, 0, 0), msg_type=0x0101)
                        last_remote_command_time = time.time()

            ### No More Streams OR input stream stopped
            print(name, 'Shutting down connections')
            s_ctl = closeconn(s_ctl)
            stream = closeconn(stream)
            for s in streams: closeconn(s)
        else:
            print(name,'ERROR: Slingbox session startup failed.')
    print(name, 'Streamer Exiting.. should never get here')
    s_ctl = closeconn(s_ctl)
    stream = closeconn(stream)

def remote_control_stream( connection, client, request, server_port):
    def fix_host(request):
        start_host = request.find('Host:')
        start_port = request.find(':', start_host + 5 )+1
        end_port = request.find('\r\n', start_host)
#        print(request)
#        print('Fixing', start_port, end_port, request[0:start_port] + str(server_port) + request[end_port:])
        return bytes(request[0:start_port] + str(server_port) + request[end_port:], 'utf-8')
     
    http_port = server_port + 1
    print('\r\nStarting remote control stream handler for ', str(client), 'to port', http_port)
    remote_control_socket =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_control_socket.connect(('127.0.0.1', http_port ))  ## Send Packets to Flask
    print('Remote Control Connected')
#    print('GOT', request )
    request = fix_host(request)
#    print(request)

    remote_control_socket.sendall(request)
    sockets = [remote_control_socket, connection]
    POST = 'POST'.encode('utf-8')
    GET = 'GET'.encode('utf-8')
    
    while True:
 #       print('Waiting for data')
        read_sockets, _, _ = select.select(sockets, [], [])
        for sock in read_sockets:
            try: data = sock.recv(32768)
            except: break
            if len(data) == 0 :
                break
            if sock == connection: 
 #               print(data[0:10].decode("utf-8"))
                if POST in data or GET in data:
                    data = fix_host(data.decode("utf-8"))
                remote_control_socket.sendall(data)
            if sock == remote_control_socket: 
                connection.sendall(data)
        else:
            continue
        break
    connection = closeconn(connection)
    remote_control_socket = closeconn(remote_control_socket)
    print('Exiting Remote Control Stream Handler for', client )

def remote_control_channel(server_port, channel):
    global streamer_qs
    streamer_q = streamer_qs[server_port]
    Page, cmds, rccode = remotes[port]
    rcbytes = bytearray(3)
    rcbytes[0] = 0
    rcbytes[1] = 0
    rcbytes[2] = rccode
    digits2buttons = [18,9,10,11,12,13,14,15,16,17]
    if channel[0] == '?' :
       kc = int(channel[1:])
       print('Sending test keycode', kc )
       streamer_q.put(kc.to_bytes(1, byteorder='little') + rcbytes)
    else:
        print('Sending Channel Digits', channel)
        for digit in channel:
            if digit in '0123456789' :
                streamer_q.put(digits2buttons[int(digit)].to_bytes(1, byteorder='little') + rcbytes)
    print('Exiting Remote Control Channel Handler for', channel )


########################################################################
def ConnectionManager(config_fn):
    global streamer_qs

    cp = ConfigParser()
    cp.read(config_fn)
    serverinfo = cp['SERVER']
    local_port = int(serverinfo.get('port', '8080'))
    maxstreams = int(serverinfo.get('maxstreams', 4))
    remoteenabled = serverinfo.get('enableremote', 'yes') == 'yes'
    print('Connection Manager Running on port %d with %d max streams....' % (local_port,maxstreams))

    server_address = ('', local_port)

    Thread(target=streamer, args=(maxstreams, config_fn, local_port)).start()

    # Create a TCP/IP socket
    ConnectionManagerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ConnectionManagerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('starting up on %s port %s' % server_address )
    ConnectionManagerSocket.bind(server_address)
    ConnectionManagerSocket.listen()

    while True:
        # Wait for a connection
 #       print(ts(), 'waiting for a connection')
        try:
            connection, client_address = ConnectionManagerSocket.accept()
        except:
            print(ts(), 'Restarting ConnectionManager')
            ConnectionManagerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ConnectionManagerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print('starting up on %s port %s' % server_address )
            ConnectionManagerSocket.bind(server_address)
            ConnectionManagerSocket.listen(maxstreams)
            continue

        try:
            ready_read, ready_write, exceptional = select.select([connection], [], [], 0.4)
            if not ready_read:
                #print(ts(), 'No request in time, hacker?', str(client_address))
                #close silenty Chrome browers opens connection and then doesn't send anything
                connection = closeconn(connection)
                continue

            data = connection.recv(1024).decode("utf-8")
            if 'slingbox' in data and 'GET' in data:
                print(ts(), ' Streaming connection from', str(client_address))
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024*1024*8)
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                connection.setblocking(False)
                if streamer_qs[local_port] : # Streamer Thread ready to accept connections
                    streamer_q = streamer_qs[local_port]
                    streamer_q.put( bytearray(1) + bytes('STREAM=%s:%d' % client_address, 'utf-8'))
                    streamer_q.put(connection)
                    if 'channel' in data:
                        result = re.search('channel=(\d+)', data)
                        if result:
                            channel = result.group(1)
                            print('Sending Channel Digits', channel)
                            Thread(target=remote_control_channel, args=(local_port, channel)).start()
                else:
                    connetion = closeconn(connection)
            elif 'emote' in data and ('GET' in data or 'POST' in data) and remoteenabled :
                print(ts(), ' RemoteControl connection from', str(client_address))
                Thread(target=remote_control_stream, args=(connection, client_address, data, local_port)).start()
            elif not 'PINGER' in data:
                print('Hacker Alert. Invalid Request from ', client_address )
                connection = closeconn(connection)
                continue
        except Exception as e:
            print( 'Hacker Alert. Bad Data from ', client_address )
            connection = closeconn(connection)
            continue

def killmyself():
    if 'windows' in platform.platform().lower():
        os.system('taskkill /f /pid %d /t' % mypid)
    else:
        os.system('kill -9 %d' % mypid)

def parse_buttons(buttons):
    lines = buttons.split('\n')
#        print('LINES=', lines)
    cmds = []
    for line in lines:
#            print('Line=', line)
            name, value = line.split(':', 1)
#               print( name, value)
            name = name.replace("'", '')
            cmds.append((name.strip(), value.strip()))
#       print(cmds)
    return cmds

def BuildPage(cp):
    BasePage = '''
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"><html>
<head>
  <meta http-equiv="content-type" content="text/html; charset=UTF-8">
  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
  <meta http-equiv="Pragma" content="no-cache" />
  <meta http-equiv="Expires" content="0" />
  <title>Remote</title>
  <style>
     %s
  </style>
</head>
<body>
     <form method="post" action="/Remote">
        %s
     </form>
     <h3>Status:%s</h3>
</body>
</html>
'''
    default_style='''
.button {
  border: none;
  color: white;
  background-color: blue;
  padding: 0px 20px;
  text-align: center;
  text-decoration: none;
  display: inline-block;
  font-size: 70px;
  margin: 4px 2px;
  cursor: pointer;
}

.round {
  border: none;
  color: white;
  background-color: green;
  padding: 0px 20px;
  text-align: center;
  text-decoration: none;
  display: inline-block;
  font-size: 70px;
  margin: 4px 2px;
 cursor: pointer;
  border-radius: 50%;
}
  
.text {
  border: none;
  color: black;
  background-color: lightblue;
  text-align: center;
  text-decoration: none;
  display: inline-block;
  font-size: 60px;
  margin: 4px 2px;
  cursor: pointer;
}'''

    default_buttons=''''1' : 9 : round
        :&nbsp;&nbsp;
        '2' : 10 : round
         :&nbsp;&nbsp;
        '3' : 11 : round
        :&nbsp;&nbsp;
        '4' : 12 : round
         :&nbsp;&nbsp;
        '5' : 13 : round
        :&nbsp;&nbsp;
        '6' : 14 : round
         :&nbsp;&nbsp;
        '7' : 15 : round
        :&nbsp;&nbsp;
        '8' : 16 : round
        :&nbsp;&nbsp;
        '9' : 17 : round
        :&nbsp;&nbsp;
        '0' : 18 : round
        :<br><br>
        'OK' : 42
         :&nbsp;&nbsp;
        'Up' : 38
        :&nbsp;&nbsp;
        'Down' : 39
        :&nbsp;&nbsp;
        'Left' : 40
        :&nbsp;&nbsp;
        'Right': 41
        :<br><br>
        :&nbsp;&nbsp;
        'Guide' : 35
        :&nbsp;&nbsp;
        'Last' : 56
        :&nbsp;&nbsp;
        'Exit' : 37
        :&nbsp;&nbsp;
        'DVR' : 23
        :<br><br>
        'FF' : 28
        :&nbsp;&nbsp;
        'Rew' : 27
        :&nbsp;&nbsp;
        'Play' : 24
        :&nbsp;&nbsp;
        'Pause' : 26
        : <br><br>
        'Ch+' : 4
        :&nbsp;&nbsp;
        'Ch-' : 5
        :&nbsp;&nbsp;
        'Pg-' : 43
        :&nbsp;&nbsp;
        'Pg+' : 44
        : <br><br>
        'Day-' : 59
        :&nbsp;&nbsp;
        'Day+' : 60
        :<br><br>
        'Rec' : 29
        :&nbsp;&nbsp;
        'OnDemand': 34
        :&nbsp;&nbsp;
        'Menu' : 33
        :<br><br>
        'Power' : 1
        :&nbsp;&nbsp;
        '1920x1080' : 16
        :&nbsp;&nbsp;
        '1280x720' : 12
        :<br><br>
        'Restart': Restart
        :&nbsp;&nbsp;
        'Channel': Channel
        'RT' : RCtest'''

    style = default_style
    buttons = default_buttons
    
    remoteinfo = cp['REMOTE'] 
    rccode = int(remoteinfo.get('code', '0'))
    fn = remoteinfo.get('include', '')
    if fn:  # Get form data myself
        print('Reading Custom Remote definition from', fn)
        try:
            f = open(fn)
            data = f.read()
            f.close()
            start_style = data.find('style=')
            start_buttons = data.find('buttons=')
            style=data[start_style+6:start_buttons].strip()
            buttons = data[start_buttons+8:].strip()
#            print('STYLE', style,'BUTTONS', buttons)
        except:
            print('Error reading remote definition file, using defaults')
            
    style = style.replace('%', '%%')
    cmds = parse_buttons(buttons)
    formstr = ''
    for key, data in cmds:
        if key == '':
            formstr = formstr + data
        else:
#            print('BUTTON', data)
            try: btn_class = data.split(':')[1].strip()
            except: btn_class = 'button'
            formstr = formstr + '<button class=%s type="submit" name="%s" value="%s">%s</button>' % (btn_class, key, str(data), key)
            if 'Channel' == data:
                formstr = formstr + '<input class=text type="text" name="Digits" maxlength="4" size="4" id="" value=""></input>'
        page = BasePage % ( style, formstr, '%s' )
 #       print('PAGE', page)
    return page, cmds, rccode
        
###############################################################################
###########   START OF EXECUTION #####################################
mypid = os.getpid()
print( 'Version :', version, 'Running on', platform.platform(), 'pid=', mypid)

streamer_qs = {}
stati = {}
remotes = {}
finderids = {}
tcode = 0
if len(sys.argv) == 1 : sys.argv.append('config.ini')
for config_fn in sys.argv[1:] :
    if os.path.exists( config_fn ):
        print( 'Using config file', config_fn )
    else:
        print( "Can't find specified config file", config_fn, 'Giving up.' ) 

    Thread(target=ConnectionManager, args=(config_fn,)).start()

    cp = ConfigParser()
    cp.read(config_fn)
    serverinfo = cp['SERVER']
    port = int(serverinfo.get('port', '8080'))
    
    stati[port] = 'Waiting for first update...'
    http_port = port + 1
    cmds = None
    if serverinfo.get('enableremote', 'yes') == 'yes' :
        from flask import Flask, render_template, request, render_template_string
        remotes[port] = BuildPage(cp)
        
        app = Flask(__name__)

        @app.route('/Remote', methods=["GET"])
        def index():
  #          print('HOST', request.host)
            port = int(request.host.split(':')[1]) 
            return render_template_string(remotes[port][0] % stati[port])

        @app.route('/Remote', methods=["POST"])
        def button():
            global streamer_qs, tcode, stati
            port = int(request.host.split(':')[1])
 #           print('PORT', port, streamer_qs)
            streamer_q = streamer_qs[port]
            Page, cmds, rccode = remotes[port]
            rcbytes = bytearray(3)
            rcbytes[0] = 0
            rcbytes[1] = 0
            rcbytes[2] = rccode
            print('Remote Code:', rccode, hex(rcbytes[0]),hex(rcbytes[1]),hex(rcbytes[2]))
                
            digits2buttons = [18,9,10,11,12,13,14,15,16,17]
            print('Button Clicked', request.form)
            if request.form.get('Digits'):
                channel = request.form.get('Digits').strip()
                if channel[0] == '?' :
                    kc = int(channel[1:])
                    print('Sending test keycode', kc )
                    streamer_q.put(kc.to_bytes(1, byteorder='little') + rcbytes)
                else:
                    print('Sending Channel Digits', channel)
                    for digit in channel:
                        if digit in '0123456789' :
                            streamer_q.put(digits2buttons[int(digit)].to_bytes(1, byteorder='little') + rcbytes)
            else:
                for tuple in cmds:
                    cmd = tuple[0]
                    data = request.form.get(cmd)
                    if data != None:
                        if data == 'RCtest':
                            rccode = tcode
                            print('Remote Test', rccode )
                            tbytes = bytearray(4)
                            tbytes[0] = 1
                            tbytes[1] = 0
                            tbytes[2] = 0
                            tbytes[3] = rccode
                            streamer_q.put(tbytes) 
                            stati[port] = 'Testing Remote Code = %d' % tcode
                            tcode += 1
                            remotes[port] = (Page,cmds,rccode)
                            if tcode == 3 : tcode = 0
                        elif cmd == 'Restart' :
                            print('Restarting, killing myself')
                            killmyself()
                        elif 'x' in cmd and cmd != 'Exit':
     #                       print('Changing Resolution', data )
                            streamer_q.put( bytearray(1) + bytes('RESOLUTION=%s' % data, 'utf-8'))
                        elif cmd == 'Channel' : pass # Channel request with no digits
                        else:
                            data = data.split(':')[0].strip()
    #                       print('KEY', data )
                            streamer_q.put(int(data).to_bytes(1, byteorder='little') + rcbytes)
            return render_template_string(Page%stati[port])

        Thread(target=lambda: app.run(host='0.0.0.0', port=http_port, debug=False, use_reloader=False)).start()
        time.sleep(1) # give Flask sometime to start up makes logs easier to read

if len(finderids) : Thread(target=register_slingboxes).start()
while True: time.sleep(1)
