#!/usr/bin/env python
import sys
try:
    assert sys.version_info >= (3,7)
except:
    print('This program requires Python version 3.7 or higher.')
    exit(100)
import os
import socket
import sys
import time
import select
import queue
import re
import subprocess
from threading import Thread, get_ident
import platform
import datetime
import traceback
import ipaddress
from struct import pack, unpack, calcsize
from configparser import ConfigParser
from ctypes import *
import mimetypes

version='3.08f'

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
    return '%s ' % datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S.%f").rstrip('0')[:-3]
    
def pbuf(s):
    s = ''.join('{:02x} '.format(x) for x in s).upper()
    cnt = 0
    out = ''
    for i in range(0, len(s), 48):
        ss = s[i:i+48].strip()
#           print( "%06d" % (cnt,), ss )
        out = out + "%06d " % (cnt,) + ss + '\r\n'
        cnt += 16
    return out
        
def find_slingbox_info(name):
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
    print(name, 'No valid slingbox ip info found in config.ini')
    for local_ip, broadcast in ip4_addresses():
        if local_ip == '127.0.0.1': continue
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                s.bind((local_ip, 0))
            except Exception as e:
 #               print('Error binding socket to send broadcast', e )
                continue
                
            print('Finding Slingbox on local network. My IP Info = ', local_ip)
            s.sendto( bytearray(query), (broadcast, 5004 ))
            while True:
                try:
                    msg, source = s.recvfrom(128)
#                    print('MSG', len(msg), source, pbuf(msg))
                    if len(msg) == 124 :
                        port = msg[121] * 256 + msg[120]
                        name = ''
                        for char in msg[ 56:120]:
                            if char != 0: name = name + chr(char)
                        finderid = ''.join('{:02x}'.format(x) for x in msg[40:56])
                        print('Slingbox Found', source[0], port, '"',name, '"', 
                        'FinderID', finderid.upper())
                        boxes.append((source[0], port, name))
                except Exception as e:
 #                   print(e, traceback.print_exc())
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
 #          print('Good Slinger Remote Access Test', addr)
           return True
        except Exception as e: 
           print(ts(), 'Slinger Remote Access Test failure', addr, e)
           
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
               closeconn(s)
           except:
               print('Register: Cannot Get External IP Address, Retrying in 10 minutes. Warning only not service affecting.')
               closeconn(s)
               time.sleep(600)
               my_ip = ''
        print('Redirector, my external IP address', my_ip)
        return my_ip
 
    ############################################### 
    redirector = ('sbfinder.dazoo.net', 54321 )
    fail_count = 0
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
                closeconn(s)
            except: 
                print("Warning can't connecting to cloud server retrying in 10 minutes", redirector)
                closeconn(s)
                time.sleep(600)
                continue
        else:
            print('No working external portmaps. Not registering slingboxes')
            fail_count = fail_count + 1
            if fail_count > 3 :         
                print('''!!!!!! No open ports or bad port maps on router or missing firewall rules !!!!!
No external access is possible. Giving up trying to register slingbox''')
                return
            print('Retry', fail_count, 'in 10 minutes')
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
                    print('Finding a good remote access port')
                    for port in finderids.values():  # Find a working port
                        pingaddr = (my_ip, port)
                        if ping(pingaddr): 
                            good_ping_addr = pingaddr
                            print('Pinger, Found good remote accessport', good_ping_addr)
                            break
                    if good_ping_addr :
                        time.sleep(60)
                        continue
                    else: break
                    
            if not good_ping_addr :
                print('Remote access test failed on all ports. External IP address changed?')
                new_ip = get_external_ip()
                if new_ip == my_ip :
                    print('''!!!!!! No open ports or bad port maps on router or missing firewall rules !!!!!
No external access is possible. Giving up. You can still stream locally.''')
                    return
                                              
def find_max_buffer_size( opt ):
    size = 1024*1024*8
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while size > 0 :
        try:
 #           print( 'trying', size )
            sock.setsockopt(socket.SOL_SOCKET, opt, size )
            break
        except : 
            size = size - (1024*1024)
            continue 
    if size < 1024*1024*8 :
        print('Warning TCP buffering might not be sufficent for reliable streaming')
    return size         
        
def streamer(maxstreams, config_fn, section_name, box_name, streamer_q, server_port):
    global streamer_qs, stati, num_streams
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
    rccode = 0
    streams = []
    stream_header = None
    max_recv_tcp_buffer = find_max_buffer_size(socket.SO_RCVBUF)

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
            return

        if opcode == 0x66 : return

        response = s_ctl.recv(32)
        sid, stat, dlen = unpack("2x H 8x H 2x H", response[0:18] ) # "x2 v x8 v x2 v", $hbuf);
#        print( 'Sent to Slingbox ', hex(opcode), hex(parity), hex(len(data)))
#        print( 'Received from Slingbox', sid, hex(stat), dlen )
#        print('RESP', pbuf(response))
        if opcode == 0x68 : return  # ignore logout errors
        if stat & stat != 0x0d & stat != 0x13 :
            print( "cmd:", hex(opcode), "err:",  hex(stat), dlen )
        if dlen > 0 :
            in_buf = s_ctl.recv( 512 )
            dbuf = Decrypt(in_buf, skey)
#            print('DBUF', hex(opcode), pbuf(dbuf))

    def sling_open(addr, connection_type):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, max_recv_tcp_buffer)
        print('Connecting...', addr, connection_type )
        s.connect(addr)
        s.sendall(str.encode('GET /stream.asf HTTP/1.1\r\nAccept: */*\r\nPragma: Sling-Connection-Type=%s, Session-Id=%d\r\n\r\n' % (connection_type, sid)))
        return s

    def SetVideoParameters(resolution, FrameRate, VideoBandwidth, VideoSmoothness, IframeRate, AudioBitRate ):
        rand = bytearray.fromhex('feedfacedeadbeef1111222233334444') # 'random' challenge
        print('VideoParameters: Resolution=',resolution, 'FrameRate=', FrameRate,
              'VideoBandwidth=', VideoBandwidth, 'VideoSmoothness=', VideoSmoothness,
              'IframeRate=', IframeRate, 'AudioBitRate=', AudioBitRate)
        try:
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
        except:
            print('Slingbox returned error trying to set video parameters')
            print('Please validate parameters.')
            return False
        return True
     
    def start_slingbox_session(streams):
        nonlocal stream_header, sid, seq, s_ctl, dbuf, skey, stat, smode
        global stati, num_streams
        skey = [0xBCDEAAAA,0x87FBBBBA,0x7CCCCFFA,0xDDDDAABC]
 #       print('skey', skey )
        smode = 0x2000               # basic cipher mode,
        sid = seq = 0                # no session ID, seq 0
 #       print(name, 'Opening Control stream', hex(smode), sid, seq)
        s_ctl = sling_open(sling_net_address, 'Control') # open control connection to SB
        if password.upper().startswith('E1:'):
            print( name, 'Using encrypted password:', password)
            pw = password.upper().replace('E1:', '').strip()
            try:
                pw_bytes = bytearray.fromhex(pw)
                clear = Decrypt(pw_bytes, skey)
            except:
                print('Bad E1: Password cannot decrypt. Missing/bad characters?')
                return (closeconn(s_ctl), None)
            eos = clear.find(b'\x00\x00')
            if eos > 0:
                clear = clear[0:eos+2]
            else:
                print('name, Bad E1: Password Missing characters')
                return (closeconn(s_ctl), None)   
 #           print(eos, clear)
            sling_cmd(0x67, pack('I 32s 32s 132x', 0, futf16('admin'), clear)) # log in             
        else:
            sling_cmd(0x67, pack('I 32s 32s 132x', 0, futf16('admin'), futf16(password))) # log in to SB
        rand = bytearray.fromhex('feedfacedeadbeef1111222233334444') # 'random' challenge
        try:
            sling_cmd(0xc6, pack('I 16s 36x', 1, rand)) # setup dynamic key on SB
        except:
            print(name,'Error Starting Session. Check your admin password in config.ini file!')
            return s_ctl, None
           
        skey = new_key(sid, rand, dbuf[0:16])
#        print('New Key ', skey)
        smode = 0x8000                # use dynamic key from now on
        try:
            sling_cmd(0x7e, pack("I I", 1, 0)) # stream control
        except:
            print(name,'Error with new encryption keys.')
            return (s_ctl,None)
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
            try:
                sling_cmd(0x85, pack('4h', source, 0, 0, 0 )) 
            except:
                print('Error trying to set VideoSource. Please make sure the supplied value is valid for your slingbox model')
                return ( s_ctl, None )
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
        if not SetVideoParameters(resolution, FrameRate, VideoBandwidth, VideoSmoothness, IframeRate, AudioBitRate ) :
            return (s_ctl,None)
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
        if SB240:
            tbd = 0
            audio_header = b'\xA1\xDC\xAB\x8C\x47\xA9\xCF\x11\x8E\xE6\x00\xC0\x0C\x20\x53\x65\x68'
            audio_header_pos = first_buffer.find( audio_header ) + 0x60 # find audio hdr
            first_buffer[audio_header_pos:audio_header_pos+10] = pack("H 8x", 0x9012)
            
        stream_header = first_buffer[0:h264_header_pos]
        #print( 'SH', type(stream_header), pbuf(stream_header))
        
        print(name,'Stream started at', ts(), len(stream_header), len(first_buffer[h264_header_pos:]))
        for s in streams :
            try:
                s.sendall(stream_header)
            except:
                print(name, 'ERROR: Media Player closed connection immediately after receiving 200 OK')
                return (s_ctl, None )
        # flush header from socket
        stream.recv(h264_header_pos)

        return s_ctl, stream

    def parse_cmd(msg):
 #       print('Q',msg)
        if msg[0] == 0x00 :
            return msg[1:].decode('utf-8').split('=')
        else:
            return 'IR', msg

    def start_new_stream(sock):
        time.sleep(1)
        streams.append(sock)        

    def check_ip( sling_net_address ):
        print('Checking for slingbox at', sling_net_address)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect(sling_net_address)
            print(sling_net_address, 'OK')
            s.close()
            return True
        except: 
            print('Error connecting to ', sling_net_address) 
            s.close()
            return False
    
    def public_ip(ip):
        if ip == '' : return False
        if ip.startswith('192.168.'): return False            
        if ip.startswith('10.'): return False
        if ip.startswith('127.0.'): return False
        if ip.startswith('172.') :
            second_octet = int(ip.split('.')[1])
            if second_octet > 15 and second_octet < 33 : return False 
        return True
            
    def start_streaming_connection(ip):
        global num_streams
        if public_ip(ip) :
            if num_streams == maxstreams :
                print( 'Max remote streams', maxstreams, 'reached. Ignoring new streaming request')
                return False
                
            num_streams = num_streams + 1
            print('Starting remote stream', num_streams )
        return True
        
    def close_streaming_connection(s):
        global num_streams
        if s :
            if public_ip(stream_clients[s]) :
                num_streams = num_streams - 1
                print( num_streams, 'active remote connections')
                
            del stream_clients[s]
            streams.remove(s)
            return closeconn(s)
        return None
        
    def closecontrol(s):
        if s :
            print( name, 'Logging Out')
            try:
                if Solo: sling_cmd( 0x68, b'')
            except: pass
            return closeconn(s)

    ################## START of Streamer Execution
    print('Streamer Running: ', maxstreams, config_fn, section_name, box_name, server_port, max_recv_tcp_buffer)
    OK = b'HTTP/1.0 200 OK\r\nContent-type: application/octet-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n'
    ERROR =b'HTTP/1.0 503 ERROR\r\nContent-type: application/octet-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n'
    stream_clients = {}
    cp = ConfigParser()
    cp.read(config_fn)
    slinginfo = cp[section_name]
    slingip =  slinginfo.get('ipaddress', '' )
    slingport = int(slinginfo.get('port', '5201'))
    name = slinginfo.get('name', box_name )
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
        
    if not slingip and not public_ip(sling_net_address[0]):
        time.sleep(1)
        boxes = find_slingbox_info(name)
        if len(boxes):        
            if len(boxes)>1:
                print("""Found more than one slingbox on the local network.
Please select the one you want to use and update the config.ini accordingly.
\n%s Giving up. Sorry..""" % name)
                return
            slingip = boxes[0][0]
            slingport = boxes[0][1]
            sling_net_address = (slingip, slingport)
    
    if not slingip:
        msg =  "Can't find a slingbox on network. Please make sure it's plugged in and connected. Check config.ini"
        for port in stati.keys():
            stati[port] = msg
        print(msg)
        time.sleep(5)
        print( name, 'Giving up. Sorry...')
        return

    def readnbytes(sock, n):
#        print( 'Reading', n )
        buff = b''
        try:
            while n > 0:
                b = sock.recv(n)
                if len(b) == 0:
                    return b          # peer socket has received a SH_WR shutdown
                buff += b
                n -= len(b)
        except Exception as e:
            print(name, 'Error Reading video stream')
            buff = b''
        return buff

    def process_solo_msg( msg, sock ):
    
        def cs( mybuf ):
            sum = 0
            for byte in mybuf:
                sum = sum + byte
            return sum
            
        nonlocal tbd, dco, bco, pc, bts, stream_header
#        print('MSG', pbuf(msg[0:16]))
        msg = bytearray( msg )
        pmode = unpack(">I", msg[0:4])[0]
        pad, pktt, pcnt = unpack("<x I I 2x B", msg[4:16])
        header = b''        
 #       print('pmode..', pc, hex(pmode), pad, pktt, pcnt)
        if ( pmode & 0xFFFFFFFE ) != 0x82000018 :  
            magic = bytes(u'Slingbox'.encode('utf-16le'))
 #           print('MAGIC', magic)
            if magic in msg:
                print(ts(), name, 'Solo/ProHD Input Video Format Changed. Stream Restarted')
                return b'Restart'
                
                tbd = bts = bco = runt = 0
                dco = b''

                h264_header = b'\x36\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c'
                h264_header_pos = msg.find( h264_header ) + 50
 #               print( 'h246_header_pos', h264_header_pos, len( msg ))

                audio_header = b'\x91\x07\xDC\xB7\xB7\xA9\xCF\x11\x8E\xE6\x00\xC0\x0C\x20\x53\x65\x72'
                audio_header_pos = msg.find( audio_header ) + 0x60 # find audio hdr
                msg[audio_header_pos:audio_header_pos+10] = pack("H 8x", 0x9012)

                header = msg[0:h264_header_pos]
#                print('Headers', len(stream_header), len(header))
 #               stream_header = header
                rest = readnbytes(sock, h264_header_pos)
                msg = msg[h264_header_pos:] + bytearray(rest)
                print( name, 'Synced')
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

        return header + msg
        
    def SendKeycode( key, rccode ):
        print('sending key', key, rccode )
        if '.' in key:
            code,chan,subchan = key.split('.')
            cmd = bytearray(8)
            cmd[0] = int(code)
            cmd[1] = 0
            cmd[2] = 0
            cmd[3] = 0
            cmd[4] = int(chan)
            cmd[5] = 0
            cmd[6] = int(subchan)
            cmd[7] = 0
            sling_cmd(0x89, cmd + pack('8x'), msg_type=0x0101)
        else:
            cmd = bytearray(4)
            cmd[0] = int(key)
            cmd[1] = 0
            cmd[2] = 0
            cmd[3] = rccode
            sling_cmd(0x87, cmd + pack('467x 4h', cmd[3], 0, 0, 0), msg_type=0x0101)
    
    def send_start_channel( channel, rccode ):
        if channel : 
            if channel != '0':
                print(ts(), name, 'Sending Start Channel', channel)
                if '+' in channel:
                    for keycode in channel.split('+'): SendKeycode(keycode, rccode)
                elif '.' in channel:
                    SendKeycode( '2.' + channel, 0 )              
                else:
                    digits2buttons = ['18','9','10','11','12','13','14','15','16','17']
                    for digit in channel:
                        if digit in '0123456789' :
                            SendKeycode( digits2buttons[int(digit)], rccode)
        return None
                    
    def parse_stream( header ):
        bits = header.split(':')
        return ( bits[0]+':'+bits[1], bits[2] )
        
    def RemoteLocked(sender_ip):
        if RemoteLock and sender_ip != 'Server' and (sender_ip != primary_stream_client):
            print(name, 'Ignoring IR request from', sender_ip, 'Remote Locked by', primary_stream_client )
            return True
        else: return False

                                                          
    print(name, 'Using slingbox at ', sling_net_address)
    while True:
        stream_header = None
        streams = []
        # Wait for first stream request to arrive
        cp = ConfigParser()
        cp.read(config_fn)
        slinginfo = cp[section_name]
        name = slinginfo.get('name', box_name).strip()
        my_num_streams = 0
        my_max_streams = int(slinginfo.get('maxstreams', '10'))
        print('Streamer: ', name, 'Waiting for first stream, flushing any IR requests that arrive while not connected to slingbox')
        stati[box_name] = 'Waiting for first client. Slingbox at ' + str(sling_net_address)
        while True:
            cmd, value = parse_cmd(streamer_q.get())
            if cmd == 'STREAM': break
            
        client_addr, channel = parse_stream(value)
        client_socket = (streamer_q.get()) ## Get the socket to stream on    
        if not start_streaming_connection(client_addr): 
            client_socket = closeconn(client_socket)
            continue 
            
        my_num_streams = 1
            
        cp.read(config_fn)
        slinginfo = cp[section_name]
        sbtype = slinginfo.get('sbtype', "350/500").strip()
        Solo = 'Solo' in sbtype or 'Pro' in sbtype
        SB240 = '240' in sbtype
        password = slinginfo['password'].strip()
        name = slinginfo.get('name', box_name).strip()
        resolution = int(slinginfo.get('Resolution', 12 ))
        if resolution < 0 or resolution > 16 : 
            print(name, 'Invalid Resolution', resolution, 'Defaulting to 640x480')
            resolution = 5;
        FrameRate = int(slinginfo.get('FrameRate', 30 ))
        VideoBandwidth = int(slinginfo.get('VideoBandwidth', 2000 ))
        VideoSmoothness = int(slinginfo.get('VideoSmoothness', 63 ))
        IframeRate = int(slinginfo.get('IframeRate', 5 ))
        AudioBitRate = int(slinginfo.get('AudioBitRate', 64 ))
        VideoSource = slinginfo.get('VideoSource', '' )
        if channel == '0': StartChannel = slinginfo.get('StartChannel', '' )
        else: StartChannel = channel
        RemoteLock = slinginfo.get('RemoteLock', '')
        if box_name in remotes.keys():
            rccode = remotes[box_name][2]
        pksize = 3072
        if Solo : pksize = 3000
        print( '\r\nSlinginfo ', sbtype, resolution, FrameRate, slingip, slingport, pksize, my_max_streams )

        print(name, 'Starting Stream for ', client_addr)
        stream_clients[client_socket] = client_addr  
        primary_stream_client = client_addr.split(':')[0]       
        streams.append(client_socket)
        try: 
            client_socket.sendall(OK)
            s_ctl, stream  = start_slingbox_session(streams)

        except Exception as e:
            print(name, 'Badness starting slingbox session ', e, traceback.print_exc())
            continue
        if s_ctl and stream :
            pc = 0
            stream.settimeout(15)
            tick = lasttick = laststatus = lastkeepalive = last_remote_command_time = startchanneltime = time.time()
            if not Solo : StartChannel = send_start_channel(StartChannel, rccode)
            while streams:
                msg = readnbytes(stream, pksize)
                if Solo and len(msg) > 0: 
                    try:
                        msg = process_solo_msg( msg, stream )
                    except Exception as e:
                        print(name, 'Error Processing Solo Message. Stopping', e, traceback.print_exc())
                        break
                    if len(msg) < 10:
                        if len(msg) == 0 :
                            print(ts(), name, 'Bad or Corrupted Solo message')
                        # Restart    
                        break
                
                if len(msg) == 0 :
                    print(ts(), name, 'Stream Stopped Unexpectly. Kicked Off?')
                    break
                    
                pc += 1
                for stream_socket in streams:                    
                    try:
                        sent = stream_socket.send(msg)
                    except Exception as e:
                        if stream_socket in stream_clients.keys():
                            print(ts(), name, 'Stream Terminated for ', stream_clients[stream_socket])
                            close_streaming_connection(stream_socket)
                        else:
                            print(ts(), name, 'Stream Terminated', e, traceback.print_exc())
                            streams.remove(stream_socket)

                        my_num_streams = my_num_streams - 1
                        continue
                msg = b''
                
                if (not streamer_q.empty()):
                    cmd, data = parse_cmd(streamer_q.get())
                    print( name, 'Got Streamer Control Message', cmd )
                    if cmd == 'STREAM' :
                        new_stream = streamer_q.get()
                        #print(new_stream)
                        if my_num_streams == my_max_streams :
                            print( name, 'Max streams', my_max_streams, 'for this slingbox has been reached. Not starting connection')
                            new_stream.sendall(ERROR)
                            new_stream = closeconn(new_stream)
                        elif not start_streaming_connection(data) :
                            print(name, 'Video Stream Startup Error')
                            new_stream.sendall(ERROR)
                            new_steam = closeconn(new_stream)
                        else:
                            my_num_streams = my_num_streams + 1
                            new_stream.sendall(OK)
                            stream_clients[new_stream], channel = parse_stream(data)
                            new_stream.sendall(stream_header)
                            print( name, 'New Stream Starting', channel)
                            if channel != '0':
                                if not RemoteLock : StartChannel = channel
                                else: print( name, 'RemoteLocked, ignoring channel request')
                            streams.append(new_stream) 
                            #Thread(target=start_new_stream, args=(new_stream,)).start()
                    elif cmd == 'ProHD':
                        channel, sender_ip = data.split(':')
                        print(ts(), name, 'got ProHD', channel, sender_ip)
                        stream_ip = primary_stream_client
                        if not RemoteLocked(sender_ip):
                            SendKeycode( channel, rccode)                              
                    elif cmd == 'IR':
                        print('IR', data)
                        for key in data:
                            sender_ip = key[1:].decode('utf-8')
                            stream_ip = primary_stream_client                            
                            if not RemoteLocked( sender_ip ):
                                print(ts(), name,'Sending IR keycode', key[0], rccode, 'for', sender_ip)
                                SendKeycode(str(key[0]), rccode )

                curtime = time.time()
                if curtime - tick > 0.5: # Only check stuff every 
                    tick = curtime
                    
                    if curtime - lasttick > 10.0:
                        print('.', end='')
 #                       print( stati, box_name )
                        stati[box_name] = name + ' Slingbox Streaming %d clients. Resolution=%d Packets=%d' % (len(streams), resolution, pc)
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
                          
                    if StartChannel : 
                        if curtime - startchanneltime > 10.0 :
                            StartChannel = send_start_channel(StartChannel, rccode)
                    

            ### No More Streams OR input stream stopped
            print(name, 'Shutting down connections')
            s_ctl = closecontrol(s_ctl)
            for s in streams : close_streaming_connection(s)
            streams = []
            stream_clients = {}
            my_num_streams = 0
        else:
            print(name,'ERROR: Slingbox session startup failed.')
            if s_ctl : s_ctl = closecontrol(s_ctl)
            if stream : 
                stream = close_streaming_connection(stream, stream_clients[stream])
                client_socket.sendall(ERROR)
            client_socket = closeconn(client_socket)
            my_num_streams = 0
            
    print(name, 'Streamer Exiting.. should never get here')
    s_ctl = closecontrol(s_ctl)
    stream = close_streaming_connection(stream)
    client_socket = closeconn(client_socket)

def remote_control_stream( connection, client, request, server_port):
    def fix_host(request):
        start_host = request.find('Host:')
        start_port = request.find(':', start_host + 5 )+1
        end_port = request.find('\r\n', start_host)
#        print('Fixing', start_port, end_port, request[0:start_port] + str(server_port) + request[end_port:])
        return bytes(request[0:start_port] + str(server_port) + '\r\nFrom:%s'%client[0] + request[end_port:], 'utf-8')
     
    http_port = server_port + 1
    print('\r\nStarting remote control stream handler for ', str(client), 'to port', http_port)
    remote_control_socket =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_control_socket.connect(('127.0.0.1', http_port ))  ## Send Packets to Flask
    print('Remote Control Connected')
#    print('GOT', request )
    request = fix_host(request)
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


########################################################################
def ConnectionManager(config_fn):
    global streamer_qs

    cp = ConfigParser()
    cp.read(config_fn)
    serverinfo = cp['SERVER']
    local_port = int(serverinfo.get('port', '8080'))
    maxstreams = serverinfo.get('maxremotestreams', '10')
    maxstreams = int(serverinfo.get('maxstreams', maxstreams))
    remoteenabled = serverinfo.get('enableremote', 'yes') == 'yes'
    URLbase = serverinfo.get('URLbase', 'slingbox')
    for c in " !*'();:@&=+$,/?%#[]" : 
        URLbase = URLbase.replace(c, '')
    print('Connection Manager Running on port %d with %d max streams using URL %s.' % (local_port,maxstreams, URLbase))

    server_address = ('', local_port)
    
    if cp.has_section('SLINGBOXES'):
        boxes = cp.items('SLINGBOXES')
        print('BOXES', boxes)
        for _, box in boxes:
            if cp.has_section(box):
                streamer_qs[box] = queue.Queue()
                Thread(target=streamer, args=(maxstreams, config_fn, box, box, streamer_qs[box], local_port)).start()
            else:
                print('Missing [%s] section in config file' % box)
                continue
    else:   
        box = str(local_port)
        streamer_qs[box] = queue.Queue()
        Thread(target=streamer, args=(maxstreams, config_fn, 'SLINGBOX', box, streamer_qs[box], local_port)).start()

    # Create a TCP/IP socket
    max_send_tcp_size = find_max_buffer_size( socket.SO_SNDBUF )
    ConnectionManagerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ConnectionManagerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('starting up on %s port %s' % server_address, max_send_tcp_size )
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
            try:
                data = connection.recv(1024).decode("utf-8")
            except:
 #               print('bad data')
                data = 'Bad Request'
            if URLbase in data and 'GET' in data:
                print(ts(), ' Streaming request from', str(client_address))
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, max_send_tcp_size )
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                connection.setblocking(False)
   
                result = re.search('(\/([-\w]+)(?:\/([-\w]+)?)?\??(?:channel=([0-9,+,.]+))?).*', data)
                if result:
 #                   print("URL options", result.groups())
                    channel = result.group(4)
                    if result.group(3):
                        # matched pattern for multiple boxes
                        streamer_name = result.group(3)
                    else:
                        streamer_name = str(local_port)
                else:
                    print('Failed to parse streaming request', data )
                    connection = closeconn(connection)
                    continue
                        
                if channel is None: channel = '0'

 #               print('Streamer Name', streamer_name, channel)
                if streamer_name in streamer_qs.keys():
                    streamer_q = streamer_qs[streamer_name]
                    streamer_q.put( bytearray(1) + bytes('STREAM=%s:%d:%s' % (client_address[0],client_address[1], channel), 'utf-8'))
                    streamer_q.put(connection)
                else:
                    print("Error: Can't find streamer for", streamer_name, 'in', streamer_qs.keys())
                    connection = closeconn(connection)
                    continue

            elif ( 'remote' in data.lower() and ('GET' in data or 'POST' in data) and remoteenabled ) or ('.php' in data):
                print(ts(), ' RemoteControl connection from', str(client_address))
                Thread(target=remote_control_stream, args=(connection, client_address, data, local_port)).start()
            elif not 'PINGER' in data:
                print('Hacker Alert. Invalid Request from ', client_address )
                if 'GET' in data : print(data)
                connection = closeconn(connection)
                continue
            else:
                # Ping
                connection = closeconn(connection)
                continue
                
        except Exception as e:
            print( 'Program Bug? Please report. ', client_address, data, e, traceback.print_exc())
            connection = closeconn(connection)
            continue

def killmyself():
    if 'windows' in platform.platform().lower():
        os.system('taskkill /f /pid %d /t' % mypid)
    else:
        os.system('kill -9 %d' % mypid)

def parse_buttons(buttons, lineno):
    lines = buttons.split('\n')
#        print('LINES=', lines)
    cmds = []
    for line in lines:
        try:
            lineno += 1
            if line.strip().startswith(';'): continue
#            print('Line=', line)
            name, value = line.split(':', 1)
#               print( name, value)
            name = name.replace("'", '').strip()
            cmds.append((name, value.strip()))
        except:
            print('ERROR parsing buttons in remote control file.\r\n Line number %d Contents %s' % (lineno, line))
#       print(cmds)
    return cmds
    
def parse_html(page):
    cmds = []
 #   re.search(r'pattern1(.*?)pattern2', page)
    result = re.findall('<button(.*?)/button>', page)
    for r in result:
#        print(r)
        start = r.find('name="') + 6
        if start > 6 :
            end = r.find('"', start)
            name = r[start:end]
        else: continue
        start = r.find('value="') + 7
        if start > 7:
            end = r.find('"', start)
            value = r[start:end]  
        else: continue
 #       print(name, value)
        cmds.append((name,value))
    return cmds

def BuildPage(cp, section_name):
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
     <form method="post" action="/Remote%s">
        %s
     </form>
     <h3>Status:%s</h3>
</body>
</html>
'''
    default_style='''style=
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

    default_buttons='''buttons='1' : 9 : round
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
        'Restart': Restart
        :<br><br>
        'Channel': Channel
        :&nbsp;&nbsp;'''

    data = default_style + default_buttons
#    print(section_name)
    remoteinfo = cp[section_name]
    rccode = remoteinfo.get('code', '')
#    print('rccode1', rccode)
    if not rccode: 
        remoteinfo.get('RemoteCode', '')
#        print('rccode2', rccode)
    if not rccode :
        if section_name == 'REMOTE' :
            rccode = cp['SLINGBOX'].get('RemoteCode', '')
            if not rccode : rccode = cp['SLINGBOX'].get('VideoSource', '')
        else:
            rccode = remoteinfo.get('RemoteCode', '')
            if not rccode: rccode = remoteinfo.get('VideoSource', '')
 #   print('rccode3', rccode)        
    if not rccode:
        print('WARNING: Remote Control Code not set. Set RemoteCode or VideoSource\r\nDefaulting to 0 which is probably wrong')
        rccode = '0'
    rccode = int(rccode)   
          
    if cp.has_option(section_name, 'Remote'):
        fn= remoteinfo.get('Remote', '')
    else:
        fn = remoteinfo.get('include', '')

    if fn:  # Get form data myself
        print('Reading Custom Remote definition from', fn)
        try:
            f = open(fn)
            data = f.read()
            f.close()
#            print('STYLE', style,'BUTTONS', buttons)
        except:
            print('Error reading remote definition file, using defaults')

    if fn.lower().endswith('.html') :
        page = data
        cmds = parse_html(page)
    else:
        start_style = data.find('style=')
        start_buttons = data.find('buttons=')
        style=data[start_style+6:start_buttons].strip()
        buttons = data[start_buttons+8:].strip()
        style = style.replace('%', '%%')
        linecount = data[0:start_buttons].count('\n')
        cmds = parse_buttons(buttons, linecount)
 #       print(cmds)
        formstr = ''
        for key, data in cmds:
            if key == '':
                formstr = formstr + data
            else:
    #            print('BUTTON', data)
                try: btn_class = data.split(':')[1].strip()
                except: btn_class = 'button'
 #               <button class=round type="submit" name="1" value="9 : round"
                formstr = formstr + '<button class=%s type="submit" name="%s" value="%s">%s</button>' % (btn_class, key, str(data).split(':')[0].strip(), key)
                if 'Channel' == data:
                    formstr = formstr + '<input class=text type="text" name="Digits" maxlength="4" size="4" id="" value=""></input>'
        if section_name == 'REMOTE':
            uri = ''
        else: 
            uri = '/' + section_name
        page = BasePage % ( style, uri, formstr, '%s' )
 #       print('PAGE', page)
    return page, cmds, rccode
 
def get_streamer( request, text ):
    global streamer_qs
    try: streamer = text.split('/')[1]
    except : streamer = request.host.split(':')[1]
 #   print('URI', text, 'Streamer', streamer)
    if streamer in streamer_qs.keys():
        return (streamer, request.headers['From'])
    else: 
        print('Error: Remote URL needs to be one of:')
        for streamer in streamer_qs.keys():
            print( '/Remote/%s' % streamer )
        return (None, None)
 
###############################################################################
###########   START OF EXECUTION #####################################
mypid = os.getpid()
print( 'Version :', version, 'Running on', platform.platform(), 'pid=', mypid, sys.argv[0])

streamer_qs = {}
stati = {}
remotes = {}
finderids = {}
tcode = 0
num_streams = 0
if len(sys.argv) == 1 : sys.argv.append('config.ini')
for config_fn in sys.argv[1:] :
    if os.path.exists( config_fn ):
        print( 'Using config file', config_fn )
    else:
        print( "Can't find specified config file", config_fn, 'Ignoring' )
        continue

    Thread(target=ConnectionManager, args=(config_fn,)).start()

    cp = ConfigParser()
    cp.read(config_fn)
    serverinfo = cp['SERVER']
    port = int(serverinfo.get('port', '8080'))
    
    http_port = port + 1
    cmds = None
    if serverinfo.get('enableremote', 'yes') == 'yes' :
        from flask import Flask, render_template, request, render_template_string, abort, send_file
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        
        if cp.has_section('SLINGBOXES'):
            boxes = cp.items('SLINGBOXES')
            for _, box in boxes:
                if cp.has_section(box):
                    stati[box] = 'Waiting for first update...'
                    print('Building page for', box)
                    remotes[box] = BuildPage(cp, box)
        else:
            stati[str(port)] = 'Waiting for first update...'
            remotes[str(port)] = BuildPage(cp, 'REMOTE')
            
        app = Flask(__name__)

        @app.route('/<path:text>', methods=["GET"])
        def index(text):
            print('GET', text)
            if text[1:].startswith('emote'):
                streamer, client = get_streamer( request, text )
                if streamer :
                    page = remotes[streamer][0]
                    if '<h3>Status:%s</h3>' in page:
                        return render_template_string( page % stati[streamer])
                    else:
                        return render_template_string( page )
                else:
                    abort(404)
            else:
                text = os.getcwd() + '/' + text
                if text.endswith('.php') :
                    if os.path.exists(text):
                        print('Running PHP script', text)
                        out = subprocess.run(["php", text], stdout=subprocess.PIPE)
      #                  print(out.stdout)
                        return out.stdout
                else:
 #                   print(text)
                    if os.path.exists(text):
                        mime = mimetypes.guess_type(text)[0]
                        print('Returning', text, mime)
                        return send_file(text, mime)
                    else: abort(404)

        @app.route('/<path:text>', methods=["POST"])
        def button(text):
            global streamer_qs, tcode, stati
            
            def send_pro_control(keyid):
                msg = bytearray(1) + bytes('ProHD=%s:%s' % (keyid,client), 'utf-8')
                print('ProHD', keyid)
                streamer_q.put(msg)
            
            def SendChannelDigits(channel):
                print('Sending Channel Digits', channel)
                if '.' in channel: # ProHD
                    if channel.endswith('.') : channel = channel + '0'
                    send_pro_control('2.' + channel)
                else:
                    keylist = []
                    for digit in channel:
                        if digit in '0123456789' :
                            keylist.append(
                       digits2buttons[int(digit)].to_bytes(1, byteorder='little')+ bytes(client, 'utf-8'))
                    streamer_q.put(keylist)


            streamer, client = get_streamer( request, text )
#            print('URI', text, 'Streamer', streamer)
            if not streamer : abort(404)
            streamer_q = streamer_qs[streamer]
            Page, cmds, rccode = remotes[streamer]          
            digits2buttons = [18,9,10,11,12,13,14,15,16,17]
 #           print('Button Clicked', request.form, client, cmds)
            for x in request.form.items() : print('Key Data', x)
            if request.form.get('Digits'):
                channel = request.form.get('Digits').strip()
                if channel[0] == '?' :
                    print('Sending test keycode', channel[1:] )
                    if '.' in channel:  # ProHD
                        send_pro_control(channel[1:] + '.0')
                    else:
                        kc = int(channel[1:])
                        streamer_q.put([kc.to_bytes(1, byteorder='little')])
                else: SendChannelDigits(channel)
            else:
 #               print('POST', request.form)
                for keyname, keycode in request.form.items():
  #                  print('key data', keyname, keycode)                   
                    if keyname == 'Digits': continue
                    else:
                        if keyname == 'RCtest':
                            stati[streamer] = 'Remote Code testing is depreicated. Please use VideoSource'
                        elif keyname == 'Restart' :
                            print('Restarting, killing myself')
                            killmyself()
                        elif keyname == 'Channel' : pass # Channel request with no digits
                        else:
                            data = keycode.split(':')[0].strip()
                            print( 'Remote', keyname, data )
                            if data.startswith('?') : 
                                SendChannelDigits(data[1:])
                            elif '.' in data:
                                send_pro_control(data + '.0')
                            else:
                                keycodes = []
                                for keycode in data.split(','):
                                    keycodes.append(
                                    int(keycode).to_bytes(1, byteorder='little') + bytes(client, 'utf-8'))
                                streamer_q.put(keycodes)
                             
            if '<h3>Status:%s</h3>' in Page:
                return render_template_string(Page%stati[streamer])
            else:                   
                return render_template_string(Page)

        Thread(target=lambda: app.run(host='127.0.0.1', port=http_port, debug=False, use_reloader=False)).start()
        time.sleep(1) # give Flask sometime to start up makes logs easier to read

if len(finderids) : Thread(target=register_slingboxes).start()
while True: time.sleep(1)
