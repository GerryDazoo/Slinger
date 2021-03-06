import os
import sys
import socket
import sys
import time
import select
import binascii
import queue
from threading import Thread
import platform
import datetime
import traceback
import requests
from struct import pack, unpack, calcsize
from configparser import ConfigParser
from ctypes import *

version='2.02'

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

def streamer(maxstreams):
    global streamer_q, status
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

    def dynk(sid, challange):
        try:
            f = open('keys.dat', 'rb')
        except:
            print('Fetching new encryption keys from web')
            url = 'http://www.dazoo.net:65432/cgi-bin/Sling/genkeys/?challange=%s' % challange
            r = requests.get(url, allow_redirects=False)
            open('keys.dat', 'wb').write(r.content)
            
        with open('keys.dat', 'rb') as f:
            f.seek( sid * 16 )
            data = f.read(16)
            return list(unpack('IIII', data))

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
 #       if opcode == 0xb5 : print( 'Sending to Slingbox ', hex(opcode), hex(parity), '\r\n', pbuf(data))
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
 #       print( 'Received from Slingbox', sid, hex(stat), dlen )
        if stat & stat != 0x0d & stat != 0x13 :
            print( "cmd:", hex(opcode), "err:",  hex(stat), dlen )
        if dlen > 0 :
            in_buf = s_ctl.recv( 512 )
            dbuf = Decrypt(in_buf, skey)

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
        global status
        skey = [0xBCDEAAAA,0x87FBBBBA,0x7CCCCFFA,0xDDDDAABC]
 #       print('skey', skey )
        smode = 0x2000               # basic cipher mode,
        sid = seq = 0                # no session ID, seq 0
 #       print('Opening Control stream', hex(smode), sid, seq)
        s_ctl = sling_open(sling_net_address, 'Control') # open control connection to SB
        sling_cmd(0x67, pack('I 32s 32s 132x', 0, futf16('admin'), futf16(password))) # log in to SB
        rand = bytearray.fromhex('feedfacedeadbeef1111222233334444') # 'random' challenge
        try:
            sling_cmd(0xc6, pack('I 16s 36x', 1, rand)) # setup dynamic key on SB
        except:
            print('Error Starting Session. Check your admin password in config.ini file!')
            return None, None
        c = binascii.hexlify(dbuf[0:16])
        c = c.decode('utf-8')
        print('CHALLANGE', c)            
        skey = dynk(sid, c)
#        print('New Key ', skey)
        smode = 0x8000                # use dynamic key from now on
        sling_cmd(0x7e, pack("I I", 1, 0)) # stream control
        while stat:
            print('Box in use! Kicking off other user.' )
            status = 'Slingbox in Use! Cannot start session, kicking off other user..'
            sling_cmd(0x93, pack('32s 32s 8x', futf16('admin'), futf16(password)))
            time.sleep(1)
            sling_cmd(0x6a, pack("I 172x", 1)); # unk fn
            sling_cmd(0x7e, pack("I I", 1, 0)) # stream control

        sling_cmd(0xa6, pack("10h 76x", 0x1cf, 0, 0x40, 0x10, 0x5000, 0x180, 1, 0x1e,  0, 0x3d))
        SetVideoParameters(resolution, FrameRate, VideoBandwidth, VideoSmoothness, IframeRate, AudioBitRate )
        stream = sling_open(sling_net_address, 'Stream')
        first_buffer = bytearray(stream.recv(pksize, socket.MSG_PEEK))
#        print( 'FIRST', type(first_buffer), pbuf(first_buffer))
        h264_header = b'\x36\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c'
        h264_header_pos = first_buffer.find( h264_header ) + 50
 #       print( 'h246_header_pos', h264_header_pos, len( first_buffer ))
        if 'Solo' in sbtype:
            tbd = 0
            audio_header = b'\x91\x07\xDC\xB7\xB7\xA9\xCF\x11\x8E\xE6\x00\xC0\x0C\x20\x53\x65\x72'
            audio_header_pos = first_buffer.find( audio_header ) + 0x60 # find audio hdr
            first_buffer[audio_header_pos:audio_header_pos+10] = pack("H 8x", 0x9012)
            
        stream_header = first_buffer[0:h264_header_pos]
        #print( 'SH', type(stream_header), pbuf(stream_header))
        
        print('Stream started at', ts(), len(stream_header), len(first_buffer[h264_header_pos:]))
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
    print('Streamer Running: ')
    OK = b'HTTP/1.0 200 OK\r\nContent-type: application/octet-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n'
    ERROR =b'HTTP/1.0 503 ERROR\r\nContent-type: application/octet-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n'
    streamer_q = queue.Queue()
    stream_clients = {}
    cp = ConfigParser()
    cp.read('config.ini')
    slinginfo = cp['SLINGBOX']
    slingip =  slinginfo.get('ipaddress', '' )
    slingport = int(slinginfo.get('port', 5201))
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
        status = "Can't find a slingbox on network. Please make sure it's plugged in and connected."
        status = status + ' Check config.ini'
        print(status)
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
        print('Streamer: Waiting for first stream, flushing any IR requests that arrive while not connected to slingbox')
        status = 'Waiting for first client. Slingbox at ' + str(sling_net_address)
        while True:
            cmd, value = parse_cmd(streamer_q.get())
            if cmd == 'STREAM': break
            if cmd == 'RESOLUTION' :
                print('Changing Resolution', value)
                resolution= int(value)
        cp = ConfigParser()
        cp.read('config.ini')
        slinginfo = cp['SLINGBOX']
        sbtype = slinginfo.get('sbtype', "350/500").strip()
        password = slinginfo['password'].strip()
        resolution = int(slinginfo.get('Resolution', 12 )) & 15
        if resolution == 0 : 
            print('Invalid Resolution', resolution, 'Defaulting to 640x480')
            resolution = 5;
        FrameRate = int(slinginfo.get('FrameRate', 30 ))
        VideoBandwidth = int(slinginfo.get('VideoBandwidth', 2000 ))
        VideoSmoothness = int(slinginfo.get('VideoSmoothness', 63 ))
        IframeRate = int(slinginfo.get('IframeRate', 5 ))
        AudioBitRate = int(slinginfo.get('AudioBitRate', 64 ))
        pksize = 3072
        if "Solo" in sbtype : pksize = 3000
        print( '\r\nSlinginfo ', sbtype, password, resolution, FrameRate, slingip, slingport, pksize )

        client_addr = str(value)
        print('Starting Stream for ', client_addr)
        client_socket = (streamer_q.get()) ## Get the socket to stream o
        stream_clients[client_socket] = client_addr
        streams.append(client_socket)
        client_socket.sendall(OK)
        try:          
            s_ctl, stream  = start_slingbox_session(streams)
        except Exception as e:
            print('Badness starting slingbox session ', e, traceback.print_exc())
            killmyself()
        if s_ctl and stream :
            pc = 0
            lasttick = laststatus = lastkeepalive = last_remote_command_time = time.time()
            while streams:
                msg = readnbytes(stream, pksize)
                if 'Solo' in sbtype and len(msg) > 0: 
                    msg = process_solo_msg( msg )
                    if len(msg) == 0 :
                        print(ts(), 'Bad or Corrupted Solo message')
                
                if len(msg) == 0 :
                    print(ts(), 'Stream Stopped Unexpectly, possible slingbox video format change')
                    stream = closeconn(stream)
                    s_ctl = closeconn(s_ctl)
                    break
                    
                pc += 1
                for stream_socket in streams:                    
                    try:
                        sent = stream_socket.send(msg)
                    except Exception as e:
                        print(ts(), 'Stream Terminated for ', stream_clients[stream_socket], e)
                        del stream_clients[stream_socket]
                        streams.remove(stream_socket)
                        closeconn(stream_socket)
                        continue
                msg = b''
                curtime = time.time()
                if curtime - lasttick > 10.0 :
                    print('.', end='')
                    status = 'Slingbox Streaming %d clients. Resolution=%d Packets=%d' % (len(streams), resolution, pc)
                    lasttick = curtime
                    sys.stdout.flush()

                if curtime - laststatus > 90.0 :
                    print( ts(),'%d Clients.' % len(streams), end='')
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
                    print( 'Got Streamer Control Message', cmd, data )
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
                        sling_cmd(0x87, data + pack('464x 4h', 3, 0, 0, 0), msg_type=0x0201)
                        last_remote_command_time = time.time()

            ### No More Streams OR input stream stopped
            print('Shutting down connections')
            s_ctl = closeconn(s_ctl)
            stream = closeconn(stream)
            for s in streams: closeconn(s)
        else:
            print('ERROR: Slingbox session startup failed.')
    print('Streamer Exiting.. should never get here')
    s_ctl = closeconn(s_ctl)
    stream = closeconn(stream)

def remote_control_stream( connection, client, request):
    print('\r\nStarting remote control stream hander for ', str(client))
    remote_control_socket =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_control_socket.connect(('127.0.0.1', 9998 ))  ## Send Packets to Flask
    print('Remote Control Connected')
    remote_control_socket.sendall( bytes(request, 'utf-8' ))
    sockets = [remote_control_socket, connection]
    while True:
 #       print('Waiting for data')
        read_sockets, _, _ = select.select(sockets, [], [])
        for sock in read_sockets:
            data = sock.recv(32768)
            if len(data) == 0 :
                break
            if sock == connection: remote_control_socket.sendall(data)
            if sock == remote_control_socket: connection.sendall(data)
        else:
            continue
        break
    connection = closeconn(connection)
    remote_control_socket = closeconn(remote_control_socket)
#    print('Exiting Remote Control Stream Handler for', client )


########################################################################
def ConnectionManager():
    global streamer_q

    cp = ConfigParser()
    cp.read('config.ini')
    serverinfo = cp['SERVER']
    port = int(serverinfo.get('port', 8080))
    maxstreams = int(serverinfo.get('maxstreams', 4))
    remoteenabled = serverinfo.get('enableremote', 'yes') == 'yes'
    print('Connection Manager Running %d max streams....' % maxstreams)

    server_address = ('', port)

    Thread(target=streamer, args=(maxstreams,)).start()

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
            print(ts(), ' connection from', str(client_address))

            ready_read, ready_write, exceptional = select.select([connection], [], [], 0.2)
            if not ready_read:
                print('No request in time, hacker?')
                connection = closeconn(connection)
                continue

            data = connection.recv(1024).decode("utf-8")
            if 'slingbox' in data and 'GET' in data:
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024*1024*8)
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                connection.setblocking(False)
                if streamer_q : # Streamer Thread ready to accept connections
                    streamer_q.put( bytearray(1) + bytes('STREAM=%s:%d' % client_address, 'utf-8'))
                    streamer_q.put(connection)
                else:
                    connetion = closeconn(connection)
            elif 'emote' in data and ('GET' in data or 'POST' in data) and remoteenabled :
                Thread(target=remote_control_stream, args=(connection, client_address, data )).start()
            else:
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
            name, value = line.split(':')
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
<body >
     <form method="post" action="/Remote">
        %s
     </form>
     <h3>Status:%s</h2>
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

    default_buttons=''''1' : 9
        :&nbsp;&nbsp;
        '2' : 10
         :&nbsp;&nbsp;
        '3' : 11
        :&nbsp;&nbsp;
        '4' : 12
         :&nbsp;&nbsp;
        '5' : 13
        :&nbsp;&nbsp;
        '6' : 14
         :&nbsp;&nbsp;
        '7' : 15
        :&nbsp;&nbsp;
        '8' : 16
        :&nbsp;&nbsp;
        '9' : 17
        :&nbsp;&nbsp;
        :&nbsp;&nbsp;
        '0' : 18
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
        'Channel': Channel'''

    remoteinfo = cp['REMOTE']
    style=remoteinfo.get('style', default_style )
    #    print('STYLE', style)
    buttons=remoteinfo.get('buttons', default_buttons)
    #    print('BUTTONS', buttons)
    cmds = parse_buttons(buttons)
    formstr = ''
    for key, data in cmds:
        if key == '':
            formstr = formstr + data
        else:
            formstr = formstr + '<button class=button type="submit" name="%s" value="%s">%s</button>' % (key,str(data), key)
            if 'Channel' == data:
                formstr = formstr + '<input class=text type="text" name="Digits" maxlength="4" size="4" id="" value=""></input>'
        page = BasePage % ( style, formstr, '%s' )
    return page, cmds

def dynk(sid):
    with open('keys.dat', 'rb') as f:
        f.seek( sid * 16 )
        data = f.read(16)
        return list(unpack('IIII', data))
###############################################################################
###########   START OF EXECUTION #####################################
print( 'Version :', version, 'Running on', platform.platform())
mypid = os.getpid()

streamer_q = None
status = 'Waiting for first update...'

Thread(target=ConnectionManager).start()

cp = ConfigParser()
cp.read('config.ini')
serverinfo = cp['SERVER']
cmds = None
if serverinfo.get('enableremote', 'yes') == 'yes' :
    from flask import Flask, render_template, request, render_template_string
    Page, cmds = BuildPage(cp)
    app = Flask(__name__)

    @app.route('/Remote', methods=["GET"])
    def index():
        return render_template_string(Page % status)

    @app.route('/Remote', methods=["POST"])
    def button():
        global streamer_q
        digits2buttons = [18,9,10,11,12,13,14,15,16,17]
        print('Button Clicked', request.form)
        if request.form.get('Digits'):
            channel = request.form.get('Digits').strip()
            print('Sending Channel Digits', channel)
            for digit in channel:
                streamer_q.put(digits2buttons[int(digit)].to_bytes(1, byteorder='little') +
                b'\x00\x00\x00\x00\x00\x00\x00')
        else:
            for tuple in cmds:
                cmd = tuple[0]
                data = request.form.get(cmd)
                if data != None:
                    if cmd == 'Restart' :
                        print('Restarting, killing myself')
                        killmyself()
                    elif 'x' in cmd and cmd != 'Exit':
 #                       print('Changing Resolution', data )
                        streamer_q.put( bytearray(1) + bytes('RESOLUTION=%s' % data, 'utf-8'))
                    elif cmd == 'Channel' : pass # Channel request with no digits
                    else:
                        streamer_q.put(int(data).to_bytes(1, byteorder='little') +
                                      b'\x00\x00\x00\x00\x00\x00\x00')
        return render_template_string(Page%status)

    app.run(host='0.0.0.0', port=9998, debug=False)

