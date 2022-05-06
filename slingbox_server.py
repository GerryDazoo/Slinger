import os
import sys
import subprocess
import socket
import shlex
import sys
import time
import select
import binascii
import queue
from threading import Thread
import platform
import datetime
import traceback
import tea
from struct import pack, unpack
from configparser import ConfigParser

def ts():
    return '%s ' % datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    
def find_slingbox_info(): 
    import netifaces
    def ip4_addresses():
        ips = []
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addresses = netifaces.ifaddresses(interface)
            family_addresses = addresses.get(netifaces.AF_INET)
            if not family_addresses:
                continue
            for address in family_addresses:
                ip = address['addr']
                if ip.startswith('169.254.') or ip == "127.0.0.1" : continue
                ips.append(address['addr'])
        return ips
        

    port = None
    data =  [0x01, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
              

    ip = ''
    for local_ip in ip4_addresses():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            print('\nFinding Slingbox on local network. My IP Info = ', local_ip) 
            s.bind((local_ip, 0))
            for i in range(1,4):
                try: 
                    s.sendto( bytearray(data), ('255.255.255.255', 5004 ))
                    msg, source = s.recvfrom(32768)
                #    print('Got', str(msg), source)
                    if len( msg ) == 124 :
                      #  print('good len')
                        if b'S\x00l\x00i\x00n\x00g\x00b\x00o\x00x' in msg:
                            print('Slingbox Found')
                            ip = source[0]
                            break                       
                except socket.timeout:
                    print('.', end='')
            else:
                continue
        break
        s.close()
            
    if ip :
        port = 0
        print('Scanning for open control port')
        for p in range(5201, 5220):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    print('Checking port ', ip, p)
                    result = s.connect_ex((ip,p))
                    if result ==0:
                        print("Port {} is open".format(p))
                        port = p
                        break
                except: 
                    print('EX')
                    continue

    s.close()
    return (ip, port)
    
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
    s_ctl = None
    stream = None
    dbuf = None 
    skey = None
    stat = 0 
    streams = []
    stream_header = None
   
    def pbuf(s):
        s = str(binascii.hexlify(s)).upper()
        return '.'.join(s[i:i+2] for i in range(2, len(s)-1, 2))
        
    def dynk(sid):
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
 #       print( 'Sending to Slingbox ', hex(opcode), hex(parity), hex(len(data)))
        seq += 1
        try:
            cmd = pack("<HHHHH 6x HH 4x H 6x", msg_type, sid, opcode, 0, seq, len(data), smode, parity) + tea.Crypt(data, skey)
            s_ctl.sendall( cmd )
        except:
            print('EXCEPTION', hex(msg_type), sid, hex(opcode), 0, seq, len(data), hex(smode), hex(parity))
            exit(1)
        
        if opcode == 0x66 : return
        
        response = s_ctl.recv(32)
        sid, stat, dlen = unpack("2x H 8x H 2x H", response[0:18] ) # "x2 v x8 v x2 v", $hbuf);
#        print( 'Sent to Slingbox ', hex(opcode), hex(parity), hex(len(data)))
#        print( 'Received from Slingbox', sid, hex(stat), dlen )
        if stat & stat != 0x0d & stat != 0x13 :
            print( "cmd:", hex(opcode), "err:",  hex(stat), dlen )
        if dlen > 0 :
            in_buf = s_ctl.recv( 512 ) 
            dbuf = tea.Decrypt(in_buf, skey)
                      
    def sling_open(connection_type):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('Connecting...', sling_net_address, connection_type )
        s.connect(sling_net_address)
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
                         0x05000000 + (FrameRate << 16) + VideoBandwidth,
                          0x10001 + (VideoSmoothness << 8), #Video Smoothness
                         3, #fixed
                         1, #fixed
                         AudioBitRate,
                         3,                         
#                        0x4f, 
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
        s_ctl = sling_open('Control') # open control connection to SB
        sling_cmd(0x67, pack('I 32s 32s 132x', 0, futf16('admin'), futf16(password))) # log in to SB
        rand = bytearray.fromhex('feedfacedeadbeef1111222233334444') # 'random' challenge
        sling_cmd(0xc6, pack('I 16s 36x', 1, rand)) # setup dynamic key on SB
        skey = dynk(sid)
#        print('New Key ', skey)
        smode = 0x8000                # use dynamic key from now on
        sling_cmd(0x7e, pack("I I", 1, 0)) # stream control
        while stat:
            print('Box in use!' )
            status = 'Slingbox in Use! Cannot start session, retrying in 10 seconds..'
            time.sleep(10)
            sling_cmd(0x7e, pack("I I", 1, 0)) # stream control
        
        sling_cmd(0xa6, pack("10h 76x", 0x1cf, 0, 0x40, 0x10, 0x5000, 0x180, 1, 0x1e,  0, 0x3d))
        SetVideoParameters(resolution, FrameRate, VideoBandwidth, VideoSmoothness, IframeRate, AudioBitRate )
        stream = sling_open('Stream')  
        first_buffer = stream.recv(3072) 
        h264_header = b'\x36\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c' 
        h264_header_pos = first_buffer.find( h264_header ) + 50
 #       print( 'mp4_header_pos', mp4_header_pos, len( first_buffer ))
        stream_header = first_buffer[0:h264_header_pos]
        print('Stream started at', ts(), len(stream_header))
        for s in streams :
            s.sendall(stream_header)
            # Send any left over bits
            s.sendall(first_buffer[h264_header_pos:])
        return s_ctl, stream

    def parse_cmd(msg):
        if msg[0] == 0x00 :
            return msg[1:].decode('utf-8').split('=')
        else:
            return 'IR', msg
            
    ################## START of Streamer Execution        
    print('Streamer Running: ')
    OK = b'HTTP/1.0 200 OK\r\nContent-type: application/octet-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n'
    ERROR =b'HTTP/1.0 503 ERROR\r\nContent-type: application/octet-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n'
    
    cp = ConfigParser()
    cp.read('config.ini')
    slinginfo = cp['SLINGBOX']
    password = slinginfo['password']
    cp = ConfigParser()
    cp.read('config.ini')
    slinginfo = cp['SLINGBOX']
    password = slinginfo['password'].strip()
    resolution = int(slinginfo.get('Resolution', 12 ))
    FrameRate = int(slinginfo.get('FrameRate', 30 ))
    VideoBandwidth = int(slinginfo.get('VideoBandwidth', 8000 ))
    VideoSmoothness = int(slinginfo.get('VideoSmoothness', 63 ))
    IframeRate = int(slinginfo.get('IframeRate', 5 ))
    AudioBitRate = int(slinginfo.get('AudioBitRate', 64 ))
    slingip =  slinginfo.get('ipaddress', '' )
    slingport = int(slinginfo.get('port', 5201))

    if not slingip :
        sling_net_address = find_slingbox_info()
    else:
        sling_net_address = (slingip, slingport )
        
    print( 'Slinginfo', password, resolution, FrameRate, slingip, slingport )
    
    streamer_q = queue.Queue()
    stream_clients = {}

    while True:        
        stream_header = None
        streams = []
        # Wait for first stream request to arrive 
        print('Streamer: Waiting for first stream, flushing any IR requests that arrive while not connected to slingbox')
        while True:
            cmd, value = parse_cmd(streamer_q.get())
            if cmd == 'STREAM': break
            if cmd == 'RESOLUTION' :
                print('Changing Resolution', value)
                resolution= int(value)
                
        client_addr = str(value) 
        print('Starting Stream for ', client_addr) 
         
        client_socket = (streamer_q.get()) ## Get the socket to stream o
 #       client_socket.setblocking(0)
        stream_clients[client_socket] = client_addr
        streams.append(client_socket)
        client_socket.sendall(OK)
        s_ctl, stream = start_slingbox_session(streams)
        pc = 0
        lasttick = laststatus = lastkeepalive = last_remote_command_time = time.time()
        while streams:
            sling_ready, _ , _ = select.select([stream], [], [], 4.0 )
            if sling_ready:
                msg = stream.recv(3072)
                if len(msg) == 0 :
                    print('SlingBox Closed Streaming socket. Shutting down.')
                    break
                pc += 1
                for stream_socket in streams: 
                    try:
                        _ , client_ready , _ = select.select([], [stream_socket], [], 0.2 )
                        if client_ready : 
                            stream_socket.sendall(msg)
                        else:
                            print('Client Not ready', stream_clients[stream_socket], 'Shutting Down')
                            del stream_clients[stream_socket]
                            streams.remove(stream_socket)
                            closeconn(stream_socket)
                        
                    except Exception as e:
                        print('Stream Terminated for ', stream_clients[stream_socket])
                        del stream_clients[stream_socket]
                        streams.remove(stream_socket)
                        closeconn(stream_socket)
                        continue
                
                curtime = time.time()                
                if curtime - lasttick > 10.0 : 
                    print('.', end='')      
                    status = 'Slingbox Streaming %d clients. Resolution=%d Packets=%d' % (len(streams), resolution, pc)
                    lasttick = curtime
                    
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
 #                       new_stream.setblocking(0)
                        if len(streams) == maxstreams :
                            new_stream.sendall(ERROR)
                            closeconn(new_stream)
                        else:
                            new_stream.sendall(OK)
                            stream_clients[new_stream] = data
                            streams.append(new_stream)
                            new_stream.sendall(stream_header)
                            print('New Stream Started, num clients = ', len(streams))
                    elif cmd == 'IR':
                        sling_cmd(0x87, data + pack('464x 4h', 3, 0, 0, 0), msg_type=0x0201)
                        last_remote_command_time = time.time()
            else:
                print(ts(), 'Stream Stopped Unexpectly, possible slingbox video format change')
                stream = closeconn(stream)
                s_ctl = closeconn(s_ctl)
                s_ctl, stream = start_slingbox_session(streams)
        stream = closeconn(stream)
        s_ctl = closeconn(s_ctl)

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
        print(ts(), 'waiting for a connection')
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
                print('No Get Request in time, hacker?')
                connection = closeconn(connection)
                continue
            
            data = connection.recv(1024).decode("utf-8")            
            if 'slingbox' in data :
                if streamer_q : # Streamer Thread ready to accept connections
                    streamer_q.put( bytearray(1) + bytes('STREAM=%s:%d' % client_address, 'utf-8'))
                    streamer_q.put(connection)
                else:
                    connetion = closeconn(connection)
            elif 'Remote' in data and remoteenabled :
                Thread(target=remote_control_stream, args=(connection, client_address, data )).start()
            else:
                if remoteenabled : 
                    print('Hacker Alert. Invalid Request from ', client_address )
                else:
                    print('Got Remote connection request but Remote no enabled')
                connection = closeconn(connection)
                continue
        except Exception as e:
            print( 'Hacker Alert. Bad Data from ', client_address )
            connection = closeconn(connection)
            continue

def killmyself():
    mypid = os.getpid()
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
    
###############################################################################
###########   START OF EXECUTION ##################################### 
print( 'Running on', platform.platform())

streamer_q = None
status = 'Testing'

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
                    else:
                        streamer_q.put(int(data).to_bytes(1, byteorder='little') +
                                      b'\x00\x00\x00\x00\x00\x00\x00')
        return render_template_string(Page%status)

    app.run(host='0.0.0.0', port=9998, debug=False)

