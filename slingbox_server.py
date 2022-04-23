from flask import Flask, render_template, request, render_template_string
import os
import sys
import subprocess
import socket
import netifaces
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

def ts():
    return '%s ' % datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    
def find_slingbox_info(): 
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
        print('Closing Connection')
        s.shutdown(socket.SHUT_RDWR)
        s.close()
    return None

def streamer(sling_addr, password):
    global streams, stream_header, ir_q, Resolution
    smode = 0x2000               # basic cipher mode,
    sid = 0   
    seq = 0
    s_ctl = None
    dbuf = None 
    skey = None
    stat = 0 
    s_ctl = None
    stream = None
   
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
        print( 'Sent to Slingbox ', hex(opcode), hex(parity), hex(len(data)))
        print( 'Received from Slingbox', sid, hex(stat), dlen )
        if stat & stat != 0x0d & stat != 0x13 :
            print( "cmd:", hex(opcode), "err:",  hex(stat), dlen )
        if dlen > 0 :
            in_buf = s_ctl.recv( 512 ) 
            dbuf = tea.Decrypt(in_buf, skey)
                      
    def sling_open(connection_type):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('Connecting...', sling_addr, connection_type )
        s.connect(sling_addr)
        s.sendall(str.encode('GET /stream.asf HTTP/1.1\r\nAccept: */*\r\nPragma: Sling-Connection-Type=%s, Session-Id=%d\r\n\r\n' % (connection_type, sid)))
        return s
        
    def SetVideoParameters(Resolution, FrameRate, VideoBandwidth, VideoSmoothness, IframeRate ):
        if Resolution == 16 :
            VideoBandwidth = 8000
        else:
            VideoBandwidth = 4000
        VideoSmoothness = 63
        rand = bytearray.fromhex('feedfacedeadbeef1111222233334444') # 'random' challenge
        print('VideoParameters: Resolution=',Resolution, 'FrameRate=', FrameRate, 
              'VideoBandwidth=', VideoBandwidth, 'VideoSmoothness=', VideoSmoothness, 
              'IframeRate=', IframeRate) 
        sling_cmd(0xb5, pack("11I 16s 2I 92x", 
                         0xff, 
                         0xff, 
                         Resolution, # Screen Size
                         1,
                         0x05000000 + (FrameRate << 16) + VideoBandwidth,
                          0x10001 + (VideoSmoothness << 8), #Video Smoothness
                         3, #fixed
                         1, #fixed
                         0x40, #Audio Bitrate
                         0x4f, 
                         1, 
                         rand, 
                         0x1012020, 
                         1)); # set stream params
                         

    def start_slingbox_session():
        global stream_header
        nonlocal sid, seq, s_ctl, dbuf, skey, stat, smode
        skey = [0xBCDEAAAA,0x87FBBBBA,0x7CCCCFFA,0xDDDDAABC]
 #       print('skey', skey )
        smode = 0x2000               # basic cipher mode,
        sid = seq = 0                # no session ID, seq 0
        print('Opening Control stream', smode, sid, seq)
        s_ctl = sling_open('Control') # open control connection to SB
        sling_cmd(0x67, pack('I 32s 32s 132x', 0, futf16('admin'), futf16(password))) # log in to SB
        rand = bytearray.fromhex('feedfacedeadbeef1111222233334444') # 'random' challenge
        sling_cmd(0xc6, pack('I 16s 36x', 1, rand)) # setup dynamic key on SB
        skey = dynk(sid)
#        print('New Key ', skey)
        smode = 0x8000                # use dynamic key from now on
        sling_cmd(0x7e, pack("I I", 1, 0)) # stream control
        if stat :
            print('Box in use!' )
            exit(1)
        
        sling_cmd(0xa6, pack("10h 76x", 0x1cf, 0, 0x40, 0x10, 0x5000, 0x180, 1, 0x1e,  0, 0x3d))
        SetVideoParameters(Resolution, 30, 8000, 63, 5 )
        stream = sling_open('Stream')   
        pc = 0
        stream_header = stream.recv(1024)
        ir_q.queue.clear()   # in case people pressed remote buttons before stream started    
        print('Stream started at', ts(), len(stream_header))
        return s_ctl, stream

    ################## START of Streamer Execution        
    print('Streamer Running: ', len(streams))
    s_ctl, stream = start_slingbox_session()
    pc = 0
    last_remote_command_time = time.time()
    while streams:
        socket_ready, _, _ = select.select([stream], [], [], 2.0 )
        if socket_ready:
            msg = stream.recv(8192)
            pc += 1
            for q in streams: q.put(msg)
            if pc % 1000 == 0 : 
                print(pc, end='\r')
  
                sling_cmd(0x66, '') # send a keepalive
                if pc % 10000 == 0 : print( '\r\n', ts(),'%4d Clients Connected' % len(streams))
                
            if (not ir_q.empty()) and (time.time() - last_remote_command_time > 0.5):
                data = ir_q.get()
                print( 'Got Message from Remote Control', binascii.hexlify(data))
                if data[0] == 0x00 :
                    msg = data[1:].decode('utf-8')
                    cmd, value = msg.split('=')
                    print( 'OBM ', cmd, value )
                    if cmd == 'RESOLUTION' : 
                        Resolution = int(value)
                        s_ctl = closeconn()
                        stream = closeconn(stream)
                        pc = 0
                        s_ctl, stream = start_slingbox_session()                    
                else:
                    sling_cmd(0x87, data + pack('464x 4h', 3, 0, 0, 0), msg_type=0x0201)
                    last_remote_command_time = time.time()
        else:  # Slingbox has stopped sending data. Due to video format change at source
            print(ts(), 'Stream Stopped Unexpectly')
            s_ctl = closeconn(s_ctl)
            stream = closeconn(stream)
            s_ctl, stream = start_slingbox_session()         
    s_ctl = closeconn(s_ctl)
    stream = closeconn(stream)
    stream_header = None
    print('Streamer Quiting')
    
def http_stream( connection, client, sling_addr, password ):
    global streams, stream_header
    print('\r\nStarting http stream handler for ', str(client), 'Numstreams ', len(streams))
    my_stream = queue.Queue()
    streams.append(my_stream)
    if len(streams) == 1 :         
        print('Starting Streamer') 
        Thread(target=streamer, args=(sling_addr, password)).start()    
    try:
        while not stream_header : time.sleep(0.1) ## Wait for first packet to arrive.
        connection.sendall(stream_header)
        while True: connection.sendall(my_stream.get()) 
    except Exception as e:
        print('HTTP stream Closed by Peer')
    
    streams.remove(my_stream)
    connection.close()
    print(ts(),'Exiting HTTP Connection Handler for', client )

    
def remote_control_stream( connection, client, request):
    print('\r\nStarting remote control stream hander for ', str(client))
    remote_control_socket =  socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    remote_control_socket.connect(('127.0.0.1', 9998 ))  ## Send Packets to Dash
    print('Remote Control Connected')
    remote_control_socket.sendall( bytes(request, 'utf-8' ))
    sockets = [remote_control_socket, connection]
    while True: 
 #       print('Waiting for data')
        read_sockets, _, _ = select.select(sockets, [], [], 0.5 )
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
    print('Exiting Remote Control Stream Handler for', client )
    
    
######################################################################## 
def ConnectionManager(slingbox_address, SlingboxPassword, port ): 
    global streams, stream_header
    print('Connection Manager Running....')
    streams = []
    stream_header = None
    server_address = ('', port)
     
    # Create a TCP/IP socket
    ConnectionManagerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ConnectionManagerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('starting up on %s port %s' % server_address )
    ConnectionManagerSocket.bind(server_address)
    ConnectionManagerSocket.listen(10)

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
            ConnectionManagerSocket.listen(10)
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
                connection.sendall(b'HTTP/1.0 200 OK\r\nContent-type: application/octet-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n')
                Thread(target=http_stream, args=(connection, client_address, sling_net_address, SlingboxPassword )).start()
            elif 'Remote' in data :
                Thread(target=remote_control_stream, args=(connection, client_address, data )).start()
            else:
                print('Hacker Alert. Invalid Request from ', client_address )
                connection = closeconn(connection)
                continue
        except Exception as e:
            print( 'Hacker Alert. Bad Data from ', client_address )
            connection = closeconn(connection)
            continue



#Key Codes : 1,4,5,9,10,11,12,13,14,15,16,17,18,19,21,22,23,24,25,26,27,28,29,31,32,33,34,35,37,38,39,40,41,42,43,44,45,46,47,53,54,55,56,57,58,59,60
# 1 = power
# 4 = chnl +
# 5 = chnl -
# 9 = #1
# 10 = #2
# 11 = #3
#.....
# 18 = #0
# 19 = Screen format (Stretch, Wide ..... )
# 21 = chnl +
# 22 = ???
# 23 = DVR
# 24 = Play
# 25 = ???
# 26 = Pause
# 27 = Rewind
# 28 = FF
# 29 = Record
# 31 = Back 10 Seconds
# 32 = ->|
# 33 = Menu
# 34 = OnDemand
# 35 = Guide
# 37 = Exit
# 38 = "Up arrow"
# 39 = "down Arrow"
# 40 = "<-"
# 41 = "->"
# 42 = "OK"
# 43 = Page Up
# 44 = Page Down
# 45 = Favourites
# 46 = Info
# 47 = ???
# 53 = PIP on/off
# 54 = ????
# 55 = ????
# 56 = Last
# 57 = ????
# 58 = LOck PIN
# 59 = Day -
# 60 = Day +

cmds = {'1'  : 9, 
        '2'  : 10, 
        '3'  : 11, 
        '4'  : 12, 
        '5'  : 13, 
        '6'  : 14, 
        '7'  : 15, 
        '8'  : 16, 
        '9'  : 17, 
        '0'  : 18, 
        'Br1' : '',
        'OK'   : 42, 
        'Up'   : 38, 
        'Down' : 39, 
        'Left' : 40, 
        'Right': 41, 
        'Br2'  : '',
        'Guide': 35, 
        'Last' : 56,         
        'Exit' : 37,
        'DVR'  : 23,
        'Br3'  : '',
        'FF'   : 28,
        'Rew'  : 27, 
        'Play' : 24, 
        'Pause': 26, 
        'Br4'  : '',
        'Ch+'  : 4,
        'Ch-'  : 5,
        'Pg+' : 43, 
        'Pg-' : 44,
        'Br7'  : '',
        'Day-' : 59,
        'Day+' : 60,        
        'Br5'  : '',
        'Rec'  : 29, 
        'OnDemand': 34,
        'Menu' : 33, 
        'Br6'  : '',
        'Power' : 1, 
        '1920x1080' : 16,
        '1280x720' : 12,
        'Br8'  : '',
        'Restart': ''
    }
 

def BuildPage():
    BasePage = '''
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"><html>
<head>
  <meta http-equiv="content-type" content="text/html; charset=UTF-8">
  <title>Remote</title>
  <style>
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
</style>
</head>
<body >
     <form method="post" action="/buttons"> 
        %s
     </form>
</body>
</html>
'''
    formstr = ''
    for key, data in cmds.items():
      if 'Br' in  key:
        formstr = formstr + '<br><br>'
      else:
        formstr = formstr + '<button class=button type="submit" name="%s" value="%s">%s</button>&nbsp&nbsp;' % (key,str(data), key)     
    page = BasePage % formstr
    return page 

def killmyself():
    mypid = os.getpid()
    if 'windows' in platform.platform().lower():
        os.system('taskkill /f /pid %d /t' % mypid)
    else:
        os.system('kill -9 %d' % mypip)
        
print( 'Running on', platform.platform())
mypid = os.getpid()
streams = []
Resolution = int(sys.argv[1])
stream_header = None
#ConnectionManagerSocket = None
password = sys.argv[2]
ConnectionManagerPort = int(sys.argv[3])
ir_q = queue.Queue()
sling_net_address = find_slingbox_info()

if sling_net_address[0] and sling_net_address[1] :
    print('Found Slingbox at ', sling_net_address )
    Thread(target=ConnectionManager,args=(sling_net_address, password, ConnectionManagerPort )).start()

    Page = BuildPage()

    app = Flask(__name__)

    @app.route('/Remote', methods=["GET"])
    def index():
        return render_template_string(Page)
        
    @app.route('/buttons', methods=["POST"])
    def button():
        global ir_q
        print('Button Clicked', request.form)
        for cmd in cmds.keys():
            data = request.form.get(cmd)
            if data != None:           
                if cmd == 'Restart' :
                    killmyself()
                elif 'x' in cmd and cmd != 'Exit':
                    ir_q.put( bytearray(1) + bytes('RESOLUTION=%d' % cmds[cmd], 'utf-8'))
                else:
                    ir_q.put(int(data).to_bytes(1, byteorder='little') +
                                  b'\x00\x00\x00\x00\x00\x00\x00')
        return render_template_string(Page)

    app.run(host='0.0.0.0', port=9998, debug=False)
else:
    print("Quitting. Can't find a Slingbox on the local network. Sorry")
