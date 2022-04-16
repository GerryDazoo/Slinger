import dash
from dash import html
from dash.dependencies import Input, Output, State
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

streams = []
stream_header = None
ConnectionManagerSocket = None
remote_q = queue.Queue()

def ts():
    return '\r\n%s ' % datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    
def find_slingbox_info(): 
    ip = ''
    port = None
    data =  [0x01, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
              
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(('0.0.0.0', 0))
        print('Finding SlingBox on local network')
        for i in range(1,4):
            try: 
                s.sendto( bytearray(data), ('255.255.255.255', 5004 ))
                msg, source = s.recvfrom(32768)
            #    print('Got', str(msg), source)
                if len( msg ) == 124 :
                    print('good len')
                    if b'S\x00l\x00i\x00n\x00g\x00b\x00o\x00x' in msg:
                        print('From Slingbox')
                        ip = source[0]
                        break                       
            except socket.timeout:
                print('No Response from Slingbox in time!')
        s.close()
        if ip :
           for p in range(5201, 5220):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                print('Scanning for open control port')
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

def streamer(sling_addr, res, password):
    global streams, stream_header, remote_q
    print('Streamer Running')
    remote_q.queue.clear() # in case people pressed remote buttons before stream started
    # OPen UDP socket for data from perl script
    sling_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sling_sock.setsockopt( socket.SOL_SOCKET, socket.SO_RCVBUF, 2048000) 
#    bufsize = sling_sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) 
#    print ("Buffer size [After]:%d" %bufsize) 
    sling_sock.bind(('127.0.0.1', 9999))
    # Start the perl script to get sream from slingbox
#https://newwatchsecure.slingbox.com/watch/slingAccounts/account_boxes_js
    if res == 16:
        framerate = 30
    else:
        framerate = 60
    cmd = shlex.split('perl rec350_udp.pl -ip %s -port %d -pass %s -vbw 8000 -vs %d -fr %d' % (sling_addr[0], sling_addr[1], password, res, framerate))
    print('Starting ', cmd )
    streamer_process = subprocess.Popen( cmd, shell=False )
    
    stream_header = sling_sock.recvfrom(32768)[0]
 #   print('First Packet Length = ', len(stream_header))
  #  for q in streams: q.put(stream_header[0])
    pc = 0
    last_remote_command_time = time.time()
    while streams:
        msg = sling_sock.recvfrom(32768)
        pc += 1
        for q in streams: q.put(msg[0])
        if pc % 10000 == 0 : print( ts(),'%4d Clients Connected' % len(streams))
        if (not remote_q.empty()) and (time.time() - last_remote_command_time > 0.5):
            data = remote_q.get()
            print( 'Got Messgae from RC', binascii.hexlify(data))
            sling_sock.sendto(data, msg[1])
            last_remote_command_time = time.time()
          
    print( 'Killing Perl')
    streamer_process.kill()
    sling_sock.close()
    stream_header = None
    print('Streamer Quiting')
    
def http_stream( connection, client, sling_addr, res, password ):
    global streams, stream_header
    print('\r\nStarting http stream handler for ', str(client), 'Numstreams ', len(streams))
    my_stream = queue.Queue()
    streams.append(my_stream)
    if len(streams) == 1 :         
        print('Startting Streamer') 
        Thread(target=streamer, args=(sling_addr, res, password)).start()    
    try:
        while not stream_header : time.sleep(0.1) ## Wait for first packet to arrive.
        connection.sendall(stream_header)
        while True: connection.sendall(my_stream.get()) 
    except Exception as e:
        print('Exception', e)
    
    streams.remove(my_stream)
    print(ts(),'Exiting Stream Handler for', client )
    
def remote_control_stream( connection, client, request):
    print('\r\nStarting remote control stream hander for ', str(client))
    remote_control_socket =  socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    remote_control_socket.connect(('127.0.0.1', 9998 ))  ## Send Packets to Dash
    print('Remote Control Connected')
    remote_control_socket.sendall( bytes(request, 'utf-8' ))
    sockets = [remote_control_socket, connection]
    while True: 
 #       print('Waiting for data')
        read_sockets, _, _ = select.select(sockets, [], [] )
        for sock in read_sockets:
            data = sock.recv(32768)
            if len(data) == 0 : 
                break
            if sock == connection: remote_control_socket.sendall(data)
            if sock == remote_control_socket: connection.sendall(data)
        else:
            continue
        break
    connection.shutdown(socket.SHUT_RDWR)
    connection.close()        
    remote_control_socket.shutdown(socket.SHUT_RDWR)
    remote_control_socket.close()
    print('Exiting Remote Control Stream Handler for', client )
    
    
######################################################################## 
def ConnectionManager(resolution, SlingboxPassword): 

    def closeconn( s ):
        s.sendall(b'\0x00')
        s.shutdown(socket.SHUT_RDWR)
        s.close()

    global streams, stream_header, ConnectionManagerSocket
    print('Connection Manager Running....')
    streams = []
    stream_header = None
    server_address = ('', int(sys.argv[3]))
    
    sling_net_address = find_slingbox_info()
    
    # Create a TCP/IP socket
    ConnectionManagerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ConnectionManagerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('starting up on %s port %s' % server_address )
    ConnectionManagerSocket.bind(server_address)
    ConnectionManagerSocket.listen(10)

    while True:
        # Wait for a connection
        print('\r\nwaiting for a connection')
        try:
            connection, client_address = ConnectionManagerSocket.accept()
        except:
            print('Stopping ConnectionManager')
            streams = []
            stream_header = None
            ConnectionManagerSocket = None
            break
            
        try:
            print(ts(), ' connection from', str(client_address))
            
            ready_read, ready_write, exceptional = select.select([connection], [], [], 0.2)
            if not ready_read: 
                print('No Get Request in time, hacker?')
                closeconn(connection)
                continue
            
            data = connection.recv(1024).decode("utf-8")            
            if 'slingbox' in data :
                connection.sendall(b'HTTP/1.0 200 OK\r\nContent-type: application/octet-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n')
                Thread(target=http_stream, args=(connection, client_address, sling_net_address, resolution, SlingboxPassword )).start()
            elif 'Remote' in data :
                Thread(target=remote_control_stream, args=(connection, client_address, data )).start()
            else:
                print('Hacker Alert. Invalid Request from ', client_address )
                closeconn(connection)
        except Exception as e:
            print( 'Hacker Alert. Bad Data from ', client_address )
            closeconn(connection) 



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
        'PgUp' : 43, 
        'PgDn' : 44,
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
        'Restart': ''
    }

http_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    

app = dash.Dash(title='TV Remote', url_base_pathname='/Remote/')

buttons = []
callbacks = []
for button in cmds.keys():
    if 'Br' in button :
        buttons.append( html.Br())
        buttons.append( html.Br())
        buttons.append( html.Br())
#        print('Added Break')
    else:
        buttons.append( html.Button( button, id=button, style={'font-size': '80px', 'padding': '0px 20px'}))
        callbacks.append ( Input( button, 'n_clicks' ))

app.layout = html.Div( [
                       html.Div(id='div1', children=buttons )
                      ])

def killpid( pid ):
    if 'Windows' in platform.platform():
        os.system('taskkill /f /pid %d /t' % pid)
    else:
        os.system('kill -9 %d' % os.getpid())
    
@app.callback(
    Output('div1', 'children'), callbacks )
    
def run_script_onClick(*clicks):
    global ConnectionManagerThread, remote_q
    trigger = dash.callback_context.triggered[0] 
    id = trigger["prop_id"].split(".")[0]
    print('[DEBUG]', id)

    if id not in cmds.keys(): return dash.no_update

    if id == 'Restart' :
        killpid(os.getpid())
    elif 'x' in id and id != 'Exit':
        print('Changing to Resolution', id, cmds[id])
        # Wait for thread to die
        ConnectionManagerSocket.shutdown(socket.SHUT_RDWR) # will cause exception in ConnectionManager
        print('Waiting for ConnectionManager to die' )
        while ConnectionManagerSocket != None : time.sleep(0.1)
        Thread(target=ConnectionManager, args=(cmds[id], sys.argv[2])).start()
    else:
        print('Sending IR Command ', id, cmds[id])
        remote_q.put(cmds[id].to_bytes(1, byteorder='little') +
                          b'\x00\x00\x00\x00\x00\x00\x00')
   
    return dash.no_update
            
print( 'Running on', platform.platform())
Thread(target=ConnectionManager,args=(int(sys.argv[1]), sys.argv[2])).start()
app.run_server(host='127.0.0.1', port=9998, debug=False)
