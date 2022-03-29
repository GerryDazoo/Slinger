import os
import sys
import subprocess
import shlex
import socket
import sys
import time
import select
import binascii
import queue
from threading import Thread

def streamer(res):
    global streams, stream_header
    print('Streamer Running')
# OPen UDP socket for data from Remote Control
    remote_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    remote_sock.bind(('127.0.0.1', 10000))

    # OPen UDP socket for data from perl script
    sling_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sling_sock.bind(('127.0.0.1', 9999))
    # Start the perl script to get sream from slingbox
#https://newwatchsecure.slingbox.com/watch/slingAccounts/account_boxes_js
#var sling_account_boxes={"memberslingbox":{"c631844cf70531865d73650a16a0a536":{"lookupByFinderId":true,"adminPassword":"5mTSjQhQwgg0qi2","userPassword":"bphPvzsLGQ1L2E7","finderId":"C631844CF70531865D73650A16A0A536","isOwner":true,"productSignature":18,"passwordAutoMode":true,"displayName":"My Slingbox","memberSlingBoxId":3054863},"192.168.117.110:5218":{"username":"admin","lookupByFinderId":false,"adminPassword":"5mTSjQhQwgg0qi2","remoteViewingPort":5218,"wanIpAddress":"192.168.117.110","passwordAutoMode":false,"displayName":"My Slingbox","memberSlingBoxId":3568291}},"size":2}

    SW_MINIMIZE = 6
    info = subprocess.STARTUPINFO()
    info.dwFlags = subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = SW_MINIMIZE

    if '1920' in res :
        resolution = 16
        framerate = 30
    else:
        resolution = 12  #12 = 1280x540
  #      resolution = 8  # 320x240
  #      resolution = 9  #320x240
        framerate = 60
    cmd = shlex.split('C:/cygwin64/bin/perl.exe g:/slingbox/rec350_udp.pl -ip 192.168.117.110 -port 5218 -pass 5mTSjQhQwgg0qi2 -vbw 8000 -vs %d -fr %d' % (resolution, framerate))
    print('Starting ', cmd )
    perl_process = subprocess.Popen( cmd, shell=False, startupinfo=info )
    
    stream_header = sling_sock.recvfrom(32768)[0]
 #   print('First Packet Length = ', len(stream_header))
  #  for q in streams: q.put(stream_header[0])
    pc = 0
    while streams:
        msg = sling_sock.recvfrom(32768)
        pc += 1
#        print('msg len =', len(msg[0]))
        for q in streams: q.put(msg[0])
        if pc % 10000 == 0 : print( '%4d Clients Connected' % len(streams))
        ready_read, ready_write, exceptional = select.select([remote_sock], [], [], 0)
        if ready_read :
            print('Reading Message from Remote Control')
            data, addr = remote_sock.recvfrom(1024)
            print( 'Got Messgae from RC', binascii.hexlify(data))
            sling_sock.sendto(data, msg[1])
          
    print( 'Killing Perl')
    perl_process.kill()
    sling_sock.close()
    remote_sock.close()
    stream_header = None
    print('Streamer Quiting')
    
def http_stream( connection, client, res ):
    global streams, stream_header
    print('\r\nStarting http stream hander for ', client, 'Numstreams ', len(streams))
    my_stream = queue.Queue()
    streams.append(my_stream)
    if len(streams) == 1 :         
        print('Startting Streamer') 
        Thread(target=streamer, args=(res,)).start()    
    try:
        while not stream_header : time.sleep(0.1)
        connection.sendall(stream_header)
        while True: connection.sendall(my_stream.get()) 
    except Exception as e:
        print('Exception', e)
        connection.shutdown(socket.SHUT_RDWR)
        connection.close()
    
    streams.remove(my_stream)
    print('Exiting Stream Handler for', client )
    
########################################################################    
streams = []
stream_header = None
res = sys.argv[1]
server_address = ('', 8080)
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('starting up on %s port %s' % server_address )
sock.bind(server_address)
sock.listen(4)

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()

    try:
        print('connection from', client_address)
        
        ready_read, ready_write, exceptional = select.select([connection], [], [], 0.1)
        if not ready_read: 
            print('No Get Request in time, hacker?')
            connection.close()
            continue
        
        data = connection.recv(1024).decode("utf-8")            
        print('Request = ', data)
        if 'slingbox' not in data or '\r\n\r\n' not in data :
            print( 'hacker alert')
            connection.close()
        else:
            connection.sendall(b'HTTP/1.0 200 OK\r\nContent-type: application/octet-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n')

            Thread(target=http_stream, args=(connection, client_address, res )).start()
                 
    except Exception as e:
        print('Exception', e )

