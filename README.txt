You'll need a working Python3 interpreter to get going.  

You'll need your SlingBox admin password. "https://newwatchsecure.slingbox.com/watch/slingAccounts/account_boxes_js"

Bonus: The HTTP streaming server can server out mutliple simultaneous streams so more than one person can see the Sling content at once. An integrated RTSP server should not be hard to do.

The web-based remote control is yet another huge hack to get something working quickly. Uses "Flask", definately can be made prettier. You can tweek the look in the [REMOTE] section of the config.ini file. You can insert any valid HTML between the buttons and change the button and text style.

Linux/RaspberryPi Notes
#    A minimum system is just less that 2G. So for safety sake use at least a 4G micro sd card
#    Make a user "slingbox" with whatever password you'd like
    sudo apt-get update
    sudo apt-get install python3-pip 
    sudo pip install flask
# you don't need netifaces if you configure the slingbox ip address and port number in the config.ini file
    sudo pip install netifaces
    
    copy "slinbox_server.py, tea.py, keys.dat, config.ini and sling.service to /home/slingbox  # 

    sudo cp sling.service /etc/systemd/system/.
 #   enable it
    sudo systemctl daemon-reload
    sudo systemctl enable sling.service
    sudo systemctl start sling.service
    
sudo systemctl stop sling.service to shut it down   
    
# The default config generates a log file /tmp/sling.log   to check to see what's going on....   
    
   
Windows Notes
    I used cygwin Python on my Windows box but any widows python program should work. You'll need flask and netifaces module for python. See note about netifaces above.
    make a folder "slingbox" somewhere
    copy "slinbox_server.py, tea.py, keys.dat, config.ini and RunSling.bat to the slingbox folder #
    if you want to have the server start automatically on boot make a shortcut to RunSling.bat in the Startup folder
    You need to open the port your using in your firewall on the server box if it's enabled.
    The port number the server binds to is set in the config.ini file. 
    If you want remote access add a port map on your firewall to redirect to your server box
    
Not getting what your expecting. Note the Slingbox does not upscale the input, See https://www.slingbox.com/help/KB/KB-2000464 for more info.

Here's what I've figured out about the key codes. Please let me know if you know what the keys with ????s do. I don't remember where I got the key codes for my remote :-(. Except it was from Slingbox software somewhere (Slingplayer Desktop? when setting up remote?)

 #Key Codes : For my Motorola DCX3400M PVR. 1,4,5,9,10,11,12,13,14,15,16,17,18,19,21,22,23,24,25,26,27,28,29,31,32,33,34,35,37,38,39,40,41,42,43,44,45,46,47,53,54,55,56,57,58,59,60
 
# 1 = power
# 4 = chnl +
# 5 = chnl -
# 9 = digit 1
# 10 = digit 2
# 11 = digit 3
#.....
# 18 = digit 0
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
# 58 = Lock PIN
# 59 = Day -
# 60 = Day +