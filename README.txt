So this is very early and needs alot of work to "productize" it but it is functional.
You'll need a working Python3 interpreter to get going.  

You'll need your SlingBox admin password. "https://newwatchsecure.slingbox.com/watch/slingAccounts/account_boxes_js"

Bonus: The HTTP streaming server can server out mutliple simultaneous streams so more than one person can see the Sling content at once. An integrated RTSP server should not be hard to do.

The web-based remote control is yet another huge hack to get something working quickly. Uses "Flask", definately can be make prettier. Maybe active areas on an image of the remote for the buttons.

Note: The core Sling control interface code in the Perl script came from the kttmg project slingbox plugin. You can find a SlingBox SDK written in C++ on github if you're interested.

Linux/RaspberryPi Notes
#    A minimum system is just less that 2G. SO for safety sake use at least a 4G micro sd card
#    Make a user "slingbox" with whatever password you'd like
    sudo apt-get update
    sudo apt-get install python3-pip 
    sudo pip install flask
    sudo pip install netifaces
    
    copy "slinbox_server.py, tea.py, keys.dat, and sling.service to /home/slingbox  # 
    edit sling.service with your default screen resolution, slingbox admin password  and port number to listen on for connections
    sudo cp sling.service /etc/systemd/system/.
 #   enable it
    sudo systemctl daemon-reload
    sudo systemctl enable sling.service
    sudo systemctl start sling.service
    
# The default config generates a log file /tmp/sling.log   to check to see whats going on....   
    
   
Windows Notes
    I used cygwin Python on my Windows box but any widnows python program should work. You'll need flask and netifaces module for python.
    make a folder "slingbox" somewhere
    copy "slinbox_server.py, tea.py, keys.dat and RunSling.bat to the slingbox folder #
    edit RunSling.bat to suit your local configuration, default screen size and slingbox admin password
    if you want to have the server start automatically on boot make a shortcut to RunSling.bat in the Startup folder
    You need to open the port your using in your firewall on the server box if it's enabled.
    The port number the server binds to is passed in on the command line (RunSLing.bat) 
    If you want remote access add a port map on your firewall to redirect to your server box
    
Here's a little something. The slingbox resolution 12 should be 1280x720 but after startup VLC codec info says it's really 1280x540 basically the sling box is throwing away every scond scan line. Apparently this is what you gt is the input to the slingbox is 1920x1080. Changing the output from my cable box to 1280x720 makes the slingbox send 1280x720. 