!!! The current code only supports the Slingbox 350/500  :-( !!!

You'll need your SlingBox admin password. "https://newwatchsecure.slingbox.com/watch/slingAccounts/account_boxes_js"

Bonus: The HTTP streaming server can server out mutliple simultaneous streams so more than one person can see the Sling content at once. An integrated RTSP server should not be hard to do.

The web-based remote control is yet another huge hack to get something working quickly. Uses "Flask", definately can be made prettier. You can tweek the look in the [REMOTE] section of the config.ini file. You can insert any valid HTML between the buttons and change the button and text style.

To watch your slingbox use a media player that supports http streaming. I've tested VLC, OBS studio, ffplayer and mxplayer. http://your_ip_address_or_FQDN:your_port_number/slingbox
your_port_number defaults to 8080 but you can override that with the port= entry in the config.ini file.
i.e. http://192.168.1.10:8080/slingbox

To access the Remote control functionality use the same IP address and port number but replace slingbox with Remote into any ol' web browser.
i.e. http://192.168.1.10:8080/Remote


Linux/RaspberryPi Notes
You'll need a working Python3 interpreter to get going. Comes pre-installed on the Raspberry Pi distribution

#    A minimum system is just less that 2G. So for safety sake use at least a 4G micro sd card
#    Make a user "slingbox" with whatever password you'd like
    sudo apt-get update
    sudo apt-get install python3-pip
# you don't need the flask modlue if you're not using the embedded web server to server out the Remote Control page. Disable the remote in your config.ini file set enableremote=no.
    sudo pip install flask
# you don't need netifaces if you configure the slingbox ip address and port number in the config.ini file
    sudo pip install netifaces
    
    copy "slinbox_server.py, keys.dat, config.ini and sling.service to /home/slingbox  # 

    sudo cp sling.service /etc/systemd/system/.
 #   enable it
    sudo systemctl daemon-reload
    sudo systemctl enable sling.service
    sudo systemctl start sling.service
    
sudo systemctl stop sling.service # to shut it down   
    
# The default config generates a log file /tmp/sling.log   to check to see what's going on....

Added or modify the two following lines to your /etc/sysctl.conf 
    net.core.rmem_max = 8192000
    net.core.wmem_max = 8192000
  
    
Windows Notes
    There is a windows executable now available so you don't need to do a python install but your welcome to run the python code directly if you want. I used cygwin Python on my Windows box but any windows python program should work. You'll need flask and netifaces module for python. See note about netifaces and flask above.
    make a folder "slingbox" somewhere
    copy "slinbox_server.py, keys.dat, config.ini and RunSling.bat to the slingbox folder #
    if you want to have the server start automatically on boot make a shortcut to RunSling.bat in the Startup folder
    You need to open the port your using in your firewall on the server box if it's enabled.
    The port number the server binds to is set in the config.ini file, defaults to 8080. 
    If you want remote access add a port map on your firewall to redirect to your server box.
    
    Security. Windows defender may think there are two viruses in the slingbox_server.exe file. This is not the case. Add an execption on your system for slingbox_server.exe
     pc settings/update & security/windows security/virus & threat protection/virus & thread protection settings/add or remove exclusions/add an exclusion .. enter path to slingbox_server.exe.
     Apparently there is a way around this by changing the source code and then signing the executable but I haven't tested it yet.
     
Not getting what your expecting. Note the Slingbox does not upscale the input, See https://www.slingbox.com/help/KB/KB-2000464 for more info.

// slingbox video sizes
#define SBVS_320x240	1
#define SBVS_160x120	2
#define SBVS_352x240	3
#define SBVS_176x120	4
#define SBVS_640x480	5
#define SBVS_640x240	6
#define SBVS_320x480	7
#define SBVS_128x96		8
#define SBVS_224x176	9
#define SBVS_448x240	10
#define SBVS_256x192	11
#define SBVS_1280x720	12
#define SBVS_1440x544	13
#define SBVS_1680x544	14
#define SBVS_1920x544	15
#define SBVS_1920x1080	16

 #Key Codes : For my Motorola DCX3400M PVR. 1,4,5,9,10,11,12,13,14,15,16,17,18,19,21,22,23,24,25,26,27,28,29,31,32,33,34,35,37,38,39,40,41,42,43,44,45,46,47,53,54,55,56,57,58,59,60
 
// slingbox command codes
#define SBCMD_INVALID			0
#define SBCMD_POWER				1
#define SBCMD_POWERON			2
#define SBCMD_POWEROFF			3
#define SBCMD_CHANNELUP			4
#define SBCMD_CHANNELDOWN		5
#define SBCMD_VOLUMEUP			6
#define SBCMD_VOLUMEDOWN		7
#define SBCMD_MUTE				8
#define SBCMD_NUM1				9
#define SBCMD_NUM2				10 
#define SBCMD_NUM3				11 
#define SBCMD_NUM4				12 
#define SBCMD_NUM5				13 
#define SBCMD_NUM6				14 
#define SBCMD_NUM7				15 
#define SBCMD_NUM8				16 
#define SBCMD_NUM9				17 
#define SBCMD_NUM0				18 
#define SBCMD_ENTER				19 
#define SBCMD_HUNDRED			20 
#define SBCMD_LASTCHANNEL		21 
#define SBCMD_TVVCR				22 
#define SBCMD_EXTERNAL			23 
#define SBCMD_PLAY				24 
#define SBCMD_STOP				25 
#define SBCMD_PAUSE				26 
#define SBCMD_REWIND			27 
#define SBCMD_FASTFORWARD		28 
#define SBCMD_RECORD			29 
#define SBCMD_SKIPFORWARD		30 
#define SBCMD_SKIPBACK			31 
#define SBCMD_LIVE				32 
#define SBCMD_MENU				33 
#define SBCMD_SETUP				34 
#define SBCMD_GUIDE				35 
#define SBCMD_CANCEL			36 
#define SBCMD_EXIT				37 
#define SBCMD_UP				38 
#define SBCMD_DOWN				39 
#define SBCMD_LEFT				40 
#define SBCMD_RIGHT				41 
#define SBCMD_SELECT			42 
#define SBCMD_PAGEUP			43 
#define SBCMD_PAGEDOWN			44 
#define SBCMD_FAVORITE			45 
#define SBCMD_INFO				46 
#define SBCMD_FORMAT			47 
#define SBCMD_SUBTITLE			48 
#define SBCMD_SURROUND			49 
#define SBCMD_SLOW				50 
#define SBCMD_EJECT				51 
#define SBCMD_RANDOM			52 
#define SBCMD_PIP				53 
#define SBCMD_PIPFORMAT			54 
#define SBCMD_PIPFREEZE			55 
#define SBCMD_PIPSWAP			56 
#define SBCMD_PIPMOVE			57 
#define SBCMD_PIPSOURCE			58 
#define SBCMD_PIPCHANUP			59 
#define SBCMD_PIPCHANDOWN		60 
#define SBCMD_PIPMULTI			61 
#define SBCMD_CUSTOM10			62 
#define SBCMD_CUSTOM11			63 
#define SBCMD_CUSTOM12			64 
#define SBCMD_CUSTOM13			65 
#define SBCMD_CUSTOM14			66 
#define SBCMD_CUSTOM15			67 
#define SBCMD_CUSTOM16			68 
#define SBCMD_CUSTOM17			69 
#define SBCMD_CUSTOM18			70 
#define SBCMD_CUSTOM19			71 
#define SBCMD_CUSTOM20			72 
#define SBCMD_CUSTOM21			73 
#define SBCMD_RED				74 
#define SBCMD_GREEN				75 
#define SBCMD_YELLOW			76 
#define SBCMD_BLUE				77 
#define SBCMD_WHITE				78 
#define SBCMD_CUSTOM27			79 
#define SBCMD_CUSTOM28			80 
#define SBCMD_CUSTOM29			81 