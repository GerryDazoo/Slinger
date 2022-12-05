# Slinger

Slinger is a project that allows SlingPlayer, Slingboxes and MediaPlayers to stream content:

- On the same LAN
- Connecting from the Internet
- Fully distributed (Cloud-based) 

> Sticking it to the Man, one slingbox at a time


## Version log

- Ver. 3.08: This now supports the 240/350/500/M1/M2/Solo/Pro and ProHD

## Documentation

It is highly recommended to review the following documents located in this repo as they provide more information to help you with you own setup:

- [SlingboxServerNetworkingGuide.pdf](SlingboxServerNetworkingGuide.pdf)
- [V3.0x_ReleaseNotes.pdf](V3.0x_ReleaseNotes.pdf)
- [V3.08_release_notes.pdf](V3.08_release_notes.pdf)
- [V3.08d_release_notes.pdf](V3.08d_release_notes.pdf)
- [V3.08e_release_notes.pdf](V3.08e_release_notes.pdf)
- [V3.08f_release_notes.pdf](V3.08f_release_notes.pdf)

## Setup instructions

1. Obtain your [SlingBox admin password](sb-pwd.md)
1. Edit the `config.ini` file:
    1.  You can select what type of slingbox you have with the `sbtype = entry`
1. Run `slingbox_server.py`
 


#### **Bonus**

- The HTTP streaming server can server out mutliple simultaneous streams so more than one person can see the Sling content at once.

- The web-based remote control is yet another huge hack to get something working quickly. Uses "Flask", definately can be made prettier. You can tweek the look in the [REMOTE] section of the config.ini file. You can insert any valid HTML between the buttons and change the button and text style.

## To watch your slingbox

Use a media player that supports http streaming. I've tested
- VLC
- OBS studio
- Ffplayer
- Mxplayer

Just configure:
```h
http://your_ip_address_or_FQDN:your_port_number/slingbox
```

Your_port_number defaults to `8080` but you can override that with the `port = entry` in the `SERVER` section of `config.ini` file. I.e.:

```
http://192.168.1.10:8080/slingbox
```

## Important

THIS IS THE NUMBER ONE MISTAKE PEOPLE MAKE SETTING THIS UP. THE IP ADDRESS IS FOR THE HOST RUNNING THE SERVER CODE NOT THE SLINGBOX. DO NOT USE THE SLINGBOX IP ADDRESS, IT WILL NOT WORK.

YOU CONNECT TO THE SERVER TO STREAM VIDEO NOT THE SLINGBOX. 
IT'S THE SERVER THAT TALKS TO THE SLINGBOX AND FORWARDS THE VIDEO TO YOU.
THE URL IS CASE SENSITIVE.

DO NOT USE '`Slingbox`' OR ANYTHING ELSE EXCEPT '`slingbox`'. "`slingbox`" is the default. It is now possible to change this.

Read the **Release notes pdf** document located in this repo.

THE [`SERVER`] port number is configured in the `config.ini` file. IT DEFAULTS TO `8080`.

Some people feel compelled to change this to the same port number as the slingbox and I don't know why. It only seems to add confusion to what is happening.   

## Remote control

To access the Remote control functionality, use the same IP address and port number but replace "`slingbox`" with Remote into any ol' web browser.i.e.

```
http://192.168.1.10:8080/Remote
```

## Linux/RaspberryPi Notes

You'll need a working **Python3** interpreter to get going. Comes pre-installed on the Raspberry Pi distribution:

* A minimum system is just less that 2G. So for safety sake use at least a 4G micro sd card
Make a user "slingbox" with whatever password you'd like

```sh
    sudo apt-get update
    sudo apt-get install python3-pip
```

* You don't need the flask module if you're not using the embedded web server to server out the Remote Control page. Disable the remote in your config.ini file set enableremote=no.

```sh
    sudo pip install flask
```

* You don't need netifaces if you configure the slingbox ip address and port number in the config.ini file

```sh
    sudo pip install netifaces
```    
* Copy "slingbox_server.py, config.ini and sling.service to /home/slingbox   

```sh
    sudo chmod +x /home/slingbox/slingbox_server.py
    sudo cp sling.service /etc/systemd/system/.
    # enable it
    sudo systemctl daemon-reload
    sudo systemctl enable sling.service
    sudo systemctl start sling.service
    
    sudo systemctl stop sling.service # to shut it down   
```

* The default config generates a log file /tmp/sling.log   to check to see what's going on....

As root, add or modify the two following lines to your /etc/sysctl.conf 

```py
    net.core.rmem_max = 8192000
    net.core.wmem_max = 8192000
```


### Adding your own remote

To add your own remote, please do following:

1. Create a new branch and follow this naming convention:
    
    > add-remote-`<your-remote-name>`

2. Add your control in the folder named `CustomRemotes`, name your file:

    > `Model`Remote.txt

The branch will be reviewed and approved for merging if passed.


## Notes for Windows users

There is a `windows executable` now available so you don't need to do a python install but your welcome to run the python code directly if you want.

I used `cygwin` Python on my Windows box but any windows python program should work.

You'll need flask and netifaces module for python. See note about netifaces and flask above.

1. Make a folder "slingbox" somewhere
1. Copy `slinbox_server.py`, `config.ini` and `RunSling.bat` to the slingbox folder

If you want to have the server start automatically on boot make a shortcut to `RunSling.bat` in the Startup folder.

  1. You need to open the port your using in your firewall on the server box if it's enabled.
  1. The port number the server binds to is set in the config.ini file, defaults to 8080. 
1. If you want remote access add a port map on your firewall to redirect to your server box.

### Security

Windows Defender may think there are two viruses in the slingbox_server.exe file. This is not the case. Add an exception on your system for slingbox_server.exe

    PC Settings/Update & Security/Windows Security/Virus & Threat Protection/Virus & Thread protection Settings/Add or Remove Exclusions/Add an exclusion:
    
    Enter the path to slingbox_server.exe

    Apparently there is a way around this by changing the source code and then signing the executable but I haven't tested it yet.
     
### Not getting what your expecting?

Note the Slingbox does not upscale the input, See [https://www.slingbox.com/help/KB/KB-2000464](https://www.slingbox.com/help/KB/KB-2000464)
 for more info.

### Slingbox Video Sizes

```py
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
```
Note: `Resolution = 0`, is *AudioOnly* mode.

#Key Codes : For my Motorola DCX3400M PVR. 1,4,5,9,10,11,12,13,14,15,16,17,18,19,21,22,23,24,25,26,27,28,29,31,32,33,34,35,37,38,39,40,41,42,43,44,45,46,47,53,54,55,56,57,58,59,60
 
### Slingbox Command Codes

```py
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
```