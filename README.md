# GerryDazoo/Slinger updated to allow channel switching and includes xteve & Dockerfile modified from alturismo/xteve

docker runs in host mode \
access xteve webui ipaddress:34400/web/

after docker start check your config folder and do your setups, setup is persistent, start from scratch by deleting them

slinger/xteve start options are updated on docker restart.

mounts to use as sample \
Container Path: /root/.xteve <> /mnt/user/appdata/xteve/ \
Container Path: /config <> /mnt/user/appdata/xteve/_config/ \
Container Path: /tmp/xteve <> /tmp/xteve/ \
while /mnt/user/appdata/ should fit to your system path ...

to test the cronjob functions \
docker exec -it "dockername" ./config/cronjob.sh

After intial run:
  Stop docker container
  change following settings in /root/.xteve/setting.json  (channel from 1000 to 1).  These options can also be changed in the Settings page, except first channel option.
    "buffer": "ffmpeg",
    "buffer.size.kb": 512,
    "ffmpeg.options": "-hide_banner -loglevel error -fflags +genpts -i [URL] -c copy -bsf:v h264_metadata=sample_aspect_ratio=4/3 -f mpegts -tune zerolatency pipe:1",
    "mapping.first.channel": 1,
  Save
  Start docker container

Goto ip:34400/web/ for intial xteve setup
  Tuners: 1
  EPG Source: XEPG
  File path or URL of the M3U: /config/sample_slingbox.m3u 
      (this is a sample, change however you need based channels available on slingbox and the port config in slinger, using default 8080)
  File path or URL of the XMLTV: /config/sample_xmltv.xml

Enable Channel mapping
  Use bulk edit to edit all channels and click the first row
  Add "xTeVe Dummy" to the XMLTV File,
  Add "30 Minutes (30_Minutes)" to the XMLTV Channel
  Check "Active" to enable the channels.
  Click Save

TV Tuner should now be available in Plex to configure.

All sample files get copied over to /config/ path on initial run

sample_slingbox.m3u 
    contains 360 channels.  First 359 channels are configured to change channel via slingbox IR commands.  Final channel has no channel # passed in, this is to allow viewing the stream without changing the channel (in case someone is watching the cable box)

sample_xmltv.xml 
    file contains dummy XML to get through initial xteve set up screens.

sample_slinger.txt 
    file can override the entrypoint.sh commands, you could update this to disable xteve, if not needed.  
    rename/place file in /config/slinger.txt and restart docker container
