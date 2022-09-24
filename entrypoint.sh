#!/bin/bash

SLINGER_FILE=/config/slinger.txt

if [ -f "$SLINGER_FILE" ]; then
	. $SLINGER_FILE
else
	cp -n /sample_slinger.txt /config/sample_slinger.txt
	cp -n /config.ini /config/sample_config.ini
	cp -n /sample_xmltv.xml /config/sample_xmltv.xml
	cp -n /config.ini /config/config.ini
	cp -n /slingbox.m3u /config/sample_slingbox.m3u
	xteve -port=34400 -config=/root/.xteve/ & 
	python3 -u /usr/src/app/slingbox_server.py /config/config.ini
fi

exit
