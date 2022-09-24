FROM alpine:latest
RUN apk update
RUN apk upgrade
RUN apk add --no-cache ca-certificates

# Extras
RUN apk add --no-cache curl

# Timezone (TZ)
RUN apk update && apk add --no-cache tzdata
ENV TZ=US/Eastern
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Add Bash shell & dependancies
RUN apk add --no-cache bash busybox-suid su-exec

# Volumes
VOLUME /config
VOLUME /root/.xteve
VOLUME /tmp/xteve

# Add ffmpeg and vlc
RUN apk add ffmpeg
RUN apk add vlc
RUN sed -i 's/geteuid/getppid/' /usr/bin/vlc

#Add Slinger
RUN apk add py3-pip
RUN apk add py3-netifaces
RUN pip3 install --upgrade pip
RUN pip3 install flask
RUN pip3 install requests
ADD slingbox_server.py /usr/src/app/
ADD config.ini /


# Add xTeve and guide2go
#comment/uncomment arm64 vs amd64
RUN wget https://github.com/xteve-project/xTeVe-Downloads/raw/master/xteve_linux_amd64.zip -O temp.zip; unzip temp.zip -d /usr/bin/; rm temp.zip
#RUN wget https://github.com/xteve-project/xTeVe-Downloads/raw/master/xteve_linux_arm64.zip -O temp.zip; unzip temp.zip -d /usr/bin/; rm temp.zip
ADD entrypoint.sh /
ADD sample_slinger.txt /
ADD slingbox.m3u /
ADD sample_xmltv.xml /

# Set executable permissions
RUN chmod +x /entrypoint.sh
RUN chmod +x /usr/bin/xteve

# Expose Port
EXPOSE 34400

# Entrypoint
ENTRYPOINT ["./entrypoint.sh"]
