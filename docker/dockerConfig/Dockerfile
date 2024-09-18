#非直接启动freeswitch的dockerfile，进入容器之后再启动
#系统内核与docker系统不兼容时将bullseye切换为buster
FROM debian:buster
LABEL Andrey Volk <andrey@signalwire.com>

RUN sed -i 's/http:\/\/deb.debian.org/http:\/\/mirrors.aliyun.com/g' /etc/apt/sources.list


RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -yq install git

#RUN git clone https://github.com/signalwire/freeswitch /usr/src/freeswitch
# RUN cd /usr/src/ \
#     # 增加缓冲区大小
#     && git config --global http.postBuffer 524288000 \   
#     && git clone https://github.com/signalwire/freeswitch.git -bv1.10.10 freeswitch \
#     && cd freeswitch \
#     && git config pull.rebase true
COPY ../freeswitch /usr/src/freeswitch

RUN cd /usr/src/
RUN git clone https://github.com/signalwire/libks /usr/src/libs/libks
RUN git clone https://github.com/freeswitch/sofia-sip /usr/src/libs/sofia-sip
RUN git clone https://github.com/freeswitch/spandsp /usr/src/libs/spandsp
RUN git clone https://github.com/signalwire/signalwire-c /usr/src/libs/signalwire-c

RUN DEBIAN_FRONTEND=noninteractive apt-get -yq install \
# build
    build-essential cmake automake autoconf 'libtool-bin|libtool' pkg-config \
# general
    libssl-dev zlib1g-dev libdb-dev unixodbc-dev libncurses5-dev libexpat1-dev libgdbm-dev bison erlang-dev libtpl-dev libtiff5-dev uuid-dev \
# core
    libpcre3-dev libedit-dev libsqlite3-dev libcurl4-openssl-dev nasm \
# core codecs
    libogg-dev libspeex-dev libspeexdsp-dev \
# mod_enum
    libldns-dev \
# mod_python3
    python3-dev \
# mod_av
    libavformat-dev libswscale-dev libavresample-dev \
# mod_lua
    liblua5.2-dev \
# mod_opus
    libopus-dev \
# mod_pgsql
    libpq-dev \
# mod_sndfile
    libsndfile1-dev libflac-dev libogg-dev libvorbis-dev \
# mod_shout
    libshout3-dev libmpg123-dev libmp3lame-dev \
#else
    vim sngrep htop

RUN cd /usr/src/libs/libks && cmake . -DCMAKE_INSTALL_PREFIX=/usr -DWITH_LIBBACKTRACE=1 && make install
RUN cd /usr/src/libs/sofia-sip && ./bootstrap.sh && ./configure CFLAGS="-g -ggdb" --with-pic --with-glib=no --without-doxygen --disable-stun --prefix=/usr && make -j`nproc --all` && make install
RUN cd /usr/src/libs/spandsp  && git checkout 0d2e6ac  && ./bootstrap.sh && ./configure CFLAGS="-g -ggdb" --with-pic --prefix=/usr && make -j`nproc --all` && make install
RUN cd /usr/src/libs/signalwire-c && PKG_CONFIG_PATH=/usr/lib/pkgconfig cmake . -DCMAKE_INSTALL_PREFIX=/usr && make install

# Enable modules
RUN sed -i 's|#formats/mod_shout|formats/mod_shout|' /usr/src/freeswitch/build/modules.conf.in

COPY switch_core_media.c /usr/src/freeswitch/src

RUN cd /usr/src/freeswitch && ./bootstrap.sh -j
RUN cd /usr/src/freeswitch && ./configure
RUN cd /usr/src/freeswitch && make -j`nproc` && make install

RUN ln -sf /usr/local/freeswitch/bin/freeswitch /usr/bin/ 
RUN ln -sf /usr/local/freeswitch/bin/fs_cli /usr/bin/

# RUN cd /usr/src/
# RUN git clone https://github.com/dpirch/libfvad.git \
#     && cd libfvad \
#     && autoreconf -i \
#     && ./configure \
#     && make \
#     && make install \
#     && ldconfig

COPY mod_vad /usr/src/freeswitch/src/mod/applications/mod_vad
#COPY mod_uuid_playback /usr/src/freeswitch/src/mod/applications/mod_uuid_playback
#COPY mod_uuid_playback_continue /usr/src/freeswitch/src/mod/applications/mod_uuid_playback_continue
#COPY vad.conf.xml /usr/local/freeswitch/conf/autoload_configs
COPY modules.conf.xml /usr/local/freeswitch/conf/autoload_configs
COPY switch_core_media.c /usr/src/freeswitch/src
COPY freeswitch_monitor.sh /usr/local/freeswitch/scripts
COPY log_process.sh /usr/local/freeswitch/scripts
COPY tts_file_process.sh /usr/local/freeswitch/scripts
#COPY cdr_csv.conf.xml /usr/local/freeswitch/conf/autoload_configs

RUN cd /usr/src/freeswitch/src/mod/applications/mod_vad \
    && make \
    && make install \
    && cd /usr/src/freeswitch/src/mod/applications/mod_uuid_playback \
    && make \
    && make install \
    && cd /usr/src/freeswitch/src/mod/applications/mod_uuid_playback_continue \
    && make \
    && make install \
    && cd /usr/src/freeswitch/src/mod/applications/mod_callcenter \
    && make \
    && make install 



# Cleanup the image
#RUN apt-get clean

# Uncomment to cleanup even more
#RUN rm -rf /usr/src/*