#!/bin/bash
set -e

# Source docker-entrypoint.sh:
# https://github.com/docker-library/postgres/blob/master/9.4/docker-entrypoint.sh
# https://github.com/kovalyshyn/docker-freeswitch/blob/vanilla/docker-entrypoint.sh

if [ "$1" = 'freeswitch' ]; then

    if [ ! -f "/usr/local/freeswitch/conf/freeswitch.xml" ]; then
        #mkdir -p /usr/local/freeswitch/conf
        #cp -varf /usr/share/freeswitch/conf/vanilla/* /usr/local/freeswitch/conf/
        echo "/usr/local/freeswitch/conf/freeswitch.xml no exist"
    fi

    #chown -R freeswitch:freeswitch /usr/local/freeswitch/conf
    #chown -R freeswitch:freeswitch /core_dumps
    
    if [ -d /docker-entrypoint.d ]; then
        for f in /docker-entrypoint.d/*.sh; do
            [ -f "$f" ] && . "$f"
        done
    fi
    
    exec  /usr/local/freeswitch/bin/freeswitch  -nonat -c
fi

exec "$@"

