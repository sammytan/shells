#!/bin/env bash
tar -xvf btwaf.tar.gz --overwrite -C /www/server/  && cp -r btwaf.conf /www/server/panel/vhost/nginx/



! test -f /www/server/whitelist.txt && touch  /www/server/whitelist.txt


