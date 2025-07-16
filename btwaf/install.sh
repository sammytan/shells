#!/bin/env bash
tar -xvf btwaf.tar.gz --overwrite -C /www/server/  && cp -r btwaf.conf /www/server/panel/vhost/nginx/

! test -f /www/server/whitelist.txt && touch  /www/server/whitelist.txt

cp -rp ./owasp-modsec-crs  /www/server/nginx/conf/
cp unicode.mapping /www/server/nginx/conf/
cp modsecurity.conf  /www/server/nginx/conf/
cp modsec_includes.conf  /www/server/nginx/conf/
cp custom_modsec_rules.conf /www/server/nginx/conf/


/bin/cp -r nginx.conf /www/server/nginx/conf/



