#!/bin/env bash
tar -xvf btwaf.tar.gz --overwrite -C /www/server/  && cp -r btwaf.conf /www/server/panel/vhost/nginx/


cd ~
git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git
cd ~/ModSecurity/
cp ./modsecurity.conf-recommended /www/server/nginx/conf/modsecurity.conf
cp ./unicode.mapping /www/server/nginx/conf/    


cd /www/server/nginx/conf/
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g' /www/server/nginx/conf/modsecurity.conf
sed -i 's/SecStatusEngine Off/SecStatusEngine On/g' /www/server/nginx/conf/modsecurity.conf
sed -i 's@#SecDebugLog /opt/modsecurity/var/log/debug.log@SecDebugLog /var/log/modsec_debug.log@g' /www/server/nginx/conf/modsecurity.conf
sed -i 's/#SecDebugLogLevel 3/SecDebugLogLevel 3/g' /www/server/nginx/conf/modsecurity.conf


git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git && cd owasp-modsecurity-crs/
cp crs-setup.conf.example crs-setup.conf
sed -ie 's/SecDefaultAction "phase:1,log,auditlog,pass"/#SecDefaultAction "phase:1,log,auditlog,pass"/g' crs-setup.conf
sed -ie 's/SecDefaultAction "phase:2,log,auditlog,pass"/#SecDefaultAction "phase:2,log,auditlog,pass"/g' crs-setup.conf
sed -ie 's/#.*SecDefaultAction "phase:1,log,auditlog,deny,status:403"/SecDefaultAction "phase:1,log,auditlog,deny,status:403"/g' crs-setup.conf
sed -ie 's/# SecDefaultAction "phase:2,log,auditlog,deny,status:403"/SecDefaultAction "phase:2,log,auditlog,deny,status:403"/g' crs-setup.conf

cd /www/server/nginx/conf/
echo "include modsecurity.conf" >> modsec_includes.conf
echo "include custom_modsec_rules.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/crs-setup.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf" >> modsec_includes.conf
echo "Include owasp-modsecurity-crs/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-910-IP-REPUTATION.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-912-DOS-PROTECTION.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-913-SCANNER-DETECTION.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/RESPONSE-950-DATA-LEAKAGES.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/RESPONSE-959-BLOCKING-EVALUATION.conf" >> modsec_includes.conf
echo "include owasp-modsecurity-crs/rules/RESPONSE-980-CORRELATION.conf" >> modsec_includes.conf

touch  /www/server/whitelist.txt

cat  << OEF > custom_modsec_rules.conf
SecGeoLookupDB /var/lib/GeoIP/GeoLite2-Country.mmdb
SecRule REMOTE_ADDR "@geoLookup" "id:10001,phase:1,pass,log" 
SecRule REQUEST_URI "@beginsWith /vts_status" "id:10002,phase:1,nolog,pass,ctl:ruleEngine=Off" 
SecRule REQUEST_URI "@beginsWith /e/e_DliR28KktG1dpud/" "id:10003,phase:1,nolog,pass,ctl:ruleEngine=Off" 

# 如果是白名单 IP（包括 CIDR 格式），放行，不做限制
SecRule REMOTE_ADDR "@ipMatchFromFile /www/server/whitelist.txt" \
    "id:999,phase:1,allow,msg:'Allow access from whitelist IP'"

SecRule REQUEST_URI "@rx ^/e/member/" \
    "id:11000,phase:1,deny,status:403,msg:'Access to /e/member/ is denied'"

SecRule REQUEST_URI "@rx ^//e/ShopSys/" \
    "id:11001,phase:1,deny,status:403,msg:'Access to //e/ShopSys/ is denied'"

# 检测 Base64 编码的参数值超过64个字符
SecRule ARGS "^([A-Za-z0-9+/]{64,}=*)$" \
    "phase:2,deny,id:10004,log,msg:'参数值疑似Base64编码且长度超过64'"

# 检测十六进制编码的参数值超过64个字符
SecRule ARGS "^[A-Fa-f0-9]{64,}$" \
    "phase:2,deny,id:10005,log,msg:'参数值疑似十六进制编码且长度超过64'"
    

SecAction "id:1001,phase:1,nolog,pass,setvar:tx.html_rate_limit=2"
SecRule REQUEST_URI "@endsWith .html" "id:1002,phase:2,t:none,pass,nolog,setvar:ip.html_request_counter=+1,expirevar:ip.html_request_counter=2"
SecRule IP:html_request_counter "@gt 2" "id:1003,phase:2,log,deny,status:429,msg:'Too many requests for .html files from this IP',setvar:ip.html_exceed_counter=+1,expirevar:ip.html_exceed_counter=3600"

# 封禁策略：连续超限3次，封禁IP 5分钟
SecRule IP:html_exceed_counter "@ge 3" "id:1004,phase:2,log,deny,status:403,msg:'IP temporarily banned for excessive requests to .html files',setvar:ip.block_time=+1,expirevar:ip.block_time=300,setvar:ip.html_exceed_counter=0"
SecRule IP:block_time "@ge 2" "id:1005,phase:1,log,deny,status:403,msg:'IP is banned for 5 minutes'"

# 记录页面错误请求次数
SecRule RESPONSE_STATUS "@in 400,403,404,405,429,503" \
    "id:2001,phase:3,pass,nolog,setvar:ip.error_request_counter=+1,expirevar:ip.error_request_counter=180"

# 如果3分钟内错误请求次数超过15次，则封禁IP 1小时
SecRule IP:error_request_counter "@gt 15" \
    "id:2002,phase:3,log,deny,status:403,msg:'Too many error requests in 3 minutes , IP temporarily banned',setvar:ip.block_time=+1,expirevar:ip.block_time=3600,setvar:ip.error_request_counter=0"
    
# 检查IP是否已被封禁
SecRule IP:block_time "@ge 1" \
    "id:2003,phase:1,log,deny,status:403,msg:'IP is banned for 1 hour due to excessive error requests'"
OEF
