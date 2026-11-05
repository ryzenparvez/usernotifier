# JSN WiFi - বিল নোটিশ পপ-আপ: MikroTik রুল (একবার চালাবেন)
# আগে নিচের দুইটা মান বদলান:
:local portalIp "192.168.88.10"   ;# যে PC-তে jsn_notifier.py চলবে তার IP (গেটওয়ে = MikroTik হতে হবে)
:local portalPort "8080"
:local apiPass "CHANGE_ME"        ;# config.ini এর password এর সাথে মিলবে

# 1) API ইউজার (শুধু প্রয়োজনীয় অনুমতি)
/user group add name=notifier policy=api,read,write,test
/user add name=notifier group=notifier password=$apiPass address=$portalIp

# 2) NAT: HTTP রিডাইরেক্ট (ফোনের captive-portal চেক ধরার জন্যও এটাই কাজ করে)
/ip firewall nat
add chain=dstnat src-address-list=bill-seen action=accept comment="jsn: seen -> skip" place-before=0
add chain=dstnat dst-address=$portalIp action=accept comment="jsn: portal itself" place-before=1
add chain=dstnat src-address-list=bill-warn protocol=tcp dst-port=80 action=dst-nat to-addresses=$portalIp to-ports=$portalPort comment="jsn: warn popup" place-before=2
add chain=dstnat src-address-list=bill-expired protocol=tcp dst-port=80 action=dst-nat to-addresses=$portalIp to-ports=$portalPort comment="jsn: expired popup" place-before=3

# 3) মেয়াদ শেষ ইউজারদের জন্য: শুধু DNS + পোর্টাল খোলা, বাকি সব বন্ধ
/ip firewall filter
add chain=forward src-address-list=bill-expired protocol=udp dst-port=53 action=accept comment="jsn: expired DNS" place-before=0
add chain=forward src-address-list=bill-expired protocol=tcp dst-port=53 action=accept comment="jsn: expired DNS tcp" place-before=1
add chain=forward src-address-list=bill-expired dst-address=$portalIp action=accept comment="jsn: expired -> portal" place-before=2
add chain=forward src-address-list=bill-expired protocol=tcp action=reject reject-with=tcp-reset comment="jsn: expired block tcp" place-before=3
add chain=forward src-address-list=bill-expired action=drop comment="jsn: expired block other" place-before=4
