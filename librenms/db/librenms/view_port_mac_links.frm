TYPE=VIEW
query=select `p`.`port_id` AS `port_id`,`arp`.`id` AS `ipv4_mac_id`,`rp`.`port_id` AS `remote_port_id` from (((`librenms`.`ports` `p` join `librenms`.`ipv4_mac` `arp` on(`p`.`port_id` = `arp`.`port_id` and `arp`.`mac_address` <> `p`.`ifPhysAddress`)) join `librenms`.`ipv4_addresses` `a` on(`a`.`ipv4_address` = `arp`.`ipv4_address`)) join `librenms`.`ports` `rp` on(`a`.`port_id` = `rp`.`port_id` and `arp`.`mac_address` = `rp`.`ifPhysAddress`)) where `arp`.`mac_address` not in (\'000000000000\',\'ffffffffffff\')
md5=605692259971f50738609763dce64174
updatable=1
algorithm=0
definer_user=librenms
definer_host=%
suid=2
with_check_option=0
timestamp=0001737485850670850
create-version=2
source=-- Gets a list of port IDs for devices linked by MAC address\n            SELECT\n              p.port_id\n              ,arp.id as ipv4_mac_id\n              ,rp.port_id as remote_port_id\n            FROM\n              ports p\n              -- Find all ARP entries for this port, excluding the static entries for the local IP\n              JOIN ipv4_mac arp\n                ON p.port_id=arp.port_id\n                  AND arp.mac_address <> p.ifPhysAddress\n              -- Find all IPv4 addresses on other devices that have the same IP as the ARP entry\n              JOIN ipv4_addresses a\n                ON a.ipv4_address=arp.ipv4_address\n              -- Find the matching port if the MAC address matches\n              JOIN\n                ports rp ON a.port_id=rp.port_id\n                  AND arp.mac_address=rp.ifPhysAddress\n              WHERE\n                arp.mac_address NOT IN (\'000000000000\', \'ffffffffffff\')
client_cs_name=utf8mb4
connection_cl_name=utf8mb4_unicode_ci
view_body_utf8=select `p`.`port_id` AS `port_id`,`arp`.`id` AS `ipv4_mac_id`,`rp`.`port_id` AS `remote_port_id` from (((`librenms`.`ports` `p` join `librenms`.`ipv4_mac` `arp` on(`p`.`port_id` = `arp`.`port_id` and `arp`.`mac_address` <> `p`.`ifPhysAddress`)) join `librenms`.`ipv4_addresses` `a` on(`a`.`ipv4_address` = `arp`.`ipv4_address`)) join `librenms`.`ports` `rp` on(`a`.`port_id` = `rp`.`port_id` and `arp`.`mac_address` = `rp`.`ifPhysAddress`)) where `arp`.`mac_address` not in (\'000000000000\',\'ffffffffffff\')
mariadb-version=101110
