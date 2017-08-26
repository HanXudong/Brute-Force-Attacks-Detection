
create table if not exists trainset_connect_part1 as 
select * from odps_tc_257100_f673506e024.adl_tianchi_portscan_trainset_connect_part1;

create table if not exists trainset_label_part1 as 
select * from odps_tc_257100_f673506e024.adl_tianchi_portscan_trainset_label_part1;

create table if not exists testset_connect_part1 as 
select * from odps_tc_257100_f673506e024.adl_tianchi_portscan_testset_connect_part1;

drop table if exists portscan_feature;
create table if not exists  portscan_feature as 
select 
client_port,
source_ip,
ds,
cast(client_port as bigint) as port,
count(client_ip) as sip_client_ip_n, --连接云主机次数
count(distinct client_ip) as sip_client_ip_dn_cnt, --连接云主机类别数
sum(counts) as  sip_connect_n, --总连接次数
max(counts) as   sip_connect_n_max,--10秒内最大连接次数
avg(counts) as   sip_connect_n_avg,--10秒内平均连接次数
count(distinct hashuserid) as sip_hashuserid_dn --连接云主机拥有者个数
from trainset_connect_part1 where ds>="20170606" and ds<="20170612" group by client_port,source_ip,ds
;