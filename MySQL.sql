
create table if not exists trainset_connect_part1 as 
select * from odps_tc_257100_f673506e024.adl_tianchi_portscan_trainset_connect_part1;

create table if not exists trainset_label_part1 as 
select * from odps_tc_257100_f673506e024.adl_tianchi_portscan_trainset_label_part1;

create table if not exists testset_connect_part1 as 
select * from odps_tc_257100_f673506e024.adl_tianchi_portscan_testset_connect_part1;
