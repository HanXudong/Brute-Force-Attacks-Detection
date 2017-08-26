--拉取数据到自己的项目空间(第二题<网页风险分类>数据量大不建议复制到自己的项目空间)
create table if not exists adl_tianchi_portscan_trainset_connect_part1 as 
select * from odps_tc_257100_f673506e024.adl_tianchi_portscan_trainset_connect_part1;

create table if not exists adl_tianchi_portscan_trainset_login_part1 as 
select * from odps_tc_257100_f673506e024.adl_tianchi_portscan_trainset_login_part1;

create table if not exists adl_tianchi_portscan_trainset_label_part1 as 
select * from odps_tc_257100_f673506e024.adl_tianchi_portscan_trainset_label_part1;

create table if not exists adl_tianchi_portscan_testset_connect_part1 as 
select * from odps_tc_257100_f673506e024.adl_tianchi_portscan_testset_connect_part1;

--横纵扫描攻击特征生成
drop table if exists train_portscan_x_feature;
create table if not exists  train_portscan_x_feature as 
select 
    source_ip,
    count(distinct client_ip) as ip_count, 
    count(distinct client_port) as port_count
from adl_tianchi_portscan_trainset_connect_part1 where ds>="20170523" and ds<="20170605" group by source_ip;

drop table if exists test_portscan_x_feature;
create table if not exists  test_portscan_x_feature as 
select 
    source_ip,
    count(distinct client_ip) as ip_count, 
    count(distinct client_port) as port_count
from adl_tianchi_portscan_trainset_connect_part1 where ds>="20170530" and ds<="20170612" group by source_ip;

--常用IP特征生成
drop table if exists train_portscan_login_feature;
create table if not exists  train_portscan_login_feature as 
select 
    source_ip,
    client_ip,
    client_port,
    count(*) as login_count
from adl_tianchi_portscan_trainset_login_part1 where ds>="20170523" and ds<="20170605" group by source_ip,client_ip,client_port;

drop table if exists test_portscan_login_feature;
create table if not exists  test_portscan_login_feature as 
select 
    source_ip,
    client_ip,
    client_port,
    count(*) as login_count
from adl_tianchi_portscan_trainset_login_part1 where ds>="20170530" and ds<="20170612" group by source_ip,client_ip,client_port;

--第三、四周连接数据连接上两个特征表
--待完成
drop table if exists feature_3;
create table if not exists feature_3 as
select 
    a.*,
    b.login_count,
    case when (c.ip_count/c.port_count) > (c.port_count/c.ip_count) then (c.ip_count/c.port_count) else (c.port_count/c.ip_count) end as max_x
from 
    adl_tianchi_portscan_trainset_connect_part1 a
left outer join train_portscan_login_feature b on a.client_port=b.client_port and a.source_ip=b.source_ip and a.client_ip=b.client_ip
left outer join train_portscan_x_feature c on a.source_ip=c.source_ip
where a.ds>="20170606" and a.ds<="20170612";

drop table if exists feature_4;
create table if not exists feature_4 as
select 
    a.*,
    b.login_count,
    case when (c.ip_count/c.port_count) > (c.port_count/c.ip_count) then (c.ip_count/c.port_count) else (c.port_count/c.ip_count) end as max_x
from 
    adl_tianchi_portscan_trainset_connect_part1 a
left outer join test_portscan_login_feature b on a.client_port=b.client_port and a.source_ip=b.source_ip and a.client_ip=b.client_ip
left outer join test_portscan_x_feature c on a.source_ip=c.source_ip
where a.ds>="20170613" and a.ds<="20170619";

--特征工程
drop table if exists portscan_feature;
create table if not exists  portscan_feature as 
select 
    client_port,--云主机端口
    source_ip,--访客IP
    ds,--访问日期
    cast(client_port as bigint) as port,--云主机端口（bigint型）
    count(client_ip) as sip_client_ip_n, --连接云主机次数
    count(distinct client_ip) as sip_client_ip_dn_cnt, --连接云主机类别数
    sum(counts) as  sip_connect_n, --总连接次数
    max(counts) as   sip_connect_n_max,--10秒内最大连接次数
    avg(counts) as   sip_connect_n_avg,--10秒内平均连接次数
    count(distinct hashuserid) as sip_hashuserid_dn, --连接云主机拥有者个数
    avg(max_x) as  maxx,
    (sum(login_count)/sum(counts)) as RatioLog
from feature_3
group by client_port,source_ip,ds;

drop table if exists portscan_train;
create table if not exists  portscan_train as 
select a.*,case when b.client_port is null then 0 else 1 end as lable 
from portscan_feature a 
left outer join adl_tianchi_portscan_trainset_label_part1 b 
on a.client_port=b.client_port and a.source_ip=b.source_ip and a.ds=b.ds;

drop table if exists portscan_test;
create table if not exists  portscan_test as 
select 
    client_port,--云主机端口
    source_ip,--访客IP
    ds,--访问日期
    cast(client_port as bigint) as port,--云主机端口（bigint型）
    count(client_ip) as sip_client_ip_n, --连接云主机次数
    count(distinct client_ip) as sip_client_ip_dn_cnt, --连接云主机类别数
    sum(counts) as  sip_connect_n, --总连接次数
    max(counts) as   sip_connect_n_max,--10秒内最大连接次数
    avg(counts) as   sip_connect_n_avg,--10秒内平均连接次数
    count(distinct hashuserid) as sip_hashuserid_dn, --连接云主机拥有者个数
    avg(max_x) as  maxx,
    (sum(login_count)/sum(counts)) as RatioLog
from feature_4
group by client_port,source_ip,ds;

--模型训练
drop offlinemodel if exists  GBDT_test_model_v1;
drop table if exists GBDT_test_model_Importance;

PAI -name gbdt_lr -project algo_public -DfeatureSplitValueMaxSize="500" -DrandSeed="0" -Dshrinkage="0.05" -DmaxLeafCount="32" -DlabelColName="lable" 
-DinputTableName="portscan_train" 
-DoutputImportanceTableName="GBDT_test_model_Importance" 
-DminLeafSampleCount="500" -DsampleRatio="0.6" -DmaxDepth="6" -DmetricType="0" 
-DmodelName="GBDT_test_model_v1" 
-DfeatureRatio="0.6" -DtestRatio="0" 
-DfeatureColNames="sip_client_ip_n,sip_client_ip_dn_cnt,sip_connect_n,sip_connect_n_max,sip_hashuserid_dn,sip_connect_n_avg,port,maxx,RatioLog" 
-DtreeCount="250";

--模型预测
drop table if exists portscan_pre_result;
PAI -name prediction -project algo_public -DdetailColName="prediction_detail" -DappendColNames="client_port,source_ip,ds" 
-DmodelName="GBDT_test_model_v1" 
-DitemDelimiter="," -DresultColName="prediction_result" -Dlifecycle="28" 
-DoutputTableName="portscan_pre_result" 
-DscoreColName="prediction_score" -DkvDelimiter=":" 
-DfeatureColNames="port,sip_client_ip_n,sip_client_ip_dn_cnt,sip_connect_n,sip_connect_n_max,sip_hashuserid_dn,sip_connect_n_avg,maxx,RatioLog" 
-DinputTableName="portscan_test" 
-DenableSparse="false";

--生成测试答案
drop table if exists portscan_answer_4;
create table if not exists portscan_answer_4 as
select distinct client_port,source_ip,ds from portscan_pre_result where prediction_result=1;

--evaluation
select P,R,sorce
from
{
    SELECT SUM(IF(!ISNULL(A.source_ip) AND !ISNULL(B.source_ip), 1, 0)) / SUM(if(!ISNULL(A.source_ip), 1, 0)) AS P,
           SUM(IF(!ISNULL(A.source_ip) AND !ISNULL(B.source_ip), 1, 0)) / SUM(if(!ISNULL(B.source_ip), 1, 0)) AS R
    FROM portscan_answer_4 A
    FULL OUTER JOIN adl_tianchi_portscan_trainset_label_part1 B
    ON A.client_port == B.client_port AND A.source_ip  == B.source_ip AND A.ds == B.ds
    where  A.client_port == j and A.ds == i
}


declare @i int
declare @port varchar(50)
declare @next int  
set @port = '21,22,3306,3389'
set @next=1
set @i=20170613
while @i<=20170619
begin
    while @next<=dbo.Get_StrArrayLength(@str,',')
        begin
        --端口号
        insert into EvaluationSorce((dbo.Get_StrArrayStrOfIndex(@str,',',@next)) 
            select 4*P*R/(P+3R) AS sorce 
                from 
                {
                    SELECT SUM(IF(!ISNULL(A.source_ip) AND !ISNULL(B.source_ip), 1, 0)) / SUM(if(!ISNULL(A.source_ip), 1, 0)) AS P,
                           SUM(IF(!ISNULL(A.source_ip) AND !ISNULL(B.source_ip), 1, 0)) / SUM(if(!ISNULL(B.source_ip), 1, 0)) AS R
                    FROM portscan_answer_4 A
                    FULL OUTER JOIN adl_tianchi_portscan_trainset_label_part1 B
                    ON A.client_port == B.client_port AND A.source_ip  == B.source_ip AND A.ds == B.ds
                    where  A.client_port == (dbo.Get_StrArrayStrOfIndex(@str,',',@next) and A.ds == @i
                }C
            where EvaluationSorce.ds == @i
        set @next=@next+1
    end
set @i=@i+1
end

--生成提交答案
--drop table if exists tianchi_portscan_answer;
--create table if not exists tianchi_portscan_answer as
--select distinct client_port,source_ip,ds from portscan_pre_result where prediction_result=1;

--查看提交个数
--select client_port,count(1) from  tianchi_portscan_answer group by client_port;


















