/*
 *   Copyright 2021 Oleg Zharkov
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

#include "aggnet.h"

boost::lockfree::spsc_queue<string> q_agg_net{AGG_QUEUE_SIZE};

int AggNet::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    //Read filter config
    if(!fs.GetFiltersConfig()) return 0;
    
    if (!sk.GetReportsPeriod()) return 0;
    
    return 1;
}


int AggNet::Open() {
    
    if (!sk.Open()) return 0;
    
    return 1;
}

void AggNet::Close() {
    
    sk.Close();
    
}

int AggNet::Go(void) {
    
    struct timeval start, end;
    long seconds = 0;
            
    while(1) {    
        gettimeofday(&start, NULL);
        
        while (sk.GetReportsPeriod() > seconds) {
            gettimeofday(&end, NULL);
            seconds  = end.tv_sec  - start.tv_sec;
            
            ProcessNetData();
            
        }
        
        RoutineJob();
        seconds = 0;
    }
    
    return 1;
}

void AggNet::ProcessNetData() {
    
    counter = 0;

    while (!q_netstat.empty() || !q_netflow.empty()) {
	
	if (ProcessNetStat()) counter++;
        
        if (ProcessNetFlow()) counter++;
    }
    
    if (!counter) {
        
        usleep(GetGosleepTimer()*60);
    }
}

bool AggNet::ProcessNetFlow() {
    
    if (!q_netflow.empty()) {
	
	q_netflow.pop(netflow_rec);
        
        UpdateTrafficThresholds(netflow_rec);
        
        return true;
    }
    
    return false;
}


void AggNet::UpdateTrafficThresholds(Netflow nf) {
    
    std::vector<TrafficThresholds>::iterator i, end;
    
    for(i = traf_thres.begin(), end = traf_thres.end(); i != end; ++i) {
        if (i->ref_id.compare(nf.ref_id) == 0)  {      
            
            if (i->ids.compare(nf.ids) == 0)  {
                
                if ((i->ip.compare(nf.src_ip) == 0)) { 
                    
                    i->volume = i->volume + nf.bytes;
                    i->counter++;
                    
                    return;
                }
            }
        }
    }  
    
    int type_ip = IsValidIp(nf.src_ip); // check is valid ip
    if (type_ip >= 0) traf_thres.push_back(TrafficThresholds(nf.ref_id, nf.flows_type, nf.ids, nf.src_ip));
}


bool AggNet::ProcessNetStat() {
    
    if (!q_netstat.empty()) {
	
	q_netstat.pop(netstat_rec);
        
        if (UpdateNetstat(netstat_rec)) netstat_list.push_back(netstat_rec);
        
        return true;
    }
    
    return false;
}

bool AggNet::UpdateNetstat(Netstat ns) {
    
    std::vector<Netstat>::iterator i, end;
    
    for(i = netstat_list.begin(), end = netstat_list.end(); i != end; ++i) {
            
        if (i->ref_id.compare(netstat_rec.ref_id) == 0)  {      
            
            if (i->ids.compare(netstat_rec.ids) == 0)  {
                
                i->Aggregate(&netstat_rec);
                return false;
            }
        }
    }  
    
    return true;
}

void AggNet::RoutineJob() {
    
    FlushTrafficThresholds();
    
    report = "{ \"type\": \"net_stat\", \"data\" : [ ";
    
    std::vector<Netstat>::iterator it, end;
        
    for(it = netstat_list.begin(), end = netstat_list.end(); it != end; ++it) {
        
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
    
        report += "\", \"ids\": \"";
        report += it->ids;
            
        report += "\", \"invalid\": ";
        report += std::to_string(it->invalid);
            
        report += ", \"pkts\": ";
        report += std::to_string(it->pkts);
            
        report += ", \"bytes\": ";
        report += std::to_string(it->bytes);
        
        report += ", \"ethernet\": ";
        report += std::to_string(it->ethernet);
        
        report += ", \"ppp\": ";
        report += std::to_string(it->ppp);
        
        report += ", \"pppoe\": ";
        report += std::to_string(it->pppoe);
        
        report += ", \"gre\": ";
        report += std::to_string(it->gre);
        
        report += ", \"vlan\": ";
        report += std::to_string(it->vlan);
        
        report += ", \"vlan_qinq\": ";
        report += std::to_string(it->vlan_qinq);
        
        report += ", \"mpls\": ";
        report += std::to_string(it->mpls);
        
        report += ", \"ipv4\": ";
        report += std::to_string(it->ipv4);
        
        report += ", \"ipv6\": ";
        report += std::to_string(it->ipv6);
        
        report += ", \"tcp\": ";
        report += std::to_string(it->tcp);
        
        report += ", \"udp\": ";
        report += std::to_string(it->udp);
        
        report += ", \"sctp\": ";
        report += std::to_string(it->sctp);
        
        report += ", \"icmpv4\": ";
        report += std::to_string(it->icmpv4);
        
        report += ", \"icmpv6\": ";
        report += std::to_string(it->icmpv6);
        
        report += ", \"teredo\": ";
        report += std::to_string(it->teredo);
        
        report += ", \"ipv4_in_ipv6\": ";
        report += std::to_string(it->ipv4_in_ipv6);
        
        report += ", \"ipv6_in_ipv6\": ";
        report += std::to_string(it->ipv6_in_ipv6);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
        
    }
    
    report.resize(report.size() - 1);
    report += " ] }";
    
        
    q_agg_net.push(report);
    
    report.clear();    
    netstat_list.clear();
}

void AggNet::FlushTrafficThresholds() {
    
    std::vector<TrafficThresholds>::iterator i, end;
    
    boost::shared_lock<boost::shared_mutex> lock(fs.filters_update);
    
    for(i = traf_thres.begin(), end = traf_thres.end(); i != end; ++i) {
        
        if (i->ref_id.compare(fs.filter.ref_id) == 0)  { 
            
            int max_volume = fs.filter.netflow.trafficMaxVolume;
            int max_requests = fs.filter.netflow.floodMaxRequests;
            
            switch (i->type) { // 1 - suri, 2 - modsec-waf, 3 - aws-waf)
    
                case 1:
                    if (max_volume != 0 && max_volume <= i->volume) SendAlertTraffic(i);
                    break;
                case 2:
                    if (max_requests != 0 && max_requests <= i->counter) SendAlertFlood(i);
                    break;
                case 3:
                    if (max_requests != 0 && max_requests <= i->counter) SendAlertFlood(i);
                break;
            }
        }
    }
    
    traf_thres.clear();
    
}

void AggNet::SendAlertFlood(std::vector<TrafficThresholds>::iterator r) {
    
    sk.alert.ref_id = r->ref_id;
    sk.alert.sensor_id = r->ids;
    sk.alert.alert_severity = fs.filter.netflow.floodSeverity;
    sk.alert.event_severity = fs.filter.netflow.floodSeverity;
    sk.alert.alert_type = "NET";
    
    switch (r->type) { // 1 - suri, 2 - modsec-waf, 3 - aws-waf)
    
        case 2:
            sk.alert.alert_source = "ModSecurity";
            break;
        case 3:
            sk.alert.alert_source = "AwsWaf";
            break;
    }
    
    sk.alert.event_id = "10";
    sk.alert.sensor_id = r->ids;
    
    sk.alert.description = " ";
    sk.alert.action = "indef";
    sk.alert.location = "indef";
    sk.alert.info = "Flood IP has been detected";
    
    sk.alert.status = "processed";
    sk.alert.user_name = "indef";
    sk.alert.agent_name = "indef";
    sk.alert.filter = fs.filter.name;
    
    sk.alert.list_cats.push_back("flood");
    
    sk.alert.event_time = GetNodeTime();
        
    sk.alert.src_ip = r->ip;
    sk.alert.dst_ip = r->ip;
    sk.alert.src_hostname = "indef";
    sk.alert.dst_hostname = "indef";
    sk.alert.src_port = 0;
    sk.alert.dst_port = 0;
    
    sk.alert.reg_value = "indef";
    sk.alert.file_name = "indef";
	
    sk.alert.hash_md5 = "indef";
    sk.alert.hash_sha1 = "indef";
    sk.alert.hash_sha256 = "indef";
	
    sk.alert.process_id = 0;
    sk.alert.process_name = "indef";
    sk.alert.process_cmdline = "indef";
    sk.alert.process_path = "indef";
    
    sk.alert.url_hostname = "indef";
    sk.alert.url_path = "indef";
    
    sk.alert.container_id = "indef";
    sk.alert.container_name = "indef";
    
    sk.alert.cloud_instance = "indef";
    
    sk.SendAlert();
}

void AggNet::SendAlertTraffic(std::vector<TrafficThresholds>::iterator r) {
    
    sk.alert.ref_id = r->ref_id;
    sk.alert.sensor_id = r->ids;
    sk.alert.alert_severity = fs.filter.netflow.trafficSeverity;
    sk.alert.event_severity = fs.filter.netflow.trafficSeverity;
    sk.alert.alert_type = "NET";
    
    sk.alert.alert_source = "Suricata";
    
    
    sk.alert.event_id = "11";
    sk.alert.sensor_id = r->ids;
    
    sk.alert.description = " ";
    sk.alert.action = "indef";
    sk.alert.location = "indef";
    sk.alert.info = "High volume of traffic for IP has been detected";
    
    sk.alert.status = "processed";
    sk.alert.user_name = "indef";
    sk.alert.agent_name = "indef";
    sk.alert.filter = fs.filter.name;
    
    sk.alert.list_cats.push_back("traffic");
    
    sk.alert.event_time = GetNodeTime();
        
    sk.alert.src_ip = r->ip;
    sk.alert.dst_ip = r->ip;
    sk.alert.src_hostname = "indef";
    sk.alert.dst_hostname = "indef";
    sk.alert.src_port = 0;
    sk.alert.dst_port = 0;
    
    sk.alert.reg_value = "indef";
    sk.alert.file_name = "indef";
	
    sk.alert.hash_md5 = "indef";
    sk.alert.hash_sha1 = "indef";
    sk.alert.hash_sha256 = "indef";
	
    sk.alert.process_id = 0;
    sk.alert.process_name = "indef";
    sk.alert.process_cmdline = "indef";
    sk.alert.process_path = "indef";
    
    sk.alert.url_hostname = "indef";
    sk.alert.url_path = "indef";
    
    sk.alert.container_id = "indef";
    sk.alert.container_name = "indef";
    
    sk.alert.cloud_instance = "indef";
    
    sk.SendAlert();
}
