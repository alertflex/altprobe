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
            
            ProcessNetstat();
            
        }
        
        RoutineJob();
        seconds = 0;
    }
    
    return 1;
}

void AggNet::ProcessNetstat() {
    
    counter = 0;

    while (!q_netstat.empty()) {
	
	q_netstat.pop(netstat_rec);
        
        if (UpdateNetstat(netstat_rec)) netstat_list.push_back(netstat_rec);
        
        counter++;
    }
    
    if (!counter) {
        
        usleep(GetGosleepTimer()*60);
    }
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
