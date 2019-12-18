/* 
 * File:   statflow.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */

#include "statflows.h"

boost::lockfree::spsc_queue<string> q_stats_flow{STAT_QUEUE_SIZE};

int StatFlows::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    //Read filter config
    if(!fs.GetFiltersConfig()) return 0;
    
    if (sk.GetReportsPeriod() != 0) status = 1;
    
    return status;
}


int  StatFlows::Open(int mode, int pid) {
    
    if (!sk.Open()) return 0;
    
    return 1;
}

void  StatFlows::Close() {
    
    sk.Close();
    
}

int StatFlows::Go(void) {
    
    struct timeval start, end;
    long seconds = 0;
    int flush_timer = 0;
        
    while(1) {    
        gettimeofday(&start, NULL);
        while (sk.GetReportsPeriod() > seconds) {
            gettimeofday(&end, NULL);
            seconds  = end.tv_sec  - start.tv_sec;
            
            ProcessFlows();
            
            if (flush_timer < seconds) {
                flush_timer = seconds;
            }
        }
        RoutineJob();
        seconds = 0;
        flush_timer = 0;
    }
    
    return 1;
}



void StatFlows::ProcessFlows() {

    int counter = 0;
    
    ProcessTraffic();
    
    while (!q_flows.empty()) {
        
        IncrementEventsCounter();
        
        q_flows.pop(flows_rec);
        
        if (flows_rec.flows_type == 3) {
            UpdateSshSessions(); 
        }
        
        counter++;
    }   

    if (!counter) usleep(GetGosleepTimer()*60);
}

void StatFlows::RoutineJob() {
    
    FlushSshSessions();
    FlushTraffic();
}

void StatFlows::ProcessTraffic() {
    
    while (!q_netstat.empty()) {
        
        IncrementEventsCounter();
        
        q_netstat.pop(traffic_rec);
        
        if (UpdateTraffic(traffic_rec)) traffics.push_back(traffic_rec);
    }
}

bool StatFlows::UpdateTraffic(Traffic t) {
    
    std::vector<Traffic>::iterator i, end;
    
    for(i = traffics.begin(), end = traffics.end(); i != end; ++i) {
            
        if (i->ref_id.compare(traffic_rec.ref_id) == 0)  {      
            
            if (i->ids.compare(traffic_rec.ids) == 0)  {
                
                i->Aggregate(&traffic_rec);
                return false;
            }
        }
    }  
    
    return true;
}

void StatFlows::FlushTraffic() {
    
    
    report = "{ \"type\": \"flows_traffic\", \"data\" : [ ";
    
    std::vector<Traffic>::iterator it, end;
        
    for(it = traffics.begin(), end = traffics.end(); it != end; ++it) {
        
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
    
        
    q_stats_flow.push(report);
    
    report.clear();    
    traffics.clear();
}


void StatFlows::UpdateSshSessions() {
    
    std::vector<SshSession>::iterator i, end;
    
    for(i = ssh_sessions.begin(), end = ssh_sessions.end(); i != end; ++i) {
        if (i->ref_id.compare(flows_rec.ref_id) == 0)  { 
            if (i->ids.compare(flows_rec.ids) == 0)  {
                if ((i->src_ip.compare(flows_rec.src_ip) == 0) && (i->dst_ip.compare(flows_rec.dst_ip) == 0)) { 
                    if ((i->client.compare(flows_rec.info1) == 0) && (i->server.compare(flows_rec.info2) == 0)) { 
                        i->counter++;
                        return;
                    }
                }
            }
        }
    }  
    
    ssh_sessions.push_back(SshSession(flows_rec.ref_id, flows_rec.ids, flows_rec.info1, flows_rec.info2, flows_rec.src_ip, flows_rec.dst_ip, flows_rec.src_agent, flows_rec.dst_agent));
}

void StatFlows::FlushSshSessions() {
    
    report = "{ \"type\": \"flows_ssh\", \"data\" : [ ";
        
    std::vector<SshSession>::iterator it, end;
        
    for(it = ssh_sessions.begin(), end = ssh_sessions.end(); it != end; ++it) {
            
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
        
        report += "\", \"ids\": \"";
        report += it->ids;
            
        report += "\", \"client_sw\": \"";
        report += it->client;
            
        report += "\", \"server_sw\": \"";
        report += it->server;
            
        report += "\", \"srcip\": \"";
        report += it->src_ip;
            
        report += "\", \"dstip\": \"";
        report += it->dst_ip;
            
        report += "\", \"src_agent\": \"";
        report += it->src_agent;
            
        report += "\", \"dst_agent\": \"";
        report += it->dst_agent;
                
        report += "\", \"counter\": ";
        report += std::to_string(it->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
            
    }
    
    report.resize(report.size() - 1);
    report += " ] }";
        
    q_stats_flow.push(report);
    
    report.clear();
    ssh_sessions.clear();
    
}




