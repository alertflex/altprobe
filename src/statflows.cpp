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


int  StatFlows::Open() {
    
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
                FlushThresholds();
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
        
        switch(flows_rec.flows_type) {
            case 1:
                UpdateThresholds();
                UpdateCountries();
                UpdateApplications();
                break;
            case 2:
                UpdateSshSessions(); 
                break;
            default:
                break;
        }
        
        counter++;
    }   

    if (!counter) usleep(GetGosleepTimer()*60);
}

void StatFlows::RoutineJob() {
    
    mem_mon.countries = countries.size();
    FlushCountries();
    mem_mon.applications = applications.size();
    FlushApplications();
    mem_mon.ssh_sessions = ssh_sessions.size();
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

void StatFlows::UpdateApplications() {
    
    bool src = false;
    bool dst = false;
    std::vector<Application>::iterator i, end;
    
    for(i = applications.begin(), end = applications.end(); i != end; ++i) {
        if (i->ref_id.compare(flows_rec.ref_id) == 0)  { 
            if (i->ids.compare(flows_rec.ids) == 0)  {
                if (i->app.compare(flows_rec.info1) == 0) {
                
                    if (i->agent.compare(flows_rec.src_agent) == 0) {
                        i->counter = i->counter + flows_rec.bytes;
                        src = true;
                        continue;
                    }
            
                    if (i->agent.compare(flows_rec.dst_agent) == 0) {
                        i->counter = i->counter + flows_rec.bytes;
                        dst = true;
                        continue;
                    }
                }
            }
        }
    }
    
    if (src || dst) return;
    
    if (flows_rec.dst_agent.compare("ext_net") != 0) applications.push_back(Application(flows_rec.ref_id, flows_rec.ids, flows_rec.info1, flows_rec.dst_agent, flows_rec.bytes));
    if (flows_rec.src_agent.compare("ext_net") != 0) applications.push_back(Application(flows_rec.ref_id, flows_rec.ids, flows_rec.info1, flows_rec.src_agent, flows_rec.bytes));
}

void StatFlows::FlushApplications() {
        
    report = "{ \"type\": \"flows_app\", \"data\" : [ ";
        
    std::vector<Application>::iterator it, end;
        
    for(it = applications.begin(), end = applications.end(); it != end; ++it) {
            
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
        
        report += "\", \"ids\": \"";
        report += it->ids;
            
        report += "\", \"app\": \"";
        report += it->app;
            
        report += "\", \"agent\": \"";
        report += it->agent;
                
        report += "\", \"traffic\": ";
        report += std::to_string(it->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
    }
    
    report.resize(report.size() - 1);
    report += " ] }";
        
    q_stats_flow.push(report);
    
    report.clear();
    applications.clear();
}


void StatFlows::UpdateCountries() {
    
    bool flag_src = false, flag_dst = false, flag_both = false;
    unsigned long traf;
    
    if (flows_rec.src_country.compare(flows_rec.dst_country) == 0) flag_both = true;
    
    std::vector<Country>::iterator i, end;
    
    for(i = countries.begin(), end = countries.end(); i != end; ++i) {
        
        if (i->ref_id.compare(flows_rec.ref_id) == 0)  { 
            if (i->ids.compare(flows_rec.ids) == 0)  { 
                if (i->country.compare(flows_rec.src_country) == 0) { 
                    i->counter = i->counter + flows_rec.bytes;
                    flag_src =true;
                }
            
                if (!(flag_both && flag_src))
                    if (i->country.compare(flows_rec.dst_country) == 0) {
                        i->counter = i->counter + flows_rec.bytes;
                        flag_dst = true;
                    }
        
                if (flag_src && flag_dst) return;
                if (flag_src && flag_both) return;
            }
        }
    }  
    
    if (!flag_src) {
        countries.push_back(Country(flows_rec.ref_id, flows_rec.ids, flows_rec.src_country, flows_rec.bytes));
    }
        
    if (!flag_dst && !flag_both) {
        countries.push_back(Country(flows_rec.ref_id, flows_rec.ids, flows_rec.dst_country, flows_rec.bytes));
    }
}

void StatFlows::FlushCountries() {
    
    report = "{ \"type\": \"flows_country\", \"data\" : [ ";
        
    std::vector<Country>::iterator it, end;
        
    for(it = countries.begin(), end = countries.end(); it != end; ++it) {
            
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
        
        report += "\", \"ids\": \"";
        report += it->ids;
            
        report += "\", \"country\": \"";
        report += it->country;
                
        report += "\", \"traffic\": ";
        report += std::to_string(it->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
    
    }
    
    report.resize(report.size() - 1);
    report += " ] }";
        
    q_stats_flow.push(report);
    
    report.clear();
    countries.clear();
    
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

void StatFlows::UpdateThresholds() {
    std::vector<Threshold*>::iterator i, end;
        
    boost::shared_lock<boost::shared_mutex> lock(fs.filters_update);
    
    for ( i = fs.filter.traf.th.begin(), end = fs.filter.traf.th.end(); i != end; ++i ) {
        
        bool dest = IsIPInRange(flows_rec.dst_ip, (*i)->host, (*i)->element);
        
        bool source = IsIPInRange(flows_rec.src_ip, (*i)->host, (*i)->element);
        
        if (dest || source) {
        
            if (!(*i)->parameter.compare(flows_rec.info1) || !(*i)->parameter.compare("all")) {
            
                (*i)->value_count = (*i)->value_count + flows_rec.bytes;
            }
        }
    }
}

void StatFlows::FlushThresholds() {
    std::vector<Threshold*>::iterator i, end;
    
    boost::shared_lock<boost::shared_mutex> lock(fs.filters_update);
    
    for ( i = fs.filter.traf.th.begin(), end = fs.filter.traf.th.end(); i != end; ++i ) CheckThresholds(*i);
}


void StatFlows::CheckThresholds(Threshold* th) {
    
    time_t current_time = time(NULL);
    
    if  ((th->value_count > th->value_max) && (th->value_max != 0)) SendAlert(th, true);
    
    if ((th->trigger_time + th->agr.in_period) <= current_time) {
       
        if ((th->value_count < th->value_min) && (th->value_min != 0)) SendAlert(th, false);
        else th->Reset();
    }
}
    
void StatFlows::SendAlert(Threshold* th, bool type_alert) {
    
    if (type_alert) {
        sk.alert.description = "Traffic has been reached max limit. ";
    } else { 
        sk.alert.description = "Traffic has been reached min limit. ";
    }        
            
    sk.alert.ref_id  = fs.filter.ref_id;
    sk.alert.source = "Netflow";
    sk.alert.type = "NET";
    
    sk.alert.score = 0;
    sk.alert.dstip = "";
    sk.alert.srcip = "";
    sk.alert.dstport = 0;
    sk.alert.srcport = 0;
    sk.alert.dstagent = "none";
    sk.alert.srcagent = "none";
    sk.alert.user = "none";
    
    string strNodeId(node_id);
    sk.alert.sensor = strNodeId;
    sk.alert.filter = fs.filter.desc;
    sk.alert.event_time = GetNodeTime();
        
    if ( th->rsp.new_event != 0) sk.alert.event = th->rsp.new_event;
    else sk.alert.event = 1;
    
    if ( th->rsp.new_severity != 0) sk.alert.severity = th->rsp.new_severity;
    else sk.alert.severity = 2;
    
    if (th->rsp.new_category.compare("") != 0) sk.alert.list_cats.push_back(th->rsp.new_category);
    else sk.alert.list_cats.push_back("traffic threshold");
    
    if (th->rsp.new_description.compare("") != 0)  sk.alert.description = th->rsp.new_description;
    else sk.alert.description = "traffic threshold";
        
    if (th->rsp.profile.compare("none") != 0) sk.alert.action = th->rsp.profile;
    else sk.alert.action = "none";
    
    // hostname location 
    sk.alert.location = th->host;
        
    sk.alert.info = "\"traffic counter\":";
    sk.alert.info += std::to_string(th->value_count);
    if (type_alert) {
        sk.alert.info += ", \"max limit\":";
        sk.alert.info += std::to_string(th->value_max);
    } else { 
        sk.alert.info += ", \"min limit\":";
        sk.alert.info += std::to_string(th->value_min);
    } 
    sk.alert.info += ", \"app_proto\": \"";
    sk.alert.info += th->parameter;
    sk.alert.info += "\", \"for period in sec\": ";
    sk.alert.info += std::to_string(th->agr.in_period);
        
    sk.alert.event_json = "";
        
    sk.alert.status = "aggregated_new";
    sk.SendAlert();
        
    th->Reset();
}




