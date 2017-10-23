/* 
 * File:   statflow.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */

#include "statflow.h"


int StatFlow::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    //Read filter config
    if(!fs.GetFiltersConfig()) return 0;
    
    if (sk.GetReportsPeriod() != 0 && sk.GetStateCtrl()) statflow_status = 1;
    
    return 1;
}


int  StatFlow::Open() {
    
    if (!sk.Open()) return 0;
    
    return 1;
}

void  StatFlow::Close() {
    
    sk.Close();
    
}

int StatFlow::Go(void) {
    
    struct timeval start, end;
    long seconds = 0;
    int flush_timer = 0;
        
    while(1) {    
        gettimeofday(&start, NULL);
        while (sk.GetReportsPeriod() > seconds) {
            gettimeofday(&end, NULL);
            seconds  = end.tv_sec  - start.tv_sec;
            
            ProcessTraffic();
            
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



void StatFlow::ProcessTraffic() {

    int counter = 0;
    
    while (!q_netflow.empty()) {
        
        NetflowRecord rec;
        q_netflow.pop(rec);
        
        UpdateThresholds(rec);
        
        UpdateConversation(rec);
        UpdateCountries(rec);
        UpdateApplications(rec);
        UpdateProtocols(rec);
        UpdateTraffic(rec);   
        
        counter = 1;
    }       
        
    if (!counter) usleep(GetGosleepTimer());
}

void StatFlow::RoutineJob() {
    
    FlushConversation();
    FlushCountries();
    FlushApplications();
    FlushProtocols();
    FlushTraffic();
}

void StatFlow::UpdateConversation(NetflowRecord r) {
    
    std::vector<NetflowConversation>::iterator i, end;
    
    for(i = flow_conv.begin(), end = flow_conv.end(); i != end; ++i) {
        if (i->ref_id.compare(r.ref_id) == 0)  {      
            if ((i->src_ip.compare(r.src_ip) == 0) && (i->dst_ip.compare(r.dst_ip) == 0)) { 
                i->bytes = i->bytes + r.bytes;
                return;
            }
            else {
                if ((i->src_ip.compare(r.dst_ip) == 0) && (i->dst_ip.compare(r.src_ip) == 0)) { 
                    i->bytes = i->bytes + r.bytes;
                    return;
                }
            }
        }
    }  
    
    flow_conv.push_back(NetflowConversation(r.ref_id, r.src_ip, r.dst_ip, r.bytes));
    
}

bool convSort(NetflowConversation left, NetflowConversation right)
{
    return left.bytes > right.bytes;
 
    return 0;
} 

void StatFlow::FlushConversation() {
    
    if (sk.GetStateCtrl()) {
        report.info = "{ \"netflow_talkers\" : [ ";
        
        
        std::sort(flow_conv.begin(), flow_conv.end(), convSort);
        
        std::vector<NetflowConversation>::iterator it, end;
        
        int i = 0;
        int j = 0;
        for(it = flow_conv.begin(), end = flow_conv.end(); it != end && i < fs.filter.traffic.top_talkers; ++it, i++) {
            
            report.info += "{ \"ref_id\": \"";
            report.info += it->ref_id;
            
            report.info += "\", \"srcip\": \"";
            report.info += it->src_ip;
            
            report.info += "\", \"dstip\": \"";
            report.info += it->dst_ip;
            
            report.info += "\", \"traffic\": ";
            report.info += std::to_string(it->bytes);
            
            report.info += ", \"time_of_survey\": \"";
            report.info += GetNodeTime();
            report.info += "\" }";
            
            if ( j < flow_conv.size() - 1) {
                report.info += ", "; 
                j++;
            }
        }
        report.info += " ] }";
        
        report.SetEventType(et_flow_talkers);
        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
    
    flow_conv.clear();
    
}

void StatFlow::UpdateApplications(NetflowRecord r) {
    
    std::vector<NetflowApplications>::iterator i, end;
        
    for(i = flow_appl.begin(), end = flow_appl.end(); i != end; ++i) {
        if (i->ref_id.compare(r.ref_id) == 0)  {     
            if (i->application.compare(r.app_proto) == 0) {
                i->bytes = i->bytes + r.bytes;
                return;
            }
        }
    }  
    
    flow_appl.push_back(NetflowApplications(r.ref_id, r.app_proto, r.bytes));
}

void StatFlow::FlushApplications() {
        
    if (sk.GetStateCtrl()) {
        report.info = "{ \"netflow_appl\" : [ ";
        
        std::vector<NetflowApplications>::iterator i, end;
        
        int j = 0;
        for(i = flow_appl.begin(), end = flow_appl.end(); i != end; ++i) {
            
            report.info += "{ \"ref_id\": \"";
            report.info += i->ref_id;
            
            report.info += "\", \"application\": \"";
            report.info += i->application;
                
            report.info += "\", \"traffic\": ";
            report.info += std::to_string(i->bytes);
            
            report.info += ", \"time_of_survey\": \"";
            report.info += GetNodeTime();
            report.info += "\" }";
            
            if ( j < flow_appl.size() - 1) {
                report.info += ", "; 
                j++;
            }
        }
        report.info += " ] }";
        
        report.SetEventType(et_flow_appl);
        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
    
    flow_appl.clear();
}

void StatFlow::UpdateProtocols(NetflowRecord r) {
    
    std::vector<NetflowProtocols>::iterator i, end;
        
    for(i = flow_proto.begin(), end = flow_proto.end(); i != end; ++i) {
        if (i->ref_id.compare(r.ref_id) == 0)  {     
            if (i->protocol.compare(r.proto) == 0) {
                i->bytes = i->bytes + r.bytes;
                return;
            }
        }
    }  
    
    flow_proto.push_back(NetflowProtocols(r.ref_id, r.proto, r.bytes));
}

void StatFlow::FlushProtocols() {
        
    if (sk.GetStateCtrl()) {
        report.info = "{ \"netflow_proto\" : [ ";
        
        std::vector<NetflowProtocols>::iterator i, end;
        
        int j = 0;
        for(i = flow_proto.begin(), end = flow_proto.end(); i != end; ++i) {
            
            report.info += "{ \"ref_id\": \"";
            report.info += i->ref_id;
            
            report.info += "\", \"protocol\": \"";
            report.info += i->protocol;
                
            report.info += "\", \"traffic\": ";
            report.info += std::to_string(i->bytes);
            
            report.info += ", \"time_of_survey\": \"";
            report.info += GetNodeTime();
            report.info += "\" }";
            
            if ( j < flow_proto.size() - 1) {
                report.info += ", "; 
                j++;
            }
        }
        report.info += " ] }";
        
        report.SetEventType(et_flow_proto);
        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
    
    flow_proto.clear();
}

void StatFlow::UpdateCountries(NetflowRecord r) {
    
    bool flag_src = false, flag_dst = false, flag_both = false;
    unsigned long traf;
    
    if (r.src_country.compare(r.dst_country) == 0) flag_both = true;
    
    std::vector<NetflowCountries>::iterator i, end;
    
    for(i = flow_countries.begin(), end = flow_countries.end(); i != end; ++i) {
        
        if (i->ref_id.compare(r.ref_id) == 0)  { 
            if (i->country.compare(r.src_country) == 0) { 
                i->bytes = i->bytes + r.bytes;
                flag_src =true;
            }
            
            if (!(flag_both && flag_src))
                if (i->country.compare(r.dst_country) == 0) {
                    i->bytes = i->bytes + r.bytes;
                    flag_dst = true;
                }
        
            if (flag_src && flag_dst) return;
            if (flag_src && flag_both) return;
        }
    }  
    
    if (!flag_src) {
        flow_countries.push_back(NetflowCountries(r.ref_id, r.src_country, r.bytes));
    }
        
    if (!flag_dst && !flag_both) {
        flow_countries.push_back(NetflowCountries(r.ref_id, r.dst_country, r.bytes));
    }
}

void StatFlow::FlushCountries() {
    
    if (sk.GetStateCtrl()) {
        report.info = "{ \"netflow_countries\" : [ ";
        
        std::vector<NetflowCountries>::iterator i, end;
        
        int j = 0;
        for(i = flow_countries.begin(), end = flow_countries.end(); i != end; ++i) {
            
            report.info += "{ \"ref_id\": \"";
            report.info += i->ref_id;
            
            report.info += "\", \"country\": \"";
            report.info += i->country;
                
            report.info += "\", \"traffic\": ";
            report.info += std::to_string(i->bytes);
            
            report.info += ", \"time_of_survey\": \"";
            report.info += GetNodeTime();
            report.info += "\" }";
            
            if ( j < flow_countries.size() - 1) {
                report.info += ", "; 
                j++;
            }
        }
        report.info += " ] }";
        
        report.SetEventType(et_flow_countries);
        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
    
    flow_countries.clear();
    
}

void StatFlow::UpdateTraffic(NetflowRecord r) {
    
    std::vector<Traffic>::iterator i, end;
    
    for(i = flow_traffic.begin(), end = flow_traffic.end(); i != end; ++i) {
        
            
        if (i->ref_id.compare(r.ref_id) == 0)  { 
            
            i->bytes = i->bytes + r.bytes;
            
            return;
        }
        
    }  
    flow_traffic.push_back(Traffic(r.ref_id, r.bytes));
}

void StatFlow::FlushTraffic() {
        
    if (sk.GetStateCtrl()) {
        
        report.info = "{ \"netflow_traffic\" : [ ";
        
        std::vector<Traffic>::iterator i, end;
        
        int j = 0;
        for(i = flow_traffic.begin(), end = flow_traffic.end(); i != end; ++i) {
        
            report.info += "{ \"ref_id\": \"";
            report.info += i->ref_id;
            report.info += "\", \"traffic\": ";
            report.info += std::to_string(i->bytes);
            
            report.info += ", \"time_of_survey\": \"";
            report.info += GetNodeTime();
            report.info += "\" }";
            
            if ( j < flow_traffic.size() - 1) {
                report.info += ", "; 
                j++;
            }
        }
        report.info += " ] }";
        
        report.SetEventType(et_flow_traffic);
        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
    
    flow_traffic.clear();
}


void StatFlow::UpdateThresholds(NetflowRecord r) {
    std::vector<Threshold*>::iterator i, end;
    unsigned long tmp;
    
    for ( i = fs.filter.traffic.th.begin(), end = fs.filter.traffic.th.end(); i != end; ++i ) {
        
        if (!(*i)->ip.compare(r.dst_ip) || !(*i)->ip.compare(r.src_ip)) {
        
            if (!(*i)->app_proto.compare(r.app_proto) || !(*i)->app_proto.compare("all")) {
            
                (*i)->traffic_count = (*i)->traffic_count + r.bytes;
            }
        }
    }
}

void StatFlow::FlushThresholds() {
    std::vector<Threshold*>::iterator i, end;
    
    for ( i = fs.filter.traffic.th.begin(), end = fs.filter.traffic.th.end(); i != end; ++i ) CheckThresholds(*i);
}


void StatFlow::CheckThresholds(Threshold* th) {
    
    time_t current_time = time(NULL);
    
    if  ((th->traffic_count > th->traffic_max) && (th->traffic_max != 0)) SendAlert(th, true);
    
    if ((th->trigger_time + th->agr.in_period) <= current_time) {
       
        if ((th->traffic_count < th->traffic_min) && (th->traffic_min != 0)) SendAlert(th, false);
        else th->Reset();
    }
}
    
void StatFlow::SendAlert(Threshold* th, bool type_alert) {
    
    stringstream ss;
    
    if (sk.GetStateCtrl()) {
    
        if (type_alert) {
            sk.alert.description = "Traffic has been reached max limit. ";
        } else { 
            sk.alert.description = "Traffic has been reached min limit. ";
        }        
            
        sk.alert.ref_id  = fs.filter.ref_id;
        sk.alert.source = "NET";
        sk.alert.dstip = "";
        sk.alert.srcip = "";
        string strNodeId(node_id);
        sk.alert.hostname = strNodeId;
        sk.alert.type = "Alertflex";
        
        if ( th->agr.new_event != 0) sk.alert.event = th->agr.new_event;
        else sk.alert.event = 1;
    
        if ( th->agr.new_severity != 0) sk.alert.severity = th->agr.new_severity;
        else sk.alert.severity = 2;
    
        if (th->agr.new_category.compare("") != 0) sk.alert.list_cats.push_back(th->agr.new_category);
        else sk.alert.list_cats.push_back("traffic threshold");
        
        if (th->action.compare("none") != 0) sk.alert.action = th->action;
        else sk.alert.action = "none";
        
        // hostname location 
        ss << "ip: ";
        ss << th->ip;
                
        sk.alert.location = ss.str();
        
        ss.str("");
    
        ss << "\"traffic counter\":";
        ss << th->traffic_count;
        if (type_alert) {
            ss << ", \"max limit\":";
            ss << th->traffic_max;
        } else { 
            ss << ", \"min limit\":";
            ss << th->traffic_min;
        } 
        ss << ", \"app_proto\": \"";
        ss << th->app_proto;
        ss << "\", \"for period in sec\": ";
        ss << th->agr.in_period;
        
        sk.alert.info = ss.str();
        
        sk.alert.event_json = "";
        
        sk.alert.status = "aggregated_new";
        sk.SendAlert();
        
        th->Reset();
    
    }
}




