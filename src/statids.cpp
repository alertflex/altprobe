/* 
 * File:   statids.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */

#include "statids.h"

boost::lockfree::spsc_queue<string> q_stats_ids{STAT_QUEUE_SIZE};

int StatIds::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    //Read filter config
    if(!fs.GetFiltersConfig()) return 0;
    
    if (sk.GetReportsPeriod()) status = 1;
    
    return status;
}

int  StatIds::Open() {
    
    if (!sk.Open()) return 0;
    
    return 1;
}

void  StatIds::Close() {
    sk.Close();
}


int StatIds::Go(void) {
    
    struct timeval start, end;
    long seconds = 0;
    int flush_timer = 0;
        
    while(1) {    
        gettimeofday(&start, NULL);
        while (sk.GetReportsPeriod() > seconds) {
            gettimeofday(&end, NULL);
            seconds  = end.tv_sec  - start.tv_sec;
            
            ProcessStatistic();
            
            if (flush_timer < seconds) {
                flush_timer = seconds;
                mem_mon.hids_alerts_list = hids_alerts_list.size();
                FlushHidsAlert();
                mem_mon.nids_alerts_list = nids_alerts_list.size();
                FlushNidsAlert();
            }
        }
        RoutineJob();
        seconds = 0;
        flush_timer = 0;
    }
    
    return 1;
}



void StatIds::ProcessStatistic() {
    
    counter = 0;
    
    while (!q_nids.empty() || !q_hids.empty()) {
        
        if (!q_nids.empty()) {
            q_nids.pop(ids_rec);
            PushRecord();
        }
        
        if (!q_hids.empty()) {
            q_hids.pop(ids_rec);
            PushRecord();
        }
    }       
        
    if (!counter) usleep(GetGosleepTimer()*60);
}

void StatIds::PushRecord() {
    
    UpdateIdsCategory();
    UpdateIdsEvent();
        
    if (ids_rec.ids_type == 1) {
        UpdateFimFile();
        UpdateFimCause();
    }
            
    if (ids_rec.ids_type == 2) {
        UpdateHidsHostname();
        UpdateHidsLocation();
    }
        
    if (ids_rec.ids_type == 1 || ids_rec.ids_type == 2) {
        if (ids_rec.agr.reproduced != 0) UpdateHidsAlerts();
    }
        
    if (ids_rec.ids_type == 3) {
        UpdateNidsSrcIp();
        UpdateNidsDstIp();
        if(ids_rec.agr.reproduced != 0) UpdateNidsAlerts();
    } 
        
    counter++;
}

void StatIds::RoutineJob() {
    
    mem_mon.fim_file = fim_file.size();
    FlushFimFile();
    mem_mon.fim_cause = fim_cause.size();
    FlushFimCause();
    mem_mon.nids_srcip = nids_srcip.size();
    FlushNidsSrcIp();
    mem_mon.nids_dstip = nids_dstip.size();
    FlushNidsDstIp();
    mem_mon.hids_hostname = hids_hostname.size();
    FlushHidsHostname();
    mem_mon.hids_location = hids_location.size();
    FlushHidsLocation();
    mem_mon.ids_category = ids_category.size();
    FlushIdsCategory();
    mem_mon.ids_event = ids_event.size();
    FlushIdsEvent();
}

void StatIds::UpdateNidsSrcIp() {
    
    std::vector<NidsSrcIp>::iterator i, end;
    
    for(i = nids_srcip.begin(), end = nids_srcip.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {  
            if (i->ip.compare(ids_rec.src_ip) == 0) {
                i->counter++;
                return;
            }
        }
    }  
    nids_srcip.push_back(NidsSrcIp(ids_rec.ref_id, ids_rec.src_ip, ids_rec.hostname));
}

void StatIds::FlushNidsSrcIp() {
        
    report = "{ \"type\": \"nids_srcip\", \"data\" : [ ";
        
    int j = 0;
        
    std::vector<NidsSrcIp>::iterator i, end;
        
    for(i = nids_srcip.begin(), end = nids_srcip.end(); i != end; ++i) {
                    
        report += "{ \"ref_id\": \"";
        report += i->ref_id;
            
        report += "\", \"ip\": \"";
        report += i->ip;
            
        report += "\", \"agent\": \"";
        report += i->agent;
            
        report += "\", \"counter\": ";
        report += std::to_string(i->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" }";
            
        if ( j < nids_srcip.size() - 1) { 
            report += ", "; 
            j++;
        }
    }
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    nids_srcip.clear();
}


void StatIds::UpdateNidsDstIp() {
    
    std::vector<NidsDstIp>::iterator i, end;
    
    for(i = nids_dstip.begin(), end = nids_dstip.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {      
            if (i->ip.compare(ids_rec.dst_ip) == 0) {
                i->counter++;
                return;
            }
        }
    }  
    nids_dstip.push_back(NidsDstIp(ids_rec.ref_id, ids_rec.dst_ip, ids_rec.location));
}

void StatIds::FlushNidsDstIp() {
        
    report = "{ \"type\": \"nids_dstip\", \"data\": [ ";
                
    int j = 0;
    std::vector<NidsDstIp>::iterator i, end;
        
    for(i = nids_dstip.begin(), end = nids_dstip.end(); i != end; ++i) {
                    
        report += "{ \"ref_id\": \"";
        report += i->ref_id;
            
        report += "\", \"ip\": \"";
        report += i->ip;
            
        report += "\", \"agent\": \"";
        report += i->agent;
            
        report += "\", \"counter\": ";
        report += std::to_string(i->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" }";
            
        if ( j < nids_dstip.size() - 1) { 
            report += ", "; 
            j++;
        }
    }
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();    
    nids_dstip.clear();
}    

void StatIds::UpdateHidsHostname() {
    
    std::vector<HidsHostname>::iterator i, end;
    
    for(i = hids_hostname.begin(), end = hids_hostname.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {      
            if (i->hostname.compare(ids_rec.hostname) == 0) {
                i->counter++;
                return;
            }
        }
    }  
    hids_hostname.push_back(HidsHostname(ids_rec.ref_id, ids_rec.hostname));
}

void StatIds::FlushHidsHostname() {
        
    report = "{ \"type\": \"hids_hostname\", \"data\" : [ ";
        
    int j = 0;
    std::vector<HidsHostname>::iterator i, end;
        
    for(i = hids_hostname.begin(), end = hids_hostname.end(); i != end; ++i) {
                    
        report += "{ \"ref_id\": \"";
        report += i->ref_id;
            
        report += "\", \"hostname\": \"";
        report += i->hostname;
            
        report += "\", \"counter\": ";
        report += std::to_string(i->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" }";
            
        if ( j < hids_hostname.size() - 1) { 
            report += ", "; 
            j++;
        }
    }
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    hids_hostname.clear();
}

void StatIds::UpdateHidsLocation() {
    
    std::vector<HidsLocation>::iterator i, end;
    
    for(i = hids_location.begin(), end = hids_location.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {      
            if (i->location.compare(ids_rec.location) == 0) {
                if (i->agent.compare(ids_rec.hostname) == 0) {
                    i->counter++;
                    return;
                }
            }
        }
    }  
    hids_location.push_back(HidsLocation(ids_rec.ref_id, ids_rec.location, ids_rec.hostname));
}

void StatIds::FlushHidsLocation() {
        
    report = "{ \"type\": \"hids_location\", \"data\" : [ ";
        
    int j = 0;
    std::vector<HidsLocation>::iterator i, end;
        
    for(i = hids_location.begin(), end = hids_location.end(); i != end; ++i) {
                    
        report += "{ \"ref_id\": \"";
        report += i->ref_id;
            
        report += "\", \"location\": \"";
        report += i->location;
            
        report += "\", \"agent\": \"";
        report += i->agent;
            
        report += "\", \"counter\": ";
        report += std::to_string(i->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" }";
            
        if ( j < hids_location.size() - 1) { 
            report += ", "; 
            j++;
        }
    }
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    hids_location.clear();
}

void StatIds::UpdateFimCause() {
    
    std::vector<FimCause>::iterator i, end;
    
    for(i = fim_cause.begin(), end = fim_cause.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {      
            if (i->cause.compare(ids_rec.desc) == 0) {
                if (i->agent.compare(ids_rec.hostname) == 0) {
                    i->counter++;
                    return;
                }
            }
        }
    }  
    fim_cause.push_back(FimCause(ids_rec.ref_id, ids_rec.desc, ids_rec.hostname));
}

void StatIds::FlushFimCause() {
        
    report = "{ \"type\": \"fim_cause\", \"data\" : [ ";
        
    int j = 0;
    std::vector<FimCause>::iterator i, end;
        
    for(i = fim_cause.begin(), end = fim_cause.end(); i != end; ++i) {
                    
        report += "{ \"ref_id\": \"";
        report += i->ref_id;
            
        report += "\", \"cause\": \"";
        report += i->cause;
            
        report += "\", \"agent\": \"";
        report += i->agent;
            
        report += "\", \"counter\": ";
        report += std::to_string(i->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" }";
            
        if ( j < fim_cause.size() - 1) { 
            report += ", "; 
            j++;
        }
    }
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    fim_cause.clear();
}

void StatIds::UpdateFimFile() {
    
    std::vector<FimFile>::iterator i, end;
    
    for(i = fim_file.begin(), end = fim_file.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {      
            if (i->file.compare(ids_rec.location) == 0) {
                if (i->agent.compare(ids_rec.hostname) == 0) {
                    i->counter++;
                    return;
                }
            }
        }
    }  
    fim_file.push_back(FimFile(ids_rec.ref_id, ids_rec.location, ids_rec.hostname));
}

void StatIds::FlushFimFile() {
        
    report = "{ \"type\": \"fim_file\", \"data\" : [ ";
        
    int j = 0;
    std::vector<FimFile>::iterator i, end;
        
    for(i = fim_file.begin(), end = fim_file.end(); i != end; ++i) {
                    
        report += "{ \"ref_id\": \"";
        report += i->ref_id;
            
        report += "\", \"file\": \"";
        report += i->file;
            
        report += "\", \"agent\": \"";
        report += i->agent;
            
        report += "\", \"counter\": ";
        report += std::to_string(i->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" }";
            
        if ( j < fim_file.size() - 1) { 
            report += ", "; 
            j++;
        }
    }
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    fim_file.clear();
}

void StatIds::UpdateIdsCategory() {
    bool flag = false;
    
    for (string j : ids_rec.list_cats) {
    
        std::vector<IdsCategory>::iterator i, end;
        
        for(i = ids_category.begin(), end = ids_category.end(); i != end; ++i) {
            if (i->ref_id.compare(ids_rec.ref_id) == 0)  { 
                if (i->ids_type == ids_rec.ids_type) {
                    if (i->ids_cat.compare(j) == 0) {
                        if (i->agent.compare(ids_rec.hostname) == 0) {
                            i->counter++;
                            flag = true;
                        }
                    }
                }
            }
        }
        
        if (!flag) {
            ids_category.push_back(IdsCategory( ids_rec.ref_id, ids_rec.ids_type, j, ids_rec.hostname));
            flag = false;
        }
    }  
}

void StatIds::FlushIdsCategory() {
    
    report = "{ \"type\": \"ids_cat\", \"data\" : [ ";
        
    int j = 0;
    std::vector<IdsCategory>::iterator i, end;
        
    for(i = ids_category.begin(), end = ids_category.end(); i != end; ++i) {
                    
        report += "{ \"ref_id\": \"";
        report += i->ref_id;
            
        report += "\", \"ids_type\": ";
        report += std::to_string(i->ids_type);
            
        report += ", \"category\": \"";
        report += i->ids_cat;
            
        report += "\", \"agent\": \"";
        report += i->agent;
            
        report += "\", \"counter\": ";
        report += std::to_string(i->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" }";
            
        if ( j < ids_category.size() - 1) { 
            report += ", "; 
            j++;
        }
    }
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    ids_category.clear();
}

void StatIds::UpdateIdsEvent() {
    
    std::vector<IdsEvent>::iterator i, end;
    
    for(i = ids_event.begin(), end = ids_event.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {  
            if (i->ids_type == ids_rec.ids_type) {
                if (i->event == ids_rec.event) {
                    if (i->agent.compare(ids_rec.hostname) == 0) {
                        i->counter++;
                        return;
                    }
                }
            }  
        }
    } 
    
    ids_event.push_back(IdsEvent( ids_rec.ref_id, ids_rec.ids_type, ids_rec.event, ids_rec.severity, ids_rec.desc, ids_rec.hostname));
}

void StatIds::FlushIdsEvent() {
    
    report = "{ \"type\": \"ids_event\", \"data\" : [ ";
        
    int j = 0;
    std::vector<IdsEvent>::iterator i, end;
        
    for(i = ids_event.begin(), end = ids_event.end(); i != end; ++i) {
                    
        report += "{ \"ref_id\": \"";
        report += i->ref_id;
            
        report += "\", \"ids_type\": ";
        report += std::to_string(i->ids_type);
            
        report += ", \"event\": ";
        report += std::to_string(i->event);
            
        report += ", \"severity\": ";
        report += std::to_string(i->severity);
            
        report += ", \"counter\": ";
        report += std::to_string(i->counter);
            
        report += ", \"description\": \"";
        report += i->desc;
            
        report += "\", \"agent\": \"";
        report += i->agent;
            
        report += "\", \"time_of_survey\": \"";
        report += GetNodeTime();
            
        report += "\" }";
            
        if ( j < ids_category.size() - 1) { 
            report += ", "; 
            j++;
        }
    }
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    ids_event.clear();
}

void StatIds::UpdateHidsAlerts() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    
    for(i = hids_alerts_list.begin(), end = hids_alerts_list.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {     
            if (i->event == ids_rec.event) {
                if (i->hostname.compare(ids_rec.hostname) == 0) { 
                    //get current time
                    current_time = time(NULL);
                    i->count++;    
                    if ((i->alert_time + i->agr.in_period) < current_time) {
                        if (i->count >= i->agr.reproduced) {
                            SendHidsAlert(i, i->count);
                            hids_alerts_list.erase(i);
                            return;
                        }
                        else {
                            hids_alerts_list.erase(i);
                            goto new_hids_alert;
                        }
                        return;
                    }
                }
            }  
        }
    }
new_hids_alert:
    ids_rec.count = 1;
    hids_alerts_list.push_back(ids_rec);
}

void StatIds::SendHidsAlert(std::list<IdsRecord>::iterator r, int c) {
    
    sk.alert.ref_id = r->ref_id;
    
    sk.alert.source = "OSSEC";
        
    if (r->ids_type == 1) sk.alert.type = "FIM";
    else sk.alert.type = "HIDS";
        
    if (r->agr.new_event != 0) sk.alert.event = r->agr.new_event;
    else sk.alert.event = r->event;
        
    if (r->agr.new_severity != 0) sk.alert.severity = r->agr.new_severity;
    else sk.alert.severity = r->severity;
        
    copy(r->list_cats.begin(),r->list_cats.end(),back_inserter(sk.alert.list_cats));
    if (r->agr.new_category.compare("") != 0) sk.alert.list_cats.push_back(r->agr.new_category);
                
    if (r->action.compare("none") != 0) sk.alert.action = r->action;
    else sk.alert.action = "none";
        
    if (r->agr.new_description.compare("") != 0)  sk.alert.description = r->agr.new_description;
    else sk.alert.description = r->desc;
        
    sk.alert.srcip = r->src_ip;
    
    sk.alert.dstip = r->dst_ip;
        
    sk.alert.hostname = r->hostname;
        
    sk.alert.location = r->location;
        
    sk.alert.info = "Message has been repeated ";
    sk.alert.info += std::to_string(c);
    sk.alert.info += " times";
    
    sk.alert.event_json = "";
        
    sk.alert.status = "aggregated_new";
    
    sk.SendAlert();
}

void StatIds::FlushHidsAlert() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    current_time = time(NULL);
    
    for(i = hids_alerts_list.begin(), end = hids_alerts_list.end(); i != end; ++i) {
        if ((i->alert_time + i->agr.in_period) < current_time)
            hids_alerts_list.erase(i++);
    }
}

void StatIds::UpdateNidsAlerts() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    for(i = nids_alerts_list.begin(), end = nids_alerts_list.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {     
            if (i->event == ids_rec.event) {
                if (i->hostname.compare(ids_rec.hostname) == 0) { 
                    //get current time
                    current_time = time(NULL);
                    i->count++;  
                    if ((i->alert_time + i->agr.in_period) < current_time) {
                        if (i->count >= i->agr.reproduced) {
                            SendNidsAlert(i, i->count);
                            nids_alerts_list.erase(i);
                        }
                        else {
                            nids_alerts_list.erase(i);
                            goto new_nids_alert;
                        }
                        return;
                    }
                }
            }  
        }
    } 
new_nids_alert:
    ids_rec.count = 1;
    nids_alerts_list.push_back(ids_rec);
}

void StatIds::SendNidsAlert(std::list<IdsRecord>::iterator r, int c) {
    
    sk.alert.ref_id = r->ref_id;
    
    sk.alert.source = "Suricata";
    sk.alert.type = "NIDS";
    
    if (r->agr.new_event != 0) sk.alert.event = r->agr.new_event;
    else sk.alert.event = r->event;
        
    if (r->agr.new_severity != 0) sk.alert.severity = r->agr.new_severity;
    else sk.alert.severity = r->severity;
        
    copy(r->list_cats.begin(),r->list_cats.end(),back_inserter(sk.alert.list_cats));
    if (r->agr.new_category.compare("") != 0) sk.alert.list_cats.push_back(r->agr.new_category);
              
    if (r->action.compare("none") != 0) sk.alert.action = r->action;
    else sk.alert.action = "none";
        
    if (r->agr.new_description.compare("") != 0)  sk.alert.description = r->agr.new_description;
    else sk.alert.description = r->desc;
        
    sk.alert.srcip = r->src_ip;
    
    sk.alert.dstip = r->dst_ip;
    
    sk.alert.hostname = "";
        
    sk.alert.location = "";       
    
    sk.alert.info = "Message has been repeated ";
    sk.alert.info += std::to_string(c);
    sk.alert.info += " times";
    
    sk.alert.event_json = "";
    
    sk.alert.status = "aggregated_new";
    
    sk.SendAlert();
}

void StatIds::FlushNidsAlert() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    current_time = time(NULL);
    
    for(i = nids_alerts_list.begin(), end = nids_alerts_list.end(); i != end; ++i) {
        if ((i->alert_time + i->agr.in_period) < current_time)
            nids_alerts_list.erase(i++);
    }
}












