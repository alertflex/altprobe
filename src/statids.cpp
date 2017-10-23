/* 
 * File:   statids.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */

#include "statids.h"
#include "filters.h"

int StatIds::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    //Read filter config
    if(!fs.GetFiltersConfig()) return 0;
    
    if (sk.GetReportsPeriod() != 0 && sk.GetStateCtrl()) statids_status = 1;
    
    return 1;
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
                FlushHidsAlert();
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
    
    int counter = 0;
    
    while (!q_ids.empty()) {
        
        IdsRecord rec;
        q_ids.pop(rec);
        
        UpdateIdsCategory(rec);
        UpdateIdsEvent(rec);
            
        if (rec.ids_type == 1) {
            UpdateNidsSrcIp(rec);
            UpdateNidsDstIp(rec);
            if(rec.agr.reproduced != 0) UpdateNidsAlerts(rec);
        } else {
            UpdateHidsHostname(rec);
            UpdateHidsLocation(rec);
            if(rec.agr.reproduced != 0) UpdateHidsAlerts(rec);
        }
        
        counter = 1;
    }       
        
    if (!counter) usleep(GetGosleepTimer());
}

void StatIds::RoutineJob() {
    
    FlushNidsSrcIp();
    
    FlushNidsDstIp();
    
    FlushHidsHostname();
    
    FlushHidsLocation();
    
    FlushIdsCategory();
    
    FlushIdsEvent();
}

void StatIds::UpdateNidsSrcIp(IdsRecord r) {
    
    std::vector<NidsSrcIp>::iterator i, end;
    
    for(i = nids_srcip.begin(), end = nids_srcip.end(); i != end; ++i) {
        if (i->ref_id.compare(r.ref_id) == 0)  {  
            if (i->ip.compare(r.src_ip) == 0) {
                i->counter++;
                return;
            }
        }
    }  
    nids_srcip.push_back(NidsSrcIp(r.ref_id, r.src_ip));
}

void StatIds::FlushNidsSrcIp() {
        
    if (sk.GetStateCtrl()) {
        
        report.info = "{ \"nids_srcip\" : [ ";
        int j = 0;
        
        std::vector<NidsSrcIp>::iterator i, end;
        
        for(i = nids_srcip.begin(), end = nids_srcip.end(); i != end; ++i) {
                    
            report.info += "{ \"ref_id\": \"";
            report.info += i->ref_id;
            
            report.info += "\", \"ip\": \"";
            report.info += i->ip;
            
            report.info += "\", \"counter\": ";
            report.info += std::to_string(i->counter);
            
            report.info += ", \"time_of_survey\": \"";
            report.info += GetNodeTime();
            report.info += "\" }";
            
            if ( j < nids_srcip.size() - 1) { 
                report.info += ", "; 
                j++;
            }
        }
        report.info += " ] }";
        
        report.SetEventType(et_nids_srcip);
        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
    
clear_nids_srcip:    
    nids_srcip.clear();
}


void StatIds::UpdateNidsDstIp(IdsRecord r) {
    
    std::vector<NidsDstIp>::iterator i, end;
    
    for(i = nids_dstip.begin(), end = nids_dstip.end(); i != end; ++i) {
        if (i->ref_id.compare(r.ref_id) == 0)  {      
            if (i->ip.compare(r.dst_ip) == 0) {
                i->counter++;
                return;
            }
        }
    }  
    nids_dstip.push_back(NidsDstIp(r.ref_id, r.dst_ip));
}

void StatIds::FlushNidsDstIp() {
        
    if (sk.GetStateCtrl()) {
        
        report.info = "{ \"nids_dstip\" : [ ";
        int j = 0;
        
        std::vector<NidsDstIp>::iterator i, end;
        
        for(i = nids_dstip.begin(), end = nids_dstip.end(); i != end; ++i) {
                    
            report.info += "{ \"ref_id\": \"";
            report.info += i->ref_id;
            
            report.info += "\", \"ip\": \"";
            report.info += i->ip;
            
            report.info += "\", \"counter\": ";
            report.info += std::to_string(i->counter);
            
            report.info += ", \"time_of_survey\": \"";
            report.info += GetNodeTime();
            report.info += "\" }";
            
            if ( j < nids_dstip.size() - 1) { 
                report.info += ", "; 
                j++;
            }
        }
        report.info += " ] }";
        
        report.SetEventType(et_nids_dstip);
        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
    
clear_nids_dstip:    
    nids_dstip.clear();
}    

void StatIds::UpdateHidsHostname(IdsRecord r) {
    
    std::vector<HidsHostname>::iterator i, end;
    
    for(i = hids_hostname.begin(), end = hids_hostname.end(); i != end; ++i) {
        if (i->ref_id.compare(r.ref_id) == 0)  {      
            if (i->hostname.compare(r.hostname) == 0) {
                i->counter++;
                return;
            }
        }
    }  
    hids_hostname.push_back(HidsHostname(r.ref_id, r.hostname));
}

void StatIds::FlushHidsHostname() {
        
    if (sk.GetStateCtrl()) {
        
        report.info = "{ \"hids_hostname\" : [ ";
        int j = 0;
        
        std::vector<HidsHostname>::iterator i, end;
        
        for(i = hids_hostname.begin(), end = hids_hostname.end(); i != end; ++i) {
                    
            report.info += "{ \"ref_id\": \"";
            report.info += i->ref_id;
            
            report.info += "\", \"hostname\": \"";
            report.info += i->hostname;
            
            report.info += "\", \"counter\": ";
            report.info += std::to_string(i->counter);
            
            report.info += ", \"time_of_survey\": \"";
            report.info += GetNodeTime();
            report.info += "\" }";
            
            if ( j < hids_hostname.size() - 1) { 
                report.info += ", "; 
                j++;
            }
        }
        report.info += " ] }";
        
        report.SetEventType(et_hids_hostname);
        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
    
    
clear_hids_hostname:    
    
    hids_hostname.clear();
}

void StatIds::UpdateHidsLocation(IdsRecord r) {
    
    std::vector<HidsLocation>::iterator i, end;
    
    for(i = hids_location.begin(), end = hids_location.end(); i != end; ++i) {
        if (i->ref_id.compare(r.ref_id) == 0)  {      
            if (i->location.compare(r.location) == 0) {
                i->counter++;
                return;
            }
        }
    }  
    hids_location.push_back(HidsLocation(r.ref_id, r.location));
}

void StatIds::FlushHidsLocation() {
        
    if (sk.GetStateCtrl()) {
        
        report.info = "{ \"hids_location\" : [ ";
        int j = 0;
        
        std::vector<HidsLocation>::iterator i, end;
        
        for(i = hids_location.begin(), end = hids_location.end(); i != end; ++i) {
                    
            report.info += "{ \"ref_id\": \"";
            report.info += i->ref_id;
            
            report.info += "\", \"location\": \"";
            report.info += i->location;
            
            report.info += "\", \"counter\": ";
            report.info += std::to_string(i->counter);
            
            report.info += ", \"time_of_survey\": \"";
            report.info += GetNodeTime();
            report.info += "\" }";
            
            if ( j < hids_location.size() - 1) { 
                report.info += ", "; 
                j++;
            }
        }
        report.info += " ] }";
        
        report.SetEventType(et_hids_location);
        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
    
clear_hids_location:    
    
    hids_location.clear();
}

void StatIds::UpdateIdsCategory(IdsRecord r) {
    bool flag = false;
    
    for (string j : r.list_cats) {
    
        std::vector<IdsCategory>::iterator i, end;
        
        for(i = ids_category.begin(), end = ids_category.end(); i != end; ++i) {
            if (i->ref_id.compare(r.ref_id) == 0)  {  
                if (i->ids_cat.compare(j) == 0) {
                    i->counter++;
                    flag = true;
                }
            }
        }
        
        if (!flag) {
            ids_category.push_back(IdsCategory(r.ids_type, r.ref_id, j));
            flag = false;
        }
        
    }  
}

void StatIds::FlushIdsCategory() {
    
    if (sk.GetStateCtrl()) {
        
        report.info = "{ \"ids_cat\" : [ ";
        int j = 0;
        
        std::vector<IdsCategory>::iterator i, end;
        
        for(i = ids_category.begin(), end = ids_category.end(); i != end; ++i) {
                    
            report.info += "{ \"ref_id\": \"";
            report.info += i->ref_id;
            
            report.info += "\", \"ids_type\": ";
            report.info += std::to_string(i->ids_type);
            
            report.info += ", \"category\": \"";
            report.info += i->ids_cat;
            
            report.info += "\", \"counter\": ";
            report.info += std::to_string(i->counter);
            
            report.info += ", \"time_of_survey\": \"";
            report.info += GetNodeTime();
            report.info += "\" }";
            
            if ( j < ids_category.size() - 1) { 
                report.info += ", "; 
                j++;
            }
        }
        report.info += " ] }";
        
        report.SetEventType(et_ids_cat);
        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
    
clear_ids_category:    
    
    ids_category.clear();
}

void StatIds::UpdateIdsEvent(IdsRecord r) {
    
    std::vector<IdsEvent>::iterator i, end;
    
    for(i = ids_event.begin(), end = ids_event.end(); i != end; ++i) {
        if (i->ref_id.compare(r.ref_id) == 0)  {     
            if (i->event == r.event) {
                i->counter++;
                return;
            }  
        }
    }  
    ids_event.push_back(IdsEvent(r.ids_type, r.ref_id, r.event, r.severity, r.desc));
}

void StatIds::FlushIdsEvent() {
    
    if (sk.GetStateCtrl()) {
        
        report.info = "{ \"ids_event\" : [ ";
        int j = 0;
        
        std::vector<IdsEvent>::iterator i, end;
        
        for(i = ids_event.begin(), end = ids_event.end(); i != end; ++i) {
                    
            report.info += "{ \"ref_id\": \"";
            report.info += i->ref_id;
            
            report.info += "\", \"ids_type\": ";
            report.info += std::to_string(i->ids_type);
            
            report.info += ", \"event\": ";
            report.info += std::to_string(i->event);
            
            report.info += ", \"severity\": ";
            report.info += std::to_string(i->severity);
            
            report.info += ", \"counter\": ";
            report.info += std::to_string(i->counter);
            
            report.info += ", \"description\": \"";
            report.info += i->desc;
            
            report.info += "\", \"time_of_survey\": \"";
            report.info += GetNodeTime();
            
            report.info += "\" }";
            
            if ( j < ids_category.size() - 1) { 
                report.info += ", "; 
                j++;
            }
        }
        report.info += " ] }";
        
        report.SetEventType(et_ids_event);
        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
    
clear_ids_event:    
    
    ids_event.clear();
}

void StatIds::UpdateHidsAlerts(IdsRecord r) {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    
    for(i = hids_alerts_list.begin(), end = hids_alerts_list.end(); i != end; ++i) {
        if (i->ref_id.compare(r.ref_id) == 0)  {     
            if (i->event == r.event) {
                if (i->src_ip.compare(r.src_ip) == 0) { 
                    if (i->hostname.compare(r.hostname) == 0) { 
                        if (i->location.compare(r.location) == 0) {
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
                            }
                            return;
                        }
                    }
                }
            }  
        }
    }
new_hids_alert:
    r.count = 1;
    hids_alerts_list.push_back(r);
}

void StatIds::SendHidsAlert(std::list<IdsRecord>::iterator r, int c) {
    stringstream ss;
    
    if (sk.GetStateCtrl()) {
    
        sk.alert.ref_id = r->ref_id;
    
        sk.alert.type = "Alertflex";
        
        if (r->ids_type == 3) sk.alert.source = "FIM";
        else sk.alert.source = "HIDS";
        
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
        
        ss << "Message has been repeated ";
        ss << c;
        ss << " times";
    
        sk.alert.info = ss.str();
        
        sk.alert.event_json = "";
        
        sk.alert.status = "aggregated_new";
    
        sk.SendAlert();
    }
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

void StatIds::UpdateNidsAlerts(IdsRecord r) {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    for(i = nids_alerts_list.begin(), end = nids_alerts_list.end(); i != end; ++i) {
        if (i->ref_id.compare(r.ref_id) == 0)  {     
            if (i->event == r.event) {
                if (i->src_ip.compare(r.src_ip) == 0) { 
                    if (i->dst_ip.compare(r.dst_ip) == 0) {
                        
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
                        }
                        return;
                    }
                }
            }  
        }
    } 
new_nids_alert:
    r.count = 1;
    nids_alerts_list.push_back(r);
}

void StatIds::SendNidsAlert(std::list<IdsRecord>::iterator r, int c) {
    stringstream ss;
    
    if (sk.GetStateCtrl()) {
    
        sk.alert.ref_id = r->ref_id;
    
        sk.alert.source = "NIDS";
        sk.alert.type = "Alertflex";
    
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
    
        ss << "Message has been repeated ";
        ss << c;
        ss << " times";
    
        sk.alert.info = ss.str();
        
        sk.alert.event_json = "";
    
        sk.alert.status = "aggregated_new";
    
        sk.SendAlert();
    }
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













