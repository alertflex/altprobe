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
                // mem_mon.waf_alerts_list = waf_alerts_list.size();
                FlushWafAlert();
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
    
    while (!q_nids.empty() || !q_hids.empty() || !q_waf.empty()) {
        
        if (!q_nids.empty()) {
            q_nids.pop(ids_rec);
            PushRecord();
        }
        
        if (!q_hids.empty()) {
            q_hids.pop(ids_rec);
            PushRecord();
        }
        
        if (!q_waf.empty()) {
            q_waf.pop(ids_rec);
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
        UpdateHidsSrcIp();
        UpdateHidsLocation();
    }
        
    if (ids_rec.ids_type == 1 || ids_rec.ids_type == 2) {
        if (ids_rec.agr.reproduced != 0) UpdateHidsAlerts();
        UpdateUserEvent();
    }
        
    if (ids_rec.ids_type == 3) {
        UpdateNidsSrcIp();
        UpdateNidsDstIp();
        if(ids_rec.agr.reproduced != 0) UpdateNidsAlerts();
    } 
    
    if (ids_rec.ids_type == 4) {
        UpdateWafSource();
        UpdateWafTarget();
        if(ids_rec.agr.reproduced != 0) UpdateWafAlerts();
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
    mem_mon.hids_srcip = hids_srcip.size();
    FlushHidsSrcIp();
    mem_mon.hids_location = hids_location.size();
    FlushHidsLocation();
    mem_mon.ids_category = ids_category.size();
    FlushIdsCategory();
    mem_mon.ids_event = ids_event.size();
    FlushIdsEvent();
    mem_mon.waf_target = waf_target.size();
    FlushWafTarget();
    mem_mon.waf_source = waf_source.size();
    FlushWafSource();
    
    FlushUserEvent();
    mem_mon.user_event = user_event.size();
}

void StatIds::UpdateNidsSrcIp() {
    
    std::vector<NidsSrcIp>::iterator i, end;
    
    for(i = nids_srcip.begin(), end = nids_srcip.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {  
            if (i->ids_name.compare(ids_rec.ids) == 0)  { 
                if (i->ip.compare(ids_rec.src_ip) == 0) {
                    i->counter++;
                    return;
                }
            }
        }
    }  
    nids_srcip.push_back(NidsSrcIp(ids_rec.ref_id, ids_rec.src_ip, ids_rec.agent, ids_rec.ids));
}

void StatIds::FlushNidsSrcIp() {
        
    report = "{ \"type\": \"nids_srcip\", \"data\" : [ ";
        
    std::vector<NidsSrcIp>::iterator it, end;
            
    for(it = nids_srcip.begin(), end = nids_srcip.end(); it != end; ++it) {
                    
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
            
        report += "\", \"ip\": \"";
        report += it->ip;
            
        report += "\", \"agent\": \"";
        report += it->agent;
        
        report += "\", \"ids\": \"";
        report += it->ids_name;
            
        report += "\", \"counter\": ";
        report += std::to_string(it->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
            
    }
    
    report.resize(report.size() - 1);
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    nids_srcip.clear();
}


void StatIds::UpdateNidsDstIp() {
    
    std::vector<NidsDstIp>::iterator i, end;
    
    for(i = nids_dstip.begin(), end = nids_dstip.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  { 
            if (i->ids_name.compare(ids_rec.ids) == 0)  { 
                if (i->ip.compare(ids_rec.dst_ip) == 0) {
                    i->counter++;
                    return;
                }
            }
        }
    }  
    nids_dstip.push_back(NidsDstIp(ids_rec.ref_id, ids_rec.dst_ip, ids_rec.location, ids_rec.ids));
}

void StatIds::FlushNidsDstIp() {
        
    report = "{ \"type\": \"nids_dstip\", \"data\": [ ";
                
    std::vector<NidsDstIp>::iterator it, end;
    
    for(it = nids_dstip.begin(), end = nids_dstip.end(); it != end; ++it) {
                    
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
            
        report += "\", \"ip\": \"";
        report += it->ip;
            
        report += "\", \"agent\": \"";
        report += it->agent;
        
        report += "\", \"ids\": \"";
        report += it->ids_name;
            
        report += "\", \"counter\": ";
        report += std::to_string(it->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
            
    }
    
    report.resize(report.size() - 1);
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();    
    nids_dstip.clear();
}   


void StatIds::UpdateWafSource() {
    
    std::vector<WafSource>::iterator i, end;
    
    for(i = waf_source.begin(), end = waf_source.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {  
            if (i->ids_name.compare(ids_rec.ids) == 0)  { 
                if (i->source.compare(ids_rec.src_ip) == 0) {
                    i->counter++;
                    return;
                }
            }
        }
    }  
    waf_source.push_back(WafSource(ids_rec.ref_id, ids_rec.src_ip, ids_rec.agent, ids_rec.ids));
}

void StatIds::FlushWafSource() {
        
    report = "{ \"type\": \"waf_source\", \"data\" : [ ";
        
    std::vector<WafSource>::iterator it, end;
            
    for(it = waf_source.begin(), end = waf_source.end(); it != end; ++it) {
                    
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
            
        report += "\", \"source\": \"";
        report += it->source;
            
        report += "\", \"agent\": \"";
        report += it->agent;
        
        report += "\", \"ids\": \"";
        report += it->ids_name;
            
        report += "\", \"counter\": ";
        report += std::to_string(it->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
            
    }
    
    report.resize(report.size() - 1);
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    waf_source.clear();
}

void StatIds::UpdateWafTarget() {
    
    std::vector<WafTarget>::iterator i, end;
    
    for(i = waf_target.begin(), end = waf_target.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {  
            if (i->ids_name.compare(ids_rec.ids) == 0)  { 
                if (i->target.compare(ids_rec.location) == 0) {
                    i->counter++;
                    return;
                }
            }
        }
    }  
    waf_target.push_back(WafTarget(ids_rec.ref_id, ids_rec.location, ids_rec.agent, ids_rec.ids));
}

void StatIds::FlushWafTarget() {
        
    report = "{ \"type\": \"waf_target\", \"data\" : [ ";
        
    std::vector<WafTarget>::iterator it, end;
            
    for(it = waf_target.begin(), end = waf_target.end(); it != end; ++it) {
                    
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
            
        report += "\", \"target\": \"";
        report += it->target;
            
        report += "\", \"agent\": \"";
        report += it->agent;
        
        report += "\", \"ids\": \"";
        report += it->ids_name;
            
        report += "\", \"counter\": ";
        report += std::to_string(it->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
            
    }
    
    report.resize(report.size() - 1);
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    waf_target.clear();
}

void StatIds::UpdateHidsSrcIp() {
    
    std::vector<HidsSrcIp>::iterator i, end;
    
    for(i = hids_srcip.begin(), end = hids_srcip.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  { 
            if (i->ip.compare(ids_rec.src_ip) == 0) {
                if (i->agent.compare(ids_rec.agent) == 0) {
                    i->counter++;
                    return;
                }
            }
        }
    }  
    hids_srcip.push_back(HidsSrcIp(ids_rec.ref_id, ids_rec.src_ip, ids_rec.agent));
}

void StatIds::FlushHidsSrcIp() {
        
    report = "{ \"type\": \"hids_srcip\", \"data\" : [ ";
        
    std::vector<HidsSrcIp>::iterator it, end;
            
    for(it = hids_srcip.begin(), end = hids_srcip.end(); it != end; ++it) {
                    
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
            
        report += "\", \"ip\": \"";
        report += it->ip;
        
        report += "\", \"agent\": \"";
        report += it->agent;
            
        report += "\", \"counter\": ";
        report += std::to_string(it->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
            
    }
    
    report.resize(report.size() - 1);
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    hids_srcip.clear();
}

void StatIds::UpdateHidsLocation() {
    
    std::vector<HidsLocation>::iterator i, end;
    
    for(i = hids_location.begin(), end = hids_location.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {      
            if (i->location.compare(ids_rec.location) == 0) {
                if (i->agent.compare(ids_rec.agent) == 0) {
                    i->counter++;
                    return;
                }
            }
        }
    }  
    hids_location.push_back(HidsLocation(ids_rec.ref_id, ids_rec.location, ids_rec.agent));
}

void StatIds::FlushHidsLocation() {
        
    report = "{ \"type\": \"hids_location\", \"data\" : [ ";
        
    std::vector<HidsLocation>::iterator it, end;
           
    for(it = hids_location.begin(), end = hids_location.end(); it != end; ++it) {
                    
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
            
        report += "\", \"location\": \"";
        report += it->location;
            
        report += "\", \"agent\": \"";
        report += it->agent;
            
        report += "\", \"counter\": ";
        report += std::to_string(it->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
            
    }
    
    report.resize(report.size() - 1);
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
                if (i->agent.compare(ids_rec.agent) == 0) {
                    i->counter++;
                    return;
                }
            }
        }
    }  
    fim_cause.push_back(FimCause(ids_rec.ref_id, ids_rec.desc, ids_rec.agent));
}

void StatIds::FlushFimCause() {
        
    report = "{ \"type\": \"fim_cause\", \"data\" : [ ";
        
    std::vector<FimCause>::iterator it, end;
      
    for(it = fim_cause.begin(), end = fim_cause.end(); it != end; ++it) {
                    
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
            
        report += "\", \"cause\": \"";
        report += it->cause;
            
        report += "\", \"agent\": \"";
        report += it->agent;
            
        report += "\", \"counter\": ";
        report += std::to_string(it->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
            
    }
    
    report.resize(report.size() - 1);
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
                if (i->agent.compare(ids_rec.agent) == 0) {
                    i->counter++;
                    return;
                }
            }
        }
    }  
    fim_file.push_back(FimFile(ids_rec.ref_id, ids_rec.location, ids_rec.agent));
}

void StatIds::FlushFimFile() {
        
    report = "{ \"type\": \"fim_file\", \"data\" : [ ";
        
    std::vector<FimFile>::iterator it, end;
            
    for(it = fim_file.begin(), end = fim_file.end(); it != end; ++it) {
                    
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
            
        report += "\", \"file\": \"";
        report += it->file;
            
        report += "\", \"agent\": \"";
        report += it->agent;
            
        report += "\", \"counter\": ";
        report += std::to_string(it->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
            
    }
    
    report.resize(report.size() - 1);
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
                if (i->ids_cat.compare(j) == 0) {
                            
                    if ((i->ids_type == 3) || (i->ids_type == 4)) {
                        
                        if (i->ids_name.compare(ids_rec.ids) == 0) {
                            i->counter++;
                            flag = true;
                        }
                    } else {
                            
                        if (i->agent.compare(ids_rec.agent) == 0) {
                            i->counter++;
                            flag = true;
                        }
                    }
                   
                }
            }
        }
        
        if (!flag) {
            ids_category.push_back(IdsCategory( ids_rec.ref_id, ids_rec.ids_type, j, ids_rec.agent, ids_rec.ids));
            flag = false;
        }
    }  
}

void StatIds::FlushIdsCategory() {
    
    report = "{ \"type\": \"ids_cat\", \"data\" : [ ";
        
    std::vector<IdsCategory>::iterator it, end;
            
    for(it = ids_category.begin(), end = ids_category.end(); it != end; ++it) {
                    
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
            
        report += "\", \"ids_type\": ";
        report += std::to_string(it->ids_type);
            
        report += ", \"category\": \"";
        report += it->ids_cat;
            
        report += "\", \"agent\": \"";
        report += it->agent;
        
        report += "\", \"ids\": \"";
        report += it->ids_name;
            
        report += "\", \"counter\": ";
        report += std::to_string(it->counter);
            
        report += ", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } ,";
            
    }
    
    report.resize(report.size() - 1);
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    ids_category.clear();
}

void StatIds::UpdateIdsEvent() {
    
    std::vector<IdsEvent>::iterator i, end;
    
    for(i = ids_event.begin(), end = ids_event.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {  
            
            if (i->event == ids_rec.event) {
                
                if ((i->ids_type == 3) || (i->ids_type == 4)) {
                        
                    if (i->ids_name.compare(ids_rec.ids) == 0) {
                        i->counter++;
                        return;
                    }
                        
                } else {
                        
                    if (i->agent.compare(ids_rec.agent) == 0) {
                        i->counter++;
                        return;
                    }
                }
            }
                
        }
    } 
    
    ids_event.push_back(IdsEvent( ids_rec.ref_id, ids_rec.ids_type, ids_rec.event, ids_rec.severity, ids_rec.desc, ids_rec.agent, ids_rec.ids));
}

void StatIds::FlushIdsEvent() {
    
    report = "{ \"type\": \"ids_event\", \"data\" : [ ";
        
    std::vector<IdsEvent>::iterator it, end;
            
    for(it = ids_event.begin(), end = ids_event.end(); it != end; ++it) {
                    
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
            
        report += "\", \"ids_type\": ";
        report += std::to_string(it->ids_type);
            
        report += ", \"event\": ";
        report += std::to_string(it->event);
            
        report += ", \"severity\": ";
        report += std::to_string(it->severity);
            
        report += ", \"counter\": ";
        report += std::to_string(it->counter);
            
        report += ", \"description\": \"";
        report += it->desc;
            
        report += "\", \"agent\": \"";
        report += it->agent;
        
        report += "\", \"ids\": \"";
        report += it->ids_name;
            
        report += "\", \"time_of_survey\": \"";
        report += GetNodeTime();
            
        report += "\" } ,";
            
    }
    
    report.resize(report.size() - 1);
    report += " ] }";
        
    q_stats_ids.push(report);
    
    report.clear();
    ids_event.clear();
}

void StatIds::UpdateUserEvent() {
    
    std::vector<UserEvent>::iterator i, end;
    
    for(i = user_event.begin(), end = user_event.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {  
            
            if (i->event == ids_rec.event) {
                
                if (i->agent.compare(ids_rec.agent) == 0) {
                    
                    if (i->user.compare(ids_rec.user) == 0) {
                        
                        if (i->ip.compare("") == 0 || i->ip.compare(ids_rec.src_ip) == 0) {
                            i->counter++;
                            return;
                        }
                    }
                }
            }
        }
    } 
    
    if (ids_rec.user.compare("") != 0)
        user_event.push_back(UserEvent( ids_rec.ref_id, ids_rec.event, ids_rec.severity, ids_rec.desc, ids_rec.agent, ids_rec.user, ids_rec.src_ip));
}

void StatIds::FlushUserEvent() {
    
    report = "{ \"type\": \"user_event\", \"data\" : [ ";
        
    std::vector<UserEvent>::iterator it, end;
            
    for(it = user_event.begin(), end = user_event.end(); it != end; ++it) {
                    
        report += "{ \"ref_id\": \"";
        report += it->ref_id;
            
        report += "\", \"event\": ";
        report += std::to_string(it->event);
            
        report += ", \"severity\": ";
        report += std::to_string(it->severity);
            
        report += ", \"counter\": ";
        report += std::to_string(it->counter);
            
        report += ", \"description\": \"";
        report += it->desc;
            
        report += "\", \"agent\": \"";
        report += it->agent;
        
        report += "\", \"user\": \"";
        report += it->user;
        
        report += "\", \"ip\": \"";
        report += it->ip;
            
        report += "\", \"time_of_survey\": \"";
        report += GetNodeTime();
            
        report += "\" } ,";
            
    }
    
    report.resize(report.size() - 1);
    report += " ] }";
     
    //SysLog((char*) report.c_str());
    q_stats_ids.push(report);
    
    report.clear();
    user_event.clear();
}

void StatIds::UpdateHidsAlerts() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    
    for(i = hids_alerts_list.begin(), end = hids_alerts_list.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  { 
            if (i->agent.compare(ids_rec.agent) == 0) {
                
                if (i->event == ids_rec.event) {
                
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
    
    sk.alert.source = "Wazuh";
        
    if (r->ids_type == 1) sk.alert.type = "FILE";
    else sk.alert.type = "HOST";
    
    sk.alert.srcip = r->src_ip;
    
    sk.alert.dstip = r->dst_ip;
    
    sk.alert.dstport = 0;
    sk.alert.srcport = 0;
    sk.alert.dstagent = r->agent;
    sk.alert.srcagent = "none";
    sk.alert.user = "none";
    sk.alert.score = 0;
    
    sk.alert.sensor = r->ids;
    sk.alert.filter = fs.filter.desc;
    sk.alert.event_time = GetNodeTime();
        
    if (r->rsp.new_event != 0) sk.alert.event = r->rsp.new_event;
    else sk.alert.event = r->event;
        
    if (r->rsp.new_severity != 0) sk.alert.severity = r->rsp.new_severity;
    else sk.alert.severity = r->severity;
        
    copy(r->list_cats.begin(),r->list_cats.end(),back_inserter(sk.alert.list_cats));
    if (r->rsp.new_category.compare("") != 0) sk.alert.list_cats.push_back(r->rsp.new_category);
                
    if (r->rsp.new_description.compare("") != 0)  sk.alert.description = r->rsp.new_description;
    else sk.alert.description = r->desc;
    
    if (r->rsp.profile.compare("none") != 0) sk.alert.action = r->rsp.profile;
    else sk.alert.action = "none";
    
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
            if (i->ids.compare(ids_rec.ids) == 0)  {
                if (i->event == ids_rec.event) {
                    
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
    sk.alert.type = "NET";
    
    sk.alert.srcip = r->src_ip;
    
    sk.alert.dstip = r->dst_ip;
    
    sk.alert.dstport = 0;
    sk.alert.srcport = 0;
    sk.alert.dstagent = r->agent;
    sk.alert.srcagent = "none";
    sk.alert.user = "none";
    sk.alert.score = 0;
    
    sk.alert.sensor = r->ids;
    sk.alert.filter = fs.filter.desc;
    sk.alert.event_time = GetNodeTime();
    
    if (r->rsp.new_event != 0) sk.alert.event = r->rsp.new_event;
    else sk.alert.event = r->event;
        
    if (r->rsp.new_severity != 0) sk.alert.severity = r->rsp.new_severity;
    else sk.alert.severity = r->severity;
        
    copy(r->list_cats.begin(),r->list_cats.end(),back_inserter(sk.alert.list_cats));
    if (r->rsp.new_category.compare("") != 0) sk.alert.list_cats.push_back(r->rsp.new_category);
              
    if (r->rsp.profile.compare("none") != 0) sk.alert.action = r->rsp.profile;
    else sk.alert.action = "none";
        
    if (r->rsp.new_description.compare("") != 0)  sk.alert.description = r->rsp.new_description;
    else sk.alert.description = r->desc;
    
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


void StatIds::UpdateWafAlerts() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    for(i = waf_alerts_list.begin(), end = waf_alerts_list.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  { 
            if (i->ids.compare(ids_rec.ids) == 0)  {
                if (i->event == ids_rec.event) {
                    
                    //get current time
                    current_time = time(NULL);
                    i->count++;  
                    if ((i->alert_time + i->agr.in_period) < current_time) {
                        if (i->count >= i->agr.reproduced) {
                            SendWafAlert(i, i->count);
                            waf_alerts_list.erase(i);
                        }
                        else {
                            waf_alerts_list.erase(i);
                            goto new_waf_alert;
                        }
                        return;
                    }
                }
            }  
        }
    } 
new_waf_alert:
    ids_rec.count = 1;
    waf_alerts_list.push_back(ids_rec);
}

void StatIds::SendWafAlert(std::list<IdsRecord>::iterator r, int c) {
    
    sk.alert.ref_id = r->ref_id;
    
    sk.alert.source = "Modsecurity";
    sk.alert.type = "NET";
    
    sk.alert.srcip = r->src_ip;
    
    sk.alert.dstip = r->dst_ip;
    
    sk.alert.dstport = 0;
    sk.alert.srcport = 0;
    sk.alert.dstagent = r->agent;
    sk.alert.srcagent = "none";
    sk.alert.user = "none";
    sk.alert.score = 0;
    
    sk.alert.sensor = r->ids;
    sk.alert.filter = fs.filter.desc;
    sk.alert.event_time = GetNodeTime();
    
    if (r->rsp.new_event != 0) sk.alert.event = r->rsp.new_event;
    else sk.alert.event = r->event;
        
    if (r->rsp.new_severity != 0) sk.alert.severity = r->rsp.new_severity;
    else sk.alert.severity = r->severity;
        
    copy(r->list_cats.begin(),r->list_cats.end(),back_inserter(sk.alert.list_cats));
    if (r->rsp.new_category.compare("") != 0) sk.alert.list_cats.push_back(r->rsp.new_category);
              
    if (r->rsp.profile.compare("none") != 0) sk.alert.action = r->rsp.profile;
    else sk.alert.action = "none";
        
    if (r->rsp.new_description.compare("") != 0)  sk.alert.description = r->rsp.new_description;
    else sk.alert.description = r->desc;
    
    sk.alert.location = "";       
    
    sk.alert.info = "Message has been repeated ";
    sk.alert.info += std::to_string(c);
    sk.alert.info += " times";
    
    sk.alert.event_json = "";
    
    sk.alert.status = "aggregated_new";
    
    sk.SendAlert();
}

void StatIds::FlushWafAlert() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    current_time = time(NULL);
    
    for(i = waf_alerts_list.begin(), end = waf_alerts_list.end(); i != end; ++i) {
        if ((i->alert_time + i->agr.in_period) < current_time)
            waf_alerts_list.erase(i++);
    }
}












