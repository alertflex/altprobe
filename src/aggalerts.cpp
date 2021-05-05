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

#include "aggalerts.h"

boost::lockfree::spsc_queue<string> q_agg_alerts{AGG_QUEUE_SIZE};

int AggAlerts::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    //Read filter config
    if(!fs.GetFiltersConfig()) return 0;
    
    if (!sk.GetReportsPeriod()) return 0;
    
    return status;
}

int  AggAlerts::Open() {
    
    if (!sk.Open()) return 0;
    
    return 1;
}

void  AggAlerts::Close() {
    sk.Close();
}


int AggAlerts::Go(void) {
    
    struct timeval start, end;
    long seconds = 0;
            
    while(1) {    
        
        gettimeofday(&start, NULL);
        while (sk.GetReportsPeriod() > seconds) {
            gettimeofday(&end, NULL);
            seconds  = end.tv_sec  - start.tv_sec;
            
            ProcessAlerts();
            
            ResetCrsAlert();
            ResetHidsAlert();
            ResetNidsAlert();
            ResetWafAlert();
        }
        
        RoutineJob();
        seconds = 0;
        
    }
    
    return 1;
}

void AggAlerts::ProcessAlerts() {
    
    counter = 0;
    
    while (!q_crs.empty() || !q_hids.empty() || !q_nids.empty() || !q_waf.empty()) {
        
        if (!q_crs.empty()) {
            q_crs.pop(ids_rec);
            PushRecord();
            counter++;
        }
        
        if (!q_hids.empty()) {
            q_hids.pop(ids_rec);
            PushRecord();
            counter++;
        }
        
        if (!q_nids.empty()) {
            q_nids.pop(ids_rec);
            PushRecord();
            counter++;
        }
        
        if (!q_waf.empty()) {
            q_waf.pop(ids_rec);
            PushRecord();
            counter++;
        }
    }       
        
    if (!counter) {
        
        usleep(GetGosleepTimer()*60);
    }
}

void AggAlerts::PushRecord() {
    
    if (ids_rec.ids_type == 1 || ids_rec.ids_type == 2) {
        if (ids_rec.agr.reproduced != 0) UpdateHidsAlerts();
        
        if (ids_rec.severity == 0) hids_stat.s0_counter++;
        if (ids_rec.severity == 1) hids_stat.s1_counter++;
        if (ids_rec.severity == 2) hids_stat.s2_counter++;
        if (ids_rec.severity == 3) hids_stat.s3_counter++;
        
        if (ids_rec.filter) hids_stat.filter_counter++;
        
    }
        
    if (ids_rec.ids_type == 3) {
        if(ids_rec.agr.reproduced != 0) UpdateNidsAlerts();
        
        if (ids_rec.severity == 0) nids_stat.s0_counter++;
        if (ids_rec.severity == 1) nids_stat.s1_counter++;
        if (ids_rec.severity == 2) nids_stat.s2_counter++;
        if (ids_rec.severity == 3) nids_stat.s3_counter++;
        
        if (ids_rec.filter) nids_stat.filter_counter++;
    } 
    
    if (ids_rec.ids_type == 4) {
        if(ids_rec.agr.reproduced != 0) UpdateCrsAlerts();
        
        if (ids_rec.severity == 0) crs_stat.s0_counter++;
        if (ids_rec.severity == 1) crs_stat.s1_counter++;
        if (ids_rec.severity == 2) crs_stat.s2_counter++;
        if (ids_rec.severity == 3) crs_stat.s3_counter++;
        
        if (ids_rec.filter) crs_stat.filter_counter++;
        
    } 
    
    if (ids_rec.ids_type == 5) {
        if(ids_rec.agr.reproduced != 0) UpdateWafAlerts();
        
        if (ids_rec.severity == 0) waf_stat.s0_counter++;
        if (ids_rec.severity == 1) waf_stat.s1_counter++;
        if (ids_rec.severity == 2) waf_stat.s2_counter++;
        if (ids_rec.severity == 3) waf_stat.s3_counter++;
        
        if (ids_rec.filter) crs_stat.filter_counter++;
        
    } 
}

void AggAlerts::RoutineJob() {
    
    stringstream ss;
    
    ss << "{ \"type\": \"node_alerts\", \"data\": { \"ref_id\": \"";
    ss << fs.filter.ref_id;
    
    ss << "\", \"crs_agg\": ";
    ss << to_string(crs_stat.agg_counter);
        
    ss << ", \"crs_filter\": ";
    ss << to_string(crs_stat.filter_counter);
        
    ss << ", \"crs_s0\": ";
    ss << to_string(crs_stat.s0_counter);
        
    ss << ", \"crs_s1\": ";
    ss << to_string(crs_stat.s1_counter);
    
    ss << ", \"crs_s2\": ";
    ss << to_string(crs_stat.s2_counter);
    
    ss << ", \"crs_s3\": ";
    ss << to_string(crs_stat.s3_counter);
    
    ss << ", \"hids_agg\": ";
    ss << to_string(hids_stat.agg_counter);
        
    ss << ", \"hids_filter\": ";
    ss << to_string(hids_stat.filter_counter);
        
    ss << ", \"hids_s0\": ";
    ss << to_string(hids_stat.s0_counter);
        
    ss << ", \"hids_s1\": ";
    ss << to_string(hids_stat.s1_counter);
    
    ss << ", \"hids_s2\": ";
    ss << to_string(hids_stat.s2_counter);
    
    ss << ", \"hids_s3\": ";
    ss << to_string(hids_stat.s3_counter);
    
    ss << ", \"nids_agg\": ";
    ss << to_string(nids_stat.agg_counter);
        
    ss << ", \"nids_filter\": ";
    ss << to_string(nids_stat.filter_counter);
        
    ss << ", \"nids_s0\": ";
    ss << to_string(nids_stat.s0_counter);
        
    ss << ", \"nids_s1\": ";
    ss << to_string(nids_stat.s1_counter);
    
    ss << ", \"nids_s2\": ";
    ss << to_string(nids_stat.s2_counter);
    
    ss << ", \"nids_s3\": ";
    ss << to_string(nids_stat.s3_counter);
    
    ss << ", \"waf_agg\": ";
    ss << to_string(waf_stat.agg_counter);
    
    ss << ", \"waf_filter\": ";
    ss << to_string(waf_stat.filter_counter);
        
    ss << ", \"waf_s0\": ";
    ss << to_string(waf_stat.s0_counter);
        
    ss << ", \"waf_s1\": ";
    ss << to_string(waf_stat.s1_counter);
    
    ss << ", \"waf_s2\": ";
    ss << to_string(waf_stat.s2_counter);
    
    ss << ", \"waf_s3\": ";
    ss << to_string(waf_stat.s3_counter);
    
    ss << ", \"time_of_survey\": \"";
    ss << GetNodeTime();
    ss << "\" } }";
        
    q_agg_alerts.push(ss.str());
    
    ss.str("");
    ss.clear();
    
    crs_stat.Reset();
    hids_stat.Reset();
    nids_stat.Reset();
    waf_stat.Reset();
}

void AggAlerts::UpdateCrsAlerts() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    for(i = crs_alerts_list.begin(), end = crs_alerts_list.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  { 
            if (i->event.compare(ids_rec.event) == 0) {
                if (i->container.compare("indef") == 0 || i->container.compare(ids_rec.container) == 0) {
                    if (i->match.compare(ids_rec.match) == 0) {
                        
                        //get current time
                        current_time = time(NULL);
                        
                        if ((i->alert_time + i->agr.in_period) >= current_time) {
                            
                            i->count++;  
                            
                            if (i->count >= i->agr.reproduced) {
                                SendCrsAlert(i, i->count);
                                crs_alerts_list.erase(i);
                            }
                        
                        } else {
                                
                            crs_alerts_list.erase(i);
                            goto new_crs_alert;
                        }
                        
                        return;
                    }
                }
            }  
        }
    } 
new_crs_alert:
    crs_stat.agg_counter++;
    ids_rec.count = 1;
    crs_alerts_list.push_back(ids_rec);
}

void AggAlerts::SendCrsAlert(std::list<IdsRecord>::iterator r, int c) {
    
    sk.alert.ref_id =  r->ref_id;
    sk.alert.sensor_id = r->ids;
        
    if (r->rsp.new_severity != 0) sk.alert.alert_severity = r->rsp.new_severity;
    else sk.alert.alert_severity = r->severity;
        
    if (r->rsp.new_source.compare("indef") != 0)  sk.alert.alert_source = r->rsp.new_source;
    else sk.alert.alert_source = "Falco";
    
    if (r->rsp.new_type.compare("indef") != 0) sk.alert.alert_type = r->rsp.new_type;
    else sk.alert.alert_type = "HOST";
    
    sk.alert.event_severity = 0;
    
    if (r->rsp.new_event.compare("indef") != 0) sk.alert.event_id = r->rsp.new_event;
    else sk.alert.event_id = r->event;
    
    if (r->rsp.new_description.compare("indef") != 0)  sk.alert.description = r->rsp.new_description;
    else sk.alert.description = r->desc;
    
    if (r->rsp.profile.compare("indef") != 0) sk.alert.action = r->rsp.profile;
    else sk.alert.action = "indef";
    
    sk.alert.location = "indef";
    
    sk.alert.info = "Message has been repeated ";
    sk.alert.info += std::to_string(c);
    sk.alert.info += " times";
    
    sk.alert.status = "aggregated";
    sk.alert.user_name = "indef";
    sk.alert.agent_name = "indef";
    sk.alert.filter = fs.filter.desc;
    
    copy(r->list_cats.begin(),r->list_cats.end(),back_inserter(sk.alert.list_cats));
    if (r->rsp.new_category.compare("indef") != 0) sk.alert.list_cats.push_back(r->rsp.new_category);
    
    sk.alert.event_time = GetNodeTime();
    sk.alert.event_json = "indef";
    
    sk.alert.src_ip = "indef";
    sk.alert.dst_ip = "indef";
    sk.alert.src_hostname = "indef";
    sk.alert.dst_hostname = r->agent;
    sk.alert.src_port = 0;
    sk.alert.dst_port = 0;
    
    sk.alert.file_name = "indef";
    sk.alert.file_path = "indef";
	
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
        
    sk.SendAlert();
}

void AggAlerts::ResetCrsAlert() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    current_time = time(NULL);
    
    for(i = crs_alerts_list.begin(), end = crs_alerts_list.end(); i != end; ++i) {
        if ((i->alert_time + i->agr.in_period) < current_time)
            crs_alerts_list.erase(i++);
    }
}

void AggAlerts::UpdateHidsAlerts() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    
    for(i = hids_alerts_list.begin(), end = hids_alerts_list.end(); i != end; ++i) {
        
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  {
            
            if (i->event.compare(ids_rec.event) == 0) {
               
                if (i->agent.compare("indef") == 0 || i->agent.compare(ids_rec.agent) == 0) {
                    
                    if (i->match.compare(ids_rec.match) == 0) {
                
                        current_time = time(NULL);
                           
                        if ((i->alert_time + i->agr.in_period) >= current_time) {
                            
                            i->count++; 
                            
                            if (i->count >= i->agr.reproduced) {
                                SendHidsAlert(i, i->count);
                                hids_alerts_list.erase(i);
                            }
                            
                        } else {
                            
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
    hids_stat.agg_counter++;
    ids_rec.count = 1;
    hids_alerts_list.push_back(ids_rec);
}

void AggAlerts::SendHidsAlert(std::list<IdsRecord>::iterator r, int c) {
    
    sk.alert.ref_id = r->ref_id;
    sk.alert.sensor_id = r->ids;
        
    if (r->rsp.new_severity != 0) sk.alert.alert_severity = r->rsp.new_severity;
    else sk.alert.alert_severity = r->severity;
        
    if (r->rsp.new_source.compare("indef") != 0)  sk.alert.alert_source = r->rsp.new_source;
    else sk.alert.alert_source = "Wazuh";
    
    if (r->rsp.new_type.compare("indef") != 0) sk.alert.alert_type = r->rsp.new_type;
    else {
        if (r->ids_type == 1) sk.alert.alert_type = "FILE";
        else sk.alert.alert_type = "HOST";
    }
    
    sk.alert.event_severity = 0;
    
    if (r->rsp.new_event.compare("indef") != 0) sk.alert.event_id = r->rsp.new_event;
    else sk.alert.event_id = r->event;
    
    if (r->rsp.new_description.compare("indef") != 0)  sk.alert.description = r->rsp.new_description;
    else sk.alert.description = r->desc;
    
    if (r->rsp.profile.compare("indef") != 0) sk.alert.action = r->rsp.profile;
    else sk.alert.action = "indef";
    
    sk.alert.location = "indef";
    
    sk.alert.info = "Message has been repeated ";
    sk.alert.info += std::to_string(c);
    sk.alert.info += " times";
    
    sk.alert.status = "aggregated";
    sk.alert.user_name = "indef";
    sk.alert.agent_name = "indef";
    sk.alert.filter = fs.filter.desc;
    
    copy(r->list_cats.begin(),r->list_cats.end(),back_inserter(sk.alert.list_cats));
    if (r->rsp.new_category.compare("indef") != 0) sk.alert.list_cats.push_back(r->rsp.new_category);
    
    sk.alert.event_time = GetNodeTime();
    sk.alert.event_json = "indef";
    
    sk.alert.src_ip = r->src_ip;
    sk.alert.dst_ip = r->dst_ip;
    sk.alert.src_hostname = "indef";
    sk.alert.dst_hostname = r->agent;
    sk.alert.src_port = 0;
    sk.alert.dst_port = 0;
    
    sk.alert.file_name = "indef";
    sk.alert.file_path = "indef";
	
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
    
    sk.SendAlert();
}

void AggAlerts::ResetHidsAlert() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    current_time = time(NULL);
    
    for(i = hids_alerts_list.begin(), end = hids_alerts_list.end(); i != end; ++i) {
        
        if ((i->alert_time + i->agr.in_period) < current_time)
            hids_alerts_list.erase(i++);
    }
}

void AggAlerts::UpdateNidsAlerts() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    for(i = nids_alerts_list.begin(), end = nids_alerts_list.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  { 
            if (i->event.compare(ids_rec.event) == 0) {
                if (i->host.compare("indef") == 0 || i->host.compare(ids_rec.src_ip) == 0 || i->host.compare(ids_rec.dst_ip) == 0) {    
                    if (i->match.compare(ids_rec.match) == 0) {
                        
                        //get current time
                        current_time = time(NULL);
                        
                        if ((i->alert_time + i->agr.in_period) >= current_time) {
                            
                            i->count++; 
                            
                            if (i->count >= i->agr.reproduced) {
                                SendNidsAlert(i, i->count);
                                nids_alerts_list.erase(i);
                            }
                        
                        } else {
                            
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
    nids_stat.agg_counter++;
    ids_rec.count = 1;
    nids_alerts_list.push_back(ids_rec);
}

void AggAlerts::SendNidsAlert(std::list<IdsRecord>::iterator r, int c) {
    
    sk.alert.ref_id = r->ref_id;
    sk.alert.sensor_id = r->ids;
    
    if (r->rsp.new_severity != 0) sk.alert.alert_severity = r->rsp.new_severity;
    else sk.alert.alert_severity = r->severity;
    
    if (r->rsp.new_source.compare("indef") != 0)  sk.alert.alert_source = r->rsp.new_source;
    else sk.alert.alert_source = "Suricata";
    
    if (r->rsp.new_type.compare("indef") != 0) sk.alert.alert_type = r->rsp.new_type;
    else sk.alert.alert_type = "NET";
    
    sk.alert.event_severity = 0;
    
    if (r->rsp.new_event.compare("indef") != 0) sk.alert.event_id = r->rsp.new_event;
    else sk.alert.event_id = r->event;
    
    if (r->rsp.new_description.compare("indef") != 0)  sk.alert.description = r->rsp.new_description;
    else sk.alert.description = r->desc;
    
    if (r->rsp.profile.compare("indef") != 0) sk.alert.action = r->rsp.profile;
    else sk.alert.action = "indef";
    
    sk.alert.location = "indef";
    
    sk.alert.info = "Message has been repeated ";
    sk.alert.info += std::to_string(c);
    sk.alert.info += " times";
    
    sk.alert.status = "aggregated";
    sk.alert.user_name = "indef";
    sk.alert.agent_name = "indef";
    sk.alert.filter = fs.filter.desc;
    
    copy(r->list_cats.begin(),r->list_cats.end(),back_inserter(sk.alert.list_cats));
    if (r->rsp.new_category.compare("indef") != 0) sk.alert.list_cats.push_back(r->rsp.new_category);
    
    sk.alert.event_time = GetNodeTime();
    sk.alert.event_json = "indef";
    
    sk.alert.src_ip = r->src_ip;
    sk.alert.dst_ip = r->dst_ip;
    sk.alert.src_hostname = "indef";
    sk.alert.dst_hostname = r->agent;
    sk.alert.src_port = 0;
    sk.alert.dst_port = 0;
    
    sk.alert.file_name = "indef";
    sk.alert.file_path = "indef";
	
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
    
    sk.SendAlert();
}

void AggAlerts::ResetNidsAlert() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    current_time = time(NULL);
    
    for(i = nids_alerts_list.begin(), end = nids_alerts_list.end(); i != end; ++i) {
        if ((i->alert_time + i->agr.in_period) < current_time)
            nids_alerts_list.erase(i++);
    }
}

void AggAlerts::UpdateWafAlerts() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    for(i = waf_alerts_list.begin(), end = waf_alerts_list.end(); i != end; ++i) {
        if (i->ref_id.compare(ids_rec.ref_id) == 0)  { 
            if (i->event.compare(ids_rec.event) == 0) {
                if (i->host.compare("indef") == 0 || i->host.compare(ids_rec.dst_ip) == 0 || i->host.compare(ids_rec.src_ip) == 0) {
                    if (i->match.compare(ids_rec.match) == 0) {
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
    } 
new_waf_alert:
    waf_stat.agg_counter++;
    ids_rec.count = 1;
    waf_alerts_list.push_back(ids_rec);
}

void AggAlerts::SendWafAlert(std::list<IdsRecord>::iterator r, int c) {
    
    sk.alert.ref_id = r->ref_id;
    sk.alert.sensor_id = r->ids;
    
    if (r->rsp.new_severity != 0) sk.alert.alert_severity = r->rsp.new_severity;
    else sk.alert.alert_severity = r->severity;
    
    if (r->rsp.new_source.compare("indef") != 0)  sk.alert.alert_source = r->rsp.new_source;
    else sk.alert.alert_source = "ModSecurity";
    
    if (r->rsp.new_type.compare("indef") != 0) sk.alert.alert_type = r->rsp.new_type;
    else sk.alert.alert_type = "NET";
    
    sk.alert.event_severity = 0;
    
    if (r->rsp.new_event.compare("indef") != 0) sk.alert.event_id = r->rsp.new_event;
    else sk.alert.event_id = r->event;
    
    if (r->rsp.new_description.compare("indef") != 0)  sk.alert.description = r->rsp.new_description;
    else sk.alert.description = r->desc;
    
    if (r->rsp.profile.compare("indef") != 0) sk.alert.action = r->rsp.profile;
    else sk.alert.action = "indef";
    
    sk.alert.location = "indef";
    
    sk.alert.info = "Message has been repeated ";
    sk.alert.info += std::to_string(c);
    sk.alert.info += " times";
    
    sk.alert.status = "aggregated";
    sk.alert.user_name = "indef";
    sk.alert.agent_name = "indef";
    sk.alert.filter = fs.filter.desc;
    
    copy(r->list_cats.begin(),r->list_cats.end(),back_inserter(sk.alert.list_cats));
    if (r->rsp.new_category.compare("indef") != 0) sk.alert.list_cats.push_back(r->rsp.new_category);
    
    sk.alert.event_time = GetNodeTime();
    sk.alert.event_json = "indef";
    
    sk.alert.src_ip = r->src_ip;
    sk.alert.dst_ip = r->dst_ip;
    sk.alert.src_hostname = "indef";
    sk.alert.dst_hostname = r->agent;
    sk.alert.src_port = 0;
    sk.alert.dst_port = 0;
    
    sk.alert.file_name = "indef";
    sk.alert.file_path = "indef";
	
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
    
    sk.SendAlert();
}

void AggAlerts::ResetWafAlert() {
    std::list<IdsRecord>::iterator i, end;
    time_t current_time;
    
    current_time = time(NULL);
    
    for(i = waf_alerts_list.begin(), end = waf_alerts_list.end(); i != end; ++i) {
        if ((i->alert_time + i->agr.in_period) < current_time)
            waf_alerts_list.erase(i++);
    }
}












