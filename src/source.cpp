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

#include "source.h"

int Source::config_flag = 0;

int Source::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    //Read filter config
    if(!fs.GetFiltersConfig()) return 0;
    
    string redis_host(sk.redis_host);
    
    if (!redis_key.compare("indef") || !redis_host.compare("indef") || sk.redis_port == 0) {
    
        redis_status = 0;
       
    } else {
        
        ConfigYaml* cy = new ConfigYaml( "sensors");
    
        cy->addKey(config_key);
            
        cy->ParsConfig();
    
        redis_key = cy->getParameter(config_key);
        
        if (!redis_key.compare("indef")) redis_status = 0;
        else redis_key = "lpop " + redis_key;
        
    }
    
    return 1;
}

long Source::ResetEventsCounter() {
    
    unsigned long r;
        
    m_monitor_counter.lock();
    r = events_counter;
    events_counter = 0;
    m_monitor_counter.unlock();
        
    return r;
}
    
void Source::IncrementEventsCounter() {
    m_monitor_counter.lock();
    events_counter++;
    m_monitor_counter.unlock();
}
    
void Source::SendAlertMultiple(int type) {
    
    sk.alert.ref_id  = fs.filter.ref_id;
    sk.alert.sensor_id = host_name;
                
    sk.alert.alert_severity = 3;
    switch (type) {
        case 0:
            sk.alert.alert_type = "HOST";
            sk.alert.alert_source = "Falco";
            break;
        case 1:
            sk.alert.alert_type = "HOST";
            sk.alert.alert_source = "Wazuh";
            break;
        case 2:
            sk.alert.alert_type = "NET";
            sk.alert.alert_source = "Suricata";
            break;
        case 3:
            sk.alert.alert_type = "NET";
            sk.alert.alert_source = "ModSecurity";
            break;
        default:
            sk.alert.alert_type = "MISC";
            sk.alert.alert_source = "Alertflex";
            break;
    }
    
    sk.alert.event_severity = 0;
    sk.alert.event_id = 2;
    sk.alert.description = "Multiple alert";
    sk.alert.action = "indef";
    sk.alert.location = "indef";
    sk.alert.info = "indef";
    sk.alert.status = "processed";
    sk.alert.user_name = "indef";
    sk.alert.agent_name = "indef";
    sk.alert.filter = fs.filter.name;
    
    sk.alert.list_cats.push_back("Multiple alert");
    
    sk.alert.event_time = GetNodeTime();
        
    sk.alert.src_ip = "indef";
    sk.alert.dst_ip = "indef";
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


string Source::GetHostname(string ip) {
    
    if (ip.compare("") == 0) return "indef";
    
    if (IsValidIp(ip) == -1) return "indef";
    
    string hostname = fs.GetHostnameByIP(ip);
    
    if (hostname.compare("") == 0) {
    
        hostname = "indef";
    }
    
    return hostname;
}

bool Source::SuppressAlert(string ip) {
    
    if (ip.compare("") == 0) return false;
    
    if (fs.filter.home_nets.size() != 0) {
        
        std::vector<Network*>::iterator i, end;
        
        for (i = fs.filter.home_nets.begin(), end = fs.filter.home_nets.end(); i != end; ++i) {
            
            string net = (*i)->network;
            string mask = (*i)->netmask;
            
            if(IsIPInRange(ip, net, mask)) {
                if ((*i)->alert_suppress) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

void Source::SetGeoBySrcIp(string ip) {
    
    GeoIPRecord *gir;
    char **ret;
    
    if (maxmind_status) {
        
        try {
            gir = GeoIP_record_by_name(gi, (const char *) ip.c_str());

            if (gir != NULL) {
                src_cc = string(gir->country_code);
                src_latitude = to_string(gir->latitude);
                src_longitude = to_string(gir->longitude);
                GeoIPRecord_delete(gir);
            
            } else {
                src_cc = "indef";
                src_latitude = "0.0";
                src_longitude = "0.0";
            }
        } catch (Exception& e) {
            src_cc = "indef";
            src_latitude = "0.0";
            src_longitude = "0.0";
        }
    } 
}

void Source::SetGeoByDstIp(string ip) {
    
    GeoIPRecord *gir;
    char **ret;
    
    if (maxmind_status) {
        
        try {
            gir = GeoIP_record_by_name(gi, (const char *) ip.c_str());

            if (gir != NULL) {
                dst_cc = string(gir->country_code);
                dst_latitude = to_string(gir->latitude);
                dst_longitude = to_string(gir->longitude);
                GeoIPRecord_delete(gir);
            
            } else {
                dst_cc = "indef";
                dst_latitude = "0.0";
                dst_longitude = "0.0";
            }
            
        } catch (Exception& e) {
            dst_cc = "indef";
            dst_latitude = "0.0";
            dst_longitude = "0.0";
        }
    } 
}

