/* 
 * File:   source.cpp
 * Author: Oleg Zharkov
 *
 */

#include "source.h"

int Source::config_flag = 0;

char Source::maxmind_path[OS_BUFFER_SIZE];

int Source::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    //Read filter config
    if(!fs.GetFiltersConfig()) return 0;
    
    ConfigYaml* cy = new ConfigYaml( "sources");
    
    cy->addKey(config_key);
            
    cy->ParsConfig();
    
    redis_key = cy->getParameter(config_key);
        
    if (!redis_key.compare("none")) { 
            status = 0;
            string notification = "config file notification: redis interface is disabled for " + config_key;
            SysLog((char*) notification.c_str());
    }
    else {
        redis_key = "rpop " + redis_key;
        status = 1;
    }
    
    if (!config_flag) {
        cy = new ConfigYaml( "collector");
        
        cy->addKey("geo_db");
    
        cy->ParsConfig();
        
        strncpy(maxmind_path, (char*) cy->getParameter("geo_db").c_str(), sizeof(maxmind_path));
        
        config_flag =  1;
    }
    
    return 1;
}


int Source::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (status == 1) {
        c = redisConnect(sk.redis_host, sk.redis_port);
    
        if (c != NULL && c->err) {
            // handle error
            sprintf(level, "failed open redis server interface: %s\n", c->errstr);
            SysLog(level);
            return 0;
        }
    }
    
    if (!strcmp (maxmind_path, "none")) maxmind_state = 0;
    else {
        gi = GeoIP_open(maxmind_path, GEOIP_INDEX_CACHE);

        if (gi == NULL) {
            SysLog("error opening maxmind database\n");
            maxmind_state = 0;
        }
        else maxmind_state = 1;
    }
    
    return 1;
}

void Source::Close() {
    
    sk.Close();
    
    if (status == 1) redisFree(c);
    
    if (maxmind_state != 0) GeoIP_delete(gi);
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
    
    sk.alert.dstip = "";
    sk.alert.srcip = "";
    sk.alert.dstport = 0;
    sk.alert.srcport = 0;
    sk.alert.dstagent = "none";
    sk.alert.srcagent = "none";
    sk.alert.user = "none";
    
    string strNodeId(node_id);
    sk.alert.sensor = sensor_id;
    sk.alert.filter = fs.filter.desc;
    sk.alert.event_time = GetNodeTime();
        
    switch (type) {
        case 1:
            sk.alert.type = "HOST";
            sk.alert.source = "Wazuh";
            break;
        case 2:
            sk.alert.type = "NET";
            sk.alert.source = "Modsecurity";
            break;
        case 3:
            sk.alert.type = "NET";
            sk.alert.source = "Suricata";
            break;
        default:
            sk.alert.type = "MISC";
            sk.alert.source = "Alertflex";
            break;
    }
        
    sk.alert.event = 1;
    
    sk.alert.severity = 3;
    sk.alert.score = 0;
    
    sk.alert.list_cats.push_back("Multiple alert");
        
    sk.alert.action = "none";
        
    sk.alert.description = "Multiple alert";
    
    sk.alert.location = "";
        
    sk.alert.info = "";
        
    sk.alert.event_json = "";
        
    sk.alert.status = "processed_new";
        
    sk.SendAlert();
        
}


string Source::GetAgent(string ip) {
    
    if (ip.compare("") == 0) return "unknown";
    
    string agent = fs.GetAgentNameByIP(ip);
    
    if (agent.compare("") == 0) {
    
        if (fs.filter.home_nets.size() != 0) {
        
            std::vector<Network*>::iterator i, end;
            
            for (i = fs.filter.home_nets.begin(), end = fs.filter.home_nets.end(); i != end; ++i) {
            
                string net = (*i)->network;
                string mask = (*i)->netmask;
            
                if(IsIPInRange(ip, net, mask)) {
                    string node = "node-" + (*i)->node;
                    return node;
                }
            }
        }
    
        return "ext-net";
    }
    
    return agent;
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

