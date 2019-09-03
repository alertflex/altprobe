/* 
 * File:   cobject.cpp
 * Author: Oleg Zharkov
 *
 */

#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <libdaemon/dexec.h>

#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.
#include <sstream>

#include "cobject.h"

string CollectorObject::node_id;
string CollectorObject::sensor_id;

char CollectorObject::active_response[OS_HEADER_SIZE];
char CollectorObject::update_remote[OS_HEADER_SIZE];


bool CollectorObject::arStatus;
bool CollectorObject::urStatus;

int CollectorObject::timezone;
char CollectorObject::log_path[OS_BUFFER_SIZE]; 
int CollectorObject::log_size;

long CollectorObject::gosleep_timer;
long CollectorObject::startup_timer;
long CollectorObject::update_timer;

char CollectorObject::wazuh_host[OS_HEADER_SIZE];
int CollectorObject::wazuh_port;
char CollectorObject::wazuh_user[OS_HEADER_SIZE];
char CollectorObject::wazuh_pwd[OS_HEADER_SIZE];

bool CollectorObject::wazuhServerStatus;

char CollectorObject::falco_log[OS_BUFFER_SIZE]; 
bool CollectorObject::falcolog_status;
char CollectorObject::suri_log[OS_BUFFER_SIZE]; 
bool CollectorObject::surilog_status;
char CollectorObject::wazuh_log[OS_BUFFER_SIZE];
bool CollectorObject::wazuhlog_status;
char CollectorObject::modsec_log[OS_BUFFER_SIZE];
bool CollectorObject::modseclog_status;

char CollectorObject::falco_conf[OS_BUFFER_SIZE];
char CollectorObject::falco_local[OS_BUFFER_SIZE];
char CollectorObject::falco_rules[OS_BUFFER_SIZE];

char CollectorObject::suri_conf[OS_BUFFER_SIZE];
char CollectorObject::suri_local[OS_BUFFER_SIZE];
char CollectorObject::suri_rules[OS_BUFFER_SIZE];

char CollectorObject::wazuh_conf[OS_BUFFER_SIZE];
char CollectorObject::wazuh_local[OS_BUFFER_SIZE];
char CollectorObject::wazuh_rules[OS_BUFFER_SIZE];

char CollectorObject::modsec_conf[OS_BUFFER_SIZE];
char CollectorObject::modsec_local[OS_BUFFER_SIZE];
char CollectorObject::modsec_rules[OS_BUFFER_SIZE];

char CollectorObject::SysLogInfo[OS_LONG_HEADER_SIZE];

int CollectorObject::GetConfig() {
    
    ConfigYaml* cy = new ConfigYaml( "collector");
    
    cy->addKey("node");
    cy->addKey("probe");
    
    cy->addKey("active_response");
    cy->addKey("update_remote");
               
    cy->addKey("time_zone");
    
    cy->addKey("log_path");
    cy->addKey("log_size");
    
    cy->addKey("startup_timer");
    cy->addKey("sleep_timer");
    cy->addKey("update_timer");
        
    cy->addKey("wazuh_host");
    cy->addKey("wazuh_port");
    cy->addKey("wazuh_user");
    cy->addKey("wazuh_pwd");
                
    cy->ParsConfig();
    
    node_id = cy->getParameter("node");
    
    if (!node_id.compare("")) {
        SysLog("config file error: parameter node id");
        return 0;
    }
    
    sensor_id = cy->getParameter("probe");
    
    if (!sensor_id.compare("")) {
        SysLog("config file error: parameter probe id");
        return 0;
    }
    
    timezone = stoi(cy->getParameter("time_zone"));
    
    log_size = stoi(cy->getParameter("log_size"));
    if (log_size == 0) log_size = 100;
    
    strncpy(log_path, (char*) cy->getParameter("log_path").c_str(), sizeof(log_path));
    
    if (!strcmp (log_path, "none")) { 
        strncpy(log_path, "var/log/altprobe", sizeof(log_path));
    }
    
    if (!strcmp (log_path, "")) { 
        strncpy(log_path, "var/log/altprobe", sizeof(log_path));
    }
    
    gosleep_timer = stoi(cy->getParameter("sleep_timer"));
    
    if (!gosleep_timer) {
        SysLog("config file error: parameter sleep_timer");
        return 0;
    }
    
    startup_timer = stoi(cy->getParameter("startup_timer"));
    
    if (!startup_timer) {
        SysLog("config file error: parameter startup_timer");
        return 0;
    }
    
    update_timer = stoi(cy->getParameter("update_timer"));
    
    if (!update_timer) {
        SysLog("config file: update rules is disabled");
    }
    
    strncpy(wazuh_host, (char*) cy->getParameter("wazuh_host").c_str(), sizeof(wazuh_host));
    if (!strcmp (wazuh_host, "none")) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    if (!strcmp (wazuh_host, "")) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    wazuh_port = stoi(cy->getParameter("wazuh_port"));
    if (wazuh_port == 0) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    strncpy(wazuh_user, (char*) cy->getParameter("wazuh_user").c_str(), sizeof(wazuh_user));
    if (!strcmp (wazuh_user, "none")) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    if (!strcmp (wazuh_user, "")) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    strncpy(wazuh_pwd, (char*) cy->getParameter("wazuh_pwd").c_str(), sizeof(wazuh_pwd));
    if (!strcmp (wazuh_pwd, "none")) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    if (!strcmp (wazuh_pwd, "")) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    strncpy(active_response, (char*) cy->getParameter("active_response").c_str(), sizeof(active_response));
    if (!strcmp (active_response, "true")) { 
        arStatus = true;
        SysLog("config file notification: active response is enabled");
    }
    
    strncpy(update_remote, (char*) cy->getParameter("update_remote").c_str(), sizeof(update_remote));
    if (!strcmp (update_remote, "false")) { 
        urStatus = false;
        SysLog("config file notification: update_remote for filters, rules and configs disabled");
    }
    
    cy = new ConfigYaml( "sources");
    
    cy->addKey("falco_log");
    
    cy->addKey("suri_log");
    
    cy->addKey("wazuh_log");
    
    cy->addKey("modsec_log");
    
    cy->addKey("falco_conf");
    
    cy->addKey("falco_local");
    
    cy->addKey("falco_rules");
    
    cy->addKey("suri_conf");
    
    cy->addKey("suri_local");
    
    cy->addKey("suri_rules");
    
    cy->addKey("wazuh_conf");
    
    cy->addKey("wazuh_local");
    
    cy->addKey("wazuh_rules");
    
    cy->addKey("modsec_conf");
    
    cy->addKey("modsec_local");
    
    cy->addKey("modsec_rules");
    
    cy->ParsConfig();
    
    strncpy(falco_log, (char*) cy->getParameter("falco_log").c_str(), sizeof(falco_log));
    if (!strcmp (falco_log, "none")) { 
        falcolog_status = false;
    }
    
    strncpy(suri_log, (char*) cy->getParameter("suri_log").c_str(), sizeof(suri_log));
    if (!strcmp (suri_log, "none")) { 
        surilog_status = false;
    }
    
    strncpy(wazuh_log, (char*) cy->getParameter("wazuh_log").c_str(), sizeof(wazuh_log));
    if (!strcmp (wazuh_log, "none")) { 
        wazuhlog_status = false;
    }
    
    strncpy(modsec_log, (char*) cy->getParameter("modsec_log").c_str(), sizeof(modsec_log));
    if (!strcmp (modsec_log, "none")) { 
        modseclog_status = false;
    }
    
    if (urStatus) {
        
        strncpy(falco_conf, (char*) cy->getParameter("falco_conf").c_str(), sizeof(falco_conf));
        if (!strcmp (falco_conf, "none")) { 
            SysLog("config file notification: falco_conf update disabled");
        }
    
        strncpy(falco_local, (char*) cy->getParameter("falco_local").c_str(), sizeof(falco_local));
        if (!strcmp (falco_local, "none")) { 
            SysLog("config file notification: falco_local update disabled");
        }
        
         strncpy(falco_rules, (char*) cy->getParameter("falco_rules").c_str(), sizeof(falco_rules));
        if (!strcmp (falco_rules, "none")) { 
            SysLog("config file notification: falco_rules update disabled");
        }
    
        strncpy(suri_conf, (char*) cy->getParameter("suri_conf").c_str(), sizeof(suri_conf));
        if (!strcmp (suri_conf, "none")) { 
            SysLog("config file notification: suri_conf update disabled");
        }
    
        strncpy(suri_local, (char*) cy->getParameter("suri_local").c_str(), sizeof(suri_local));
        if (!strcmp (suri_local, "none")) { 
            SysLog("config file notification: suri_local update disabled");
        }
        
         strncpy(suri_rules, (char*) cy->getParameter("suri_rules").c_str(), sizeof(suri_rules));
        if (!strcmp (suri_rules, "none")) { 
            SysLog("config file notification: suri_rules update disabled");
        }
    
        strncpy(wazuh_conf, (char*) cy->getParameter("wazuh_conf").c_str(), sizeof(wazuh_conf));
        if (!strcmp (wazuh_conf, "none")) { 
            SysLog("config file notification: wazuh_conf update disabled");
        }
    
        strncpy(wazuh_local, (char*) cy->getParameter("wazuh_local").c_str(), sizeof(wazuh_local));
        if (!strcmp (wazuh_local, "none")) { 
            SysLog("config file notification: wazuh_local update disabled");
        }
        
        strncpy(wazuh_rules, (char*) cy->getParameter("wazuh_rules").c_str(), sizeof(wazuh_rules));
        if (!strcmp (wazuh_rules, "none")) { 
            SysLog("config file notification: wazuh_rules update disabled");
        }
    
        strncpy(modsec_conf, (char*) cy->getParameter("modsec_conf").c_str(), sizeof(modsec_conf));
        if (!strcmp (modsec_conf, "none")) { 
            SysLog("config file notification: modsec_conf update disabled");
        }
    
        strncpy(modsec_local, (char*) cy->getParameter("modsec_local").c_str(), sizeof(modsec_local));
        if (!strcmp (modsec_local, "none")) { 
            SysLog("config file notification:  modsec_local update disabled");
        }
        
        strncpy(modsec_rules, (char*) cy->getParameter("modsec_rules").c_str(), sizeof(modsec_rules));
        if (!strcmp (modsec_rules, "none")) { 
            SysLog("config file notification: modsec_rules disabled");
        }
    }
    
    return 1;
}

string CollectorObject::GetNodeTime() {
    time_t rawtime;
    struct tm * timeinfo;
        
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(collector_time,sizeof(collector_time),"%Y-%m-%d %H:%M:%S",timeinfo);
    
    return string(collector_time);
}

string CollectorObject::GetGraylogFormat() {
    time_t rawtime;
    struct tm * timeinfo;
        
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(collector_time,sizeof(collector_time),"%Y-%m-%dT%H:%M:%S.000Z",timeinfo);
    
    return string(collector_time);
}

void CollectorObject::SysLog(char* info) {
    
    //If info equael NULL fuction send var SysLogInfo as String to SysLog
    if (info == NULL) daemon_log(LOG_ERR, "%s", SysLogInfo);
    else daemon_log(LOG_ERR, "%s", info);
}

int CollectorObject::ValidDigit(char* ip_str) {
    while (*ip_str) {
        if (*ip_str >= '0' && *ip_str <= '9')
            ++ip_str;
        else
            return 0;
    }
    return 1;
}
 
/* return -1 if IP string isn't valide, return 0 if IP string is private, return 1 if IP string is public */
int CollectorObject::IsValidIp(string ip) {
    
    int i = 0;
    char* ptr;
    int n[4];
    char ip_tmp[32];
    
    memset(ip_tmp, 0, sizeof(ip_tmp));
    strncpy (ip_tmp, ip.c_str(), sizeof(ip_tmp));
    
    ptr = strtok(ip_tmp, DELIM);
    if (ptr == NULL) return -1;
    /* after parsing string, it must contain only digits */
    n[0] = atoi(ptr);
    /* check for valid IP */
    if (n[0] < 0 && n[0] > 255) return -1;
 
    for(i = 1; i< 4; i++) {
        
        ptr = strtok(NULL, DELIM);
        if (ptr == NULL) return -1;
        if (!ValidDigit(ptr)) return -1;
        n[i] = atoi(ptr);
        
        if (n[i] < 0 && n[i] > 255) return -1;
    }
 
    
    if((n[0] == 10 && n[1] >= 0 && n[1] <= 255 && n[2] >= 0 && n[2] <= 255 && n[3] >= 0 && n[3] <= 255) 
        || (n[0] == 172 && n[1] >= 16 && n[1] <= 31 && n[2] >= 0 && n[2] <= 255 && n[3] >= 0 && n[3] <= 255) 
        || (n[0] == 192 && n[1] == 168 && n[2] >= 0 && n[2] <= 255 && n[3] >= 0 && n[3] <= 255) 
        || (n[0] == 169 && n[1] == 254 && n[2] >= 0 && n[2] <= 255 && n[3] >= 0 && n[3] <= 255)
        || (n[0] == 127 && n[1] == 0 && n[2] == 0 && n[3] == 1)) {
        
        return 0;
    }
    return 1;
}

uint32_t CollectorObject::IPToUInt(string ip) {
    int a, b, c, d;
    uint32_t addr = 0;
 
    if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
        return 0;
 
    addr = a << 24;
    addr |= b << 16;
    addr |= c << 8;
    addr |= d;
    return addr;
}

bool CollectorObject::IsIPInRange(string ip, string network, string mask) {
    uint32_t ip_addr = IPToUInt(ip);
    uint32_t network_addr = IPToUInt(network);
    uint32_t mask_addr = IPToUInt(mask);
 
    uint32_t net_lower = (network_addr & mask_addr);
    uint32_t net_upper = (net_lower | (~mask_addr));
 
    if (ip_addr >= net_lower &&
        ip_addr <= net_upper)
        return true;
    return false;
}

unsigned int CollectorObject::GetBufferSize(char* source) {
    char c;
    unsigned int result = 0;
    while ((c = *source++) != '\0')
        result++;
    return result;
}

void CollectorObject::ReplaceAll(string& input, const string& from, const string& to) {
  size_t pos = 0;
  while ((pos = input.find(from, pos)) != string::npos) {
    input.replace(pos, from.size(), to);
    pos += to.size();
  }
}

void Alert::CreateAlertUUID(void) {
    
    std::stringstream ss;
    
    if (alert_uuid.empty()) {
    
        boost::uuids::uuid uuid = boost::uuids::random_generator()();
        ss << uuid; 
        alert_uuid = ss.str();
    }
}



