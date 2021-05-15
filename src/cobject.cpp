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
string CollectorObject::probe_id;
string CollectorObject::project_id;

char CollectorObject::remote_control[OS_HEADER_SIZE];
char CollectorObject::remote_update[OS_HEADER_SIZE];
bool CollectorObject::rcStatus;
bool CollectorObject::ruStatus;

int CollectorObject::timezone;
char CollectorObject::log_path[OS_BUFFER_SIZE]; 
int CollectorObject::log_size;

long CollectorObject::gosleep_timer;
long CollectorObject::startup_timer;

char CollectorObject::suri_socket[OS_BUFFER_SIZE];
bool CollectorObject::suriSocketStatus;
char CollectorObject::docker_socket[OS_BUFFER_SIZE];
bool CollectorObject::dockerSocketStatus;

// scanners
char CollectorObject::dependencycheck_result[OS_BUFFER_SIZE];
char CollectorObject::dockerbench_result[OS_BUFFER_SIZE]; 
char CollectorObject::kubebench_result[OS_BUFFER_SIZE]; 
char CollectorObject::kubehunter_result[OS_BUFFER_SIZE]; 
char CollectorObject::nmap_result[OS_BUFFER_SIZE]; 
char CollectorObject::trivy_result[OS_BUFFER_SIZE]; 
char CollectorObject::zap_result[OS_BUFFER_SIZE]; 

// sensors
char CollectorObject::falco_log[OS_BUFFER_SIZE]; 
int CollectorObject::falcolog_status = 1;
char CollectorObject::falco_conf[OS_BUFFER_SIZE];
char CollectorObject::falco_local[OS_BUFFER_SIZE];
char CollectorObject::falco_rules[OS_BUFFER_SIZE];

char CollectorObject::modsec_log[OS_BUFFER_SIZE];
int CollectorObject::modseclog_status = 1;
char CollectorObject::modsec_conf[OS_BUFFER_SIZE];
char CollectorObject::modsec_local[OS_BUFFER_SIZE];
char CollectorObject::modsec_rules[OS_BUFFER_SIZE];

char CollectorObject::suri_log[OS_BUFFER_SIZE]; 
int CollectorObject::surilog_status = 1;
char CollectorObject::suri_conf[OS_BUFFER_SIZE];
char CollectorObject::suri_local[OS_BUFFER_SIZE];
char CollectorObject::suri_rules[OS_BUFFER_SIZE];

char CollectorObject::wazuh_log[OS_BUFFER_SIZE];
int CollectorObject::wazuhlog_status = 1;
char CollectorObject::wazuh_conf[OS_BUFFER_SIZE];
char CollectorObject::wazuh_local[OS_BUFFER_SIZE];
char CollectorObject::wazuh_rules[OS_BUFFER_SIZE];

char CollectorObject::wazuh_host[OS_HEADER_SIZE];
int CollectorObject::wazuh_port;
char CollectorObject::wazuh_user[OS_HEADER_SIZE];
char CollectorObject::wazuh_pwd[OS_HEADER_SIZE];
string CollectorObject::wazuh_token;
bool CollectorObject::wazuhServerStatus;

static char modsec_conf[OS_BUFFER_SIZE];
    static char modsec_local[OS_BUFFER_SIZE];
    static char modsec_rules[OS_BUFFER_SIZE];

char CollectorObject::SysLogInfo[OS_LONG_HEADER_SIZE];

int CollectorObject::GetConfig() {
    
    ConfigYaml* cy = new ConfigYaml( "collector");
    
    cy->addKey("node");
    cy->addKey("probe");
    
    cy->addKey("remote_control");
    cy->addKey("remote_update");
               
    cy->addKey("time_zone");
    
    cy->addKey("log_path");
    cy->addKey("log_size");
        
    cy->addKey("timer_start");
    cy->addKey("timer_sleep");
        
    cy->addKey("socket_suricata");
    cy->addKey("socket_docker");
        
    cy->addKey("wazuhapi_host");
    cy->addKey("wazuhapi_port");
    cy->addKey("wazuhapi_user");
    cy->addKey("wazuhapi_pwd");
                
    cy->ParsConfig();
    
    node_id = cy->getParameter("node");
    
    if (!node_id.compare("")) {
        SysLog("config file error: parameter node id");
        return 0;
    }
    
    probe_id = cy->getParameter("probe");
    
    if (!probe_id.compare("")) {
        SysLog("config file error: parameter probe id");
        return 0;
    }
    
    timezone = stoi(cy->getParameter("time_zone"));
    
    log_size = stoi(cy->getParameter("log_size"));
    if (log_size == 0) log_size = 100;
    
    strncpy(log_path, (char*) cy->getParameter("log_path").c_str(), sizeof(log_path));
    
    if (!strcmp (log_path, "indef")) { 
        strncpy(log_path, "var/log/altprobe", sizeof(log_path));
    }
    
    if (!strcmp (log_path, "")) { 
        strncpy(log_path, "var/log/altprobe", sizeof(log_path));
    }
    
    gosleep_timer = stoi(cy->getParameter("timer_sleep"));
    
    if (!gosleep_timer) {
        SysLog("config file error: parameter timer_sleep");
        return 0;
    }
    
    startup_timer = stoi(cy->getParameter("timer_start"));
    
    if (!startup_timer) {
        SysLog("config file error: parameter timer_start");
        return 0;
    }
    
    strncpy(suri_socket, (char*) cy->getParameter("socket_suricata").c_str(), sizeof(suri_socket));
    if (!strcmp (suri_socket, "indef")) { 
        suriSocketStatus =false;
        SysLog("config file notification: interface to Suricata socket is disabled");
    }
    
    strncpy(docker_socket, (char*) cy->getParameter("socket_docker").c_str(), sizeof(docker_socket));
    if (!strcmp (docker_socket, "indef")) { 
        dockerSocketStatus =false;
        SysLog("config file notification: interface to Docker socket is disabled");
    }
    
    strncpy(wazuh_host, (char*) cy->getParameter("wazuhapi_host").c_str(), sizeof(wazuh_host));
    if (!strcmp (wazuh_host, "indef")) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    if (!strcmp (wazuh_host, "")) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    wazuh_port = stoi(cy->getParameter("wazuhapi_port"));
    if (wazuh_port == 0) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    strncpy(wazuh_user, (char*) cy->getParameter("wazuhapi_user").c_str(), sizeof(wazuh_user));
    if (!strcmp (wazuh_user, "indef")) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    if (!strcmp (wazuh_user, "")) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    strncpy(wazuh_pwd, (char*) cy->getParameter("wazuhapi_pwd").c_str(), sizeof(wazuh_pwd));
    if (!strcmp (wazuh_pwd, "indef")) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    if (!strcmp (wazuh_pwd, "")) { 
        wazuhServerStatus =false;
        SysLog("config file notification: interface to Wazuh server is disabled");
    }
    
    strncpy(remote_control, (char*) cy->getParameter("remote_control").c_str(), sizeof(remote_control));
    if (!strcmp (remote_control, "true")) { 
        rcStatus = true;
        SysLog("config file notification: remote_control is enabled");
    }
    
    strncpy(remote_update, (char*) cy->getParameter("remote_update").c_str(), sizeof(remote_update));
    if (!strcmp (remote_update, "false")) { 
        ruStatus = false;
        SysLog("config file notification: remote_update disabled");
    }
    
    cy = new ConfigYaml("sensors");
    
    cy->addKey("falco_log");
    cy->addKey("falco_conf");
    cy->addKey("falco_local");
    cy->addKey("falco_rules");
    
    cy->addKey("modsec_log");
    cy->addKey("modsec_conf");
    cy->addKey("modsec_local");
    cy->addKey("modsec_rules");
    
    cy->addKey("suri_log");
    cy->addKey("suri_conf");
    cy->addKey("suri_local");
    cy->addKey("suri_rules");
    
    cy->addKey("wazuh_log");
    cy->addKey("wazuh_conf");
    cy->addKey("wazuh_local");
    cy->addKey("wazuh_rules");
    
    cy->ParsConfig();
    
    strncpy(falco_log, (char*) cy->getParameter("falco_log").c_str(), sizeof(falco_log));
    if (!strcmp (falco_log, "indef")) { 
        falcolog_status = 0;
    } 
    
    strncpy(modsec_log, (char*) cy->getParameter("modsec_log").c_str(), sizeof(modsec_log));
    if (!strcmp (modsec_log, "indef")) { 
        modseclog_status = 0;
    } 
    
    strncpy(suri_log, (char*) cy->getParameter("suri_log").c_str(), sizeof(suri_log));
    if (!strcmp (suri_log, "indef")) { 
        surilog_status = 0;
    } 
    
    strncpy(wazuh_log, (char*) cy->getParameter("wazuh_log").c_str(), sizeof(wazuh_log));
    if (!strcmp (wazuh_log, "indef")) { 
        wazuhlog_status = 0;
    } 
    
    if (ruStatus) {
        
        strncpy(falco_conf, (char*) cy->getParameter("falco_conf").c_str(), sizeof(falco_conf));
        if (!strcmp (falco_conf, "indef")) { 
            SysLog("config file notification: falco_conf update disabled");
        }
    
        strncpy(falco_local, (char*) cy->getParameter("falco_local").c_str(), sizeof(falco_local));
        if (!strcmp (falco_local, "indef")) { 
            SysLog("config file notification: falco_local update disabled");
        }
        
        strncpy(falco_rules, (char*) cy->getParameter("falco_rules").c_str(), sizeof(falco_rules));
        if (!strcmp (falco_rules, "indef")) { 
            SysLog("config file notification: falco_rules update disabled");
        }
         
        strncpy(modsec_conf, (char*) cy->getParameter("modsec_conf").c_str(), sizeof(modsec_conf));
        if (!strcmp (modsec_conf, "indef")) { 
            SysLog("config file notification: modsec_conf update disabled");
        }
    
        strncpy(modsec_local, (char*) cy->getParameter("modsec_local").c_str(), sizeof(modsec_local));
        if (!strcmp (modsec_local, "indef")) { 
            SysLog("config file notification:  modsec_local update disabled");
        }
        
        strncpy(modsec_rules, (char*) cy->getParameter("modsec_rules").c_str(), sizeof(modsec_rules));
        if (!strcmp (modsec_rules, "indef")) { 
            SysLog("config file notification: modsec_rules disabled");
        }
    
        strncpy(suri_conf, (char*) cy->getParameter("suri_conf").c_str(), sizeof(suri_conf));
        if (!strcmp (suri_conf, "indef")) { 
            SysLog("config file notification: suri_conf update disabled");
        }
    
        strncpy(suri_local, (char*) cy->getParameter("suri_local").c_str(), sizeof(suri_local));
        if (!strcmp (suri_local, "indef")) { 
            SysLog("config file notification: suri_local update disabled");
        }
        
         strncpy(suri_rules, (char*) cy->getParameter("suri_rules").c_str(), sizeof(suri_rules));
        if (!strcmp (suri_rules, "indef")) { 
            SysLog("config file notification: suri_rules update disabled");
        }
    
        strncpy(wazuh_conf, (char*) cy->getParameter("wazuh_conf").c_str(), sizeof(wazuh_conf));
        if (!strcmp (wazuh_conf, "indef")) { 
            SysLog("config file notification: wazuh_conf update disabled");
        }
    
        strncpy(wazuh_local, (char*) cy->getParameter("wazuh_local").c_str(), sizeof(wazuh_local));
        if (!strcmp (wazuh_local, "indef")) { 
            SysLog("config file notification: wazuh_local update disabled");
        }
        
        strncpy(wazuh_rules, (char*) cy->getParameter("wazuh_rules").c_str(), sizeof(wazuh_rules));
        if (!strcmp (wazuh_rules, "indef")) { 
            SysLog("config file notification: wazuh_rules update disabled");
        }
    }
    
    cy = new ConfigYaml( "scanners");
    
    cy->addKey("dependencycheck_result");
    
    cy->addKey("dockerbench_result");
    
    cy->addKey("kubebench_result");
    
    cy->addKey("kubehunter_result");
    
    cy->addKey("nmap_result");
    
    cy->addKey("trivy_result");
    
    cy->addKey("zap_result");
    
    cy->addKey("project_id");
    
    cy->ParsConfig();
    
    strncpy(dependencycheck_result, (char*) cy->getParameter("dependencycheck_result").c_str(), sizeof(dependencycheck_result));
    
    strncpy(dockerbench_result, (char*) cy->getParameter("dockerbench_result").c_str(), sizeof(dockerbench_result));
    
    strncpy(kubebench_result, (char*) cy->getParameter("kubebench_result").c_str(), sizeof(kubebench_result));
    
    strncpy(kubehunter_result, (char*) cy->getParameter("kubehunter_result").c_str(), sizeof(kubehunter_result));
    
    strncpy(nmap_result, (char*) cy->getParameter("nmap_result").c_str(), sizeof(nmap_result));
    
    strncpy(trivy_result, (char*) cy->getParameter("trivy_result").c_str(), sizeof(trivy_result));
    
    strncpy(zap_result, (char*) cy->getParameter("zap_result").c_str(), sizeof(zap_result));
    
    project_id = cy->getParameter("project_id");
    
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



