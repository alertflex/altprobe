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
char CollectorObject::remote_upload[OS_HEADER_SIZE];

bool CollectorObject::arStatus;
bool CollectorObject::uploadStatus;

int CollectorObject::timezone;
int CollectorObject::log_size;

long CollectorObject::gosleep_timer;
long CollectorObject::startup_timer;
long CollectorObject::update_timer;

char CollectorObject::wazuh_host[OS_HEADER_SIZE];
int CollectorObject::wazuh_port;
char CollectorObject::wazuh_user[OS_HEADER_SIZE];
char CollectorObject::wazuh_pwd[OS_HEADER_SIZE];

bool CollectorObject::wazuhServerStatus;

char CollectorObject::suri_path[OS_BUFFER_SIZE];
char CollectorObject::suri_rules[OS_BUFFER_SIZE];
char CollectorObject::suri_iprep[OS_BUFFER_SIZE];
char CollectorObject::wazuh_path[OS_BUFFER_SIZE];
char CollectorObject::wazuh_rules[OS_BUFFER_SIZE];
char CollectorObject::wazuh_iprep[OS_BUFFER_SIZE];

char CollectorObject::SysLogInfo[OS_LONG_HEADER_SIZE];

const string address_template = "$IPADDRESS";

int CollectorObject::GetConfig() {
    
    ConfigYaml* cy = new ConfigYaml( "collector");
    
    cy->addKey("node");
    cy->addKey("sensor");
    
    cy->addKey("active_response");
    cy->addKey("remote_upload");
           
    cy->addKey("time_zone");
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
    
    sensor_id = cy->getParameter("sensor");
    
    if (!sensor_id.compare("")) {
        SysLog("config file error: parameter sensor id");
        return 0;
    }
    
    timezone = stoi(cy->getParameter("time_zone"));
    
    log_size = stoi(cy->getParameter("log_size"));
    if (log_size == 0) log_size = 100;
    
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
    if (!strcmp (active_response, "false")) { 
        arStatus = false;
        SysLog("config file notification: active response is disabled");
    }
    
    if (!strcmp (active_response, "")) { 
        arStatus = false;
        SysLog("config file notification: active response is disabled");
    }
    
    strncpy(remote_upload, (char*) cy->getParameter("remote_upload").c_str(), sizeof(remote_upload));
    if (!strcmp (remote_upload, "false")) { 
        uploadStatus = false;
        SysLog("config file notification: remote upload of filters, rules and configs disabled");
        return 1;
    }
    strncpy(remote_upload, (char*) cy->getParameter("remote_upload").c_str(), sizeof(remote_upload));
    if (!strcmp (remote_upload, "false")) {
        uploadStatus = false;
        SysLog("config file notification: remote upload of filters, rules and configs disabled");
        return 1;
    }
    
    cy = new ConfigYaml( "sources");
    
    cy->addKey("suri_path");
    
    cy->addKey("suri_rules");
    
    cy->addKey("suri_iprep");
    
    cy->addKey("wazuh_path");
    
    cy->addKey("wazuh_rules");
    
    cy->addKey("wazuh_iprep");
    
    cy->ParsConfig();
    
    strncpy(suri_path, (char*) cy->getParameter("suri_path").c_str(), sizeof(suri_path));
    if (!strcmp (suri_path, "none")) { 
        SysLog("config file notification: remote update disabled, missing suri_path");
        return 1;
    }
    
    strncpy(suri_rules, (char*) cy->getParameter("suri_rules").c_str(), sizeof(suri_rules));
    if (!strcmp (suri_rules, "none")) { 
        SysLog("config file notification: remote update disabled, missing suri_rules");
        return 1;
    }
    
    strncpy(suri_iprep, (char*) cy->getParameter("suri_iprep").c_str(), sizeof(suri_iprep));
    if (!strcmp (suri_iprep, "none")) { 
        SysLog("config file notification: remote update disabled, missing suri_iprep");
        return 1;
    }
    
    strncpy(wazuh_path, (char*) cy->getParameter("wazuh_path").c_str(), sizeof(wazuh_path));
    if (!strcmp (wazuh_path, "none")) { 
        SysLog("config file notification: remote update disabled, missing wazuh_path");
        return 1;
    }
    
    strncpy(wazuh_rules, (char*) cy->getParameter("wazuh_rules").c_str(), sizeof(wazuh_rules));
    if (!strcmp (wazuh_rules, "none")) { 
        SysLog("config file notification: remote update disabled, missing wazuh_rules");
    }
    
    strncpy(wazuh_iprep, (char*) cy->getParameter("wazuh_iprep").c_str(), sizeof(wazuh_iprep));
    if (!strcmp (wazuh_iprep, "none")) { 
        SysLog("config file notification: remote update disabled, missing wazuh_iprep");
        return 1;
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



