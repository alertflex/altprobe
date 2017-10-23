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
int CollectorObject::timezone = 0;
int CollectorObject::log_size = 0;
long CollectorObject::gosleep_timer = 0;
long CollectorObject::startup_timer = 0;



char CollectorObject::SysLogInfo[OS_LONG_HEADER_SIZE];

int CollectorObject::GetConfig() {
    
    ConfigYaml* cy = new ConfigYaml( "collector");
    
    cy->addKey("id");
    cy->addKey("timezone");
    cy->addKey("log_size");
    cy->addKey("startup_timer");
    cy->addKey("sleep_timer");
        
    cy->ParsConfig();
    
    node_id = cy->getParameter("id");
    
    if (!node_id.compare("")) {
        SysLog("config file error: parameter collector id");
        return 0;
    }
    
    timezone = stoi(cy->getParameter("timezone"));
    
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

void Alert::CreateAlertUUID(void) {
    
    std::stringstream ss;
    
    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    ss << uuid; 
    alert_uuid = ss.str();
}


