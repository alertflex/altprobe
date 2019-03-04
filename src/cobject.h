/* 
 * File:   cobject.h
 * Author: Oleg Zharkov
 *
 */

#ifndef COBJECT_H
#define	COBJECT_H

#include "main.h"
#include "config.h"

using namespace std;

class CollectorObject {
public:
    
    //
    static string node_id;
    static string sensor_id;
    
    static char active_response[OS_HEADER_SIZE];
    static char remote_upload[OS_HEADER_SIZE];
        
    static bool arStatus;
    static bool uploadStatus;
                
    static int timezone;
    static int log_size;
    
    static long startup_timer;
    static long gosleep_timer;
    static long update_timer;
        
    // Wazuh config parameters
    static char wazuh_host[OS_HEADER_SIZE];
    static int wazuh_port;
    static char wazuh_user[OS_HEADER_SIZE];
    static char wazuh_pwd[OS_HEADER_SIZE];
    
    static bool wazuhServerStatus;
        
    static char suri_path[OS_BUFFER_SIZE]; 
    static char suri_rules[OS_BUFFER_SIZE];
    static char suri_iprep[OS_BUFFER_SIZE];
    
    static char wazuh_path[OS_BUFFER_SIZE];
    static char wazuh_rules[OS_BUFFER_SIZE];
    static char wazuh_iprep[OS_BUFFER_SIZE];
    
    static char modsec_path[OS_BUFFER_SIZE];
    static char modsec_rules[OS_BUFFER_SIZE];
    static char modsec_iprep[OS_BUFFER_SIZE];
    
    
    char collector_time[OS_DATETIME_SIZE]; 
    
    //Syslog info string
    static char SysLogInfo[OS_LONG_HEADER_SIZE];
    
    CollectorObject () {
        node_id.clear();
        sensor_id.clear();
        wazuhServerStatus = true;
        arStatus = true;
        uploadStatus = true;
        timezone = 0;
        log_size = 0;
        startup_timer = 0;
        gosleep_timer = 0;
        update_timer = 0;
        wazuh_port = 0;
    }
    
    string GetNodeId()  { return node_id; }
    virtual int GetConfig();
    
    string GetNodeTime();
    string GetGraylogFormat();
    void ReplaceAll(string& input, const string& from, const string& to);
    
    long GetStartupTimer() { return startup_timer; }
    long GetGosleepTimer() { return gosleep_timer; }
    long GetUpdateTimer() { return update_timer; }
    
    static void SysLog(char* info);
    static int ValidDigit(char* ip_str);
    static int IsValidIp(string ip);
    static uint32_t IPToUInt(string ip);
    static bool IsIPInRange(string ip, string network, string mask);
    static unsigned int GetBufferSize(char* source);
};

class Event {
public:
    int event_type;
    
    string ref_id;
    
    void Reset() {
        ref_id.clear();
        event_type  = 0;
    }
};

class BinData : public Event {
public:   
    string data;
    
    void Reset() {
        Event::Reset();
        data.clear();
    }
    
    BinData () {
        data.clear();
        event_type = 2;
    }
};

class Rule : public BinData {
public:   
    string name_rule;
        
    void Reset() {
        BinData::Reset();
        name_rule.clear();
    }
    
    Rule () {
        data.clear();
        name_rule.clear();
        event_type = 6;
    }
};

class Alert : public Event {
public:    
    // Record
    string alert_uuid;
    string source;
    string type;
    int event;
    int severity;
    int score;
    string description;
    string srcip;
    string dstip;
    string srcagent;
    string dstagent;
    unsigned int srcport;
    unsigned int dstport;
    string user;
    string sensor;
    string location;
    string action; 
    string filter;
    string status;
    string info;
    string event_json;
    string event_time;
        
    std::vector<string> list_cats;
    
    void Reset() {
        Event::Reset();
        event_type = 0;
        alert_uuid.clear();
        source.clear();
        type.clear();
        event =  0; 
        severity = 0; 
        description.clear();
        srcip.clear();
        dstip.clear();
        action.clear();
        location.clear();
        user.clear();
        status.clear();
        info.clear();
        event_json.clear();
        // new
        score = 0;
        srcagent.clear();
        dstagent.clear();
        srcport = 0;
        dstport = 0;
        sensor.clear();
        filter.clear();
        event_time.clear();
        
        list_cats.clear();
    }
    
    void CreateAlertUUID(void);
};

#endif	/* COBJECT_H */

