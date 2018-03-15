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
    static int timezone;
    static int log_size;
    static long startup_timer;
    static long gosleep_timer;
            
    char collector_time[OS_DATETIME_SIZE]; 
    
    //Syslog info string
    static char SysLogInfo[OS_LONG_HEADER_SIZE];
    
    CollectorObject () {
        node_id.clear();
    }
    
    string GetNodeId()  { return node_id; }
    virtual int GetConfig();
    
    string GetNodeTime();
    string GetGraylogFormat();
    void ReplaceAll(string& input, const string& from, const string& to);
    
    long GetStartupTimer() { return startup_timer; }
    long GetGosleepTimer() { return gosleep_timer; }
    
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

class Alert : public Event {
public:    
    // Record
    string alert_uuid;
    string source;
    string type;
    int event;
    int severity;
    string description;
    string srcip;
    string dstip;
    string hostname;
    string location;
    string action;
    string status;
    string info;
    string event_json;
    
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
        hostname.clear();
        status.clear();
        info.clear();
        event_json.clear();
        
        list_cats.clear();
    }
    
    void CreateAlertUUID(void);
};

#endif	/* COBJECT_H */

