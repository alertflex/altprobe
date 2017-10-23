/* 
 * File:   cobject.h
 * Author: Oleg Zharkov
 *
 */

#ifndef COBJECT_H
#define	COBJECT_H

#include <mutex>

#include "main.h"
#include "config.h"

using namespace std;

class CollectorObject {
public:
    //
    static string node_id;
    static int timezone;
    static long startup_timer;
    static long gosleep_timer;
    static int log_size;
    
    std::mutex m_monitor_counter;
    unsigned long events_counter;
    
    char collector_time[OS_DATETIME_SIZE]; 
    
    //Syslog info string
    static char SysLogInfo[OS_LONG_HEADER_SIZE];
    
    CollectorObject () {
        node_id.clear();
        events_counter = 0;
    }
    
    string GetNodeId()  { return node_id; }
    virtual int GetConfig();
    static void SysLog(char* info);
    string GetNodeTime();
    string GetGraylogFormat();
    
    long GetStartupTimer() { return startup_timer; }
    long GetGosleepTimer() { return gosleep_timer; }
    
    int ValidDigit(char* ip_str);
    int IsValidIp(string ip);
    uint32_t IPToUInt(string ip);
    bool IsIPInRange(string ip, string network, string mask);
    unsigned int GetBufferSize(char* source);
    
    long ResetEventsCounter() {
        unsigned long r;
        
        m_monitor_counter.lock();
        r = events_counter;
        events_counter = 0;
        m_monitor_counter.unlock();
        
        return r;
    }
    
    void IncrementEventsCounter() {
        m_monitor_counter.lock();
        events_counter++;
        m_monitor_counter.unlock();
    }
    
    void IncrementEventsCounter(int inc) {
        m_monitor_counter.lock();
        events_counter = events_counter + inc;
        m_monitor_counter.unlock();
    }
};

enum EventType { et_alert, et_nids_srcip, et_nids_dstip, et_hids_hostname, et_hids_location, et_ids_cat, et_ids_event, et_flow_appl, et_flow_countries, et_flow_talkers, et_flow_traffic, et_flow_proto, et_node_monitor, et_log };

class Event {
public:
    EventType type;
    
    string ref_id;
    
    void Reset() {
        ref_id.clear();
    }
    
    EventType GetEventType() {
        return type;
    }
    
    void SetEventType(EventType t) {
        type = t;
    }
};

class Report : public Event {
public:   
    string info;
    
    void Reset() {
        Event::Reset();
        
        info.clear();
    }
        
    string GetReportInfo() {
        return info;
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

