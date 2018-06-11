/* 
 * File:   filters.h
 * Author: Oleg Zharkov
 */

#ifndef FILTERS_H
#define	FILTERS_H


#include "main.h"
#include "cobject.h"

using namespace std;

// 1. If alert reproduce X times within of period X seconds 
// then if event_id != 0 
// new alert with new event_id
// else alert - msg was repeated several times

// 2. At begin first alert will be sended whithout change if reproduce != 0

// 3. If reproduce = 0 then msg will be replaced to new fields parameters

// 4. field location = "alertflex collector"

class Agent {
    
public:
    string id;
    string ip;
    string name;
    string status;
    string dateAdd;
    string version;
    string manager_host;
    string os_platform;
    string os_version;
    string os_name;
    
    Agent(string i, string a, string n, string s, string d, string v, string m, string op, string ov, string on) {
        id = i;
        ip = a;
        name = n;
        status = s; 
        dateAdd = d;
        version = v;
        manager_host = m;
        os_platform = op;
        os_version = ov;
        os_name = on;
    }
};

class Network {
public:
    string network;
    string netmask;
    bool alert_suppress;
    
    void Reset() {
        network.clear();
        netmask.clear();
        alert_suppress = false;
    }
    
    Network () {
        Reset();
    }
};

class Alias {
public:
    string agent_name;
    string host_name;
    string ip;
        
    void Reset() {
        agent_name.clear();
        host_name.clear();
        ip.clear();
    }
    
    Alias () {
        Reset();
    }
};

class Aggregator {
public:
    int reproduced;
    int in_period;
    int new_event;
    int new_severity;
    string new_category;
    string new_description;
    
    void Reset () {
        reproduced = 0;
        in_period = 0;
        new_event = 0;
        new_category.clear();
        new_description.clear();
    }
    
    Aggregator () {
        Reset();
    }
};

class BwList {
public:  
    int event;
    string host;
    string action;
    Aggregator agr;
    
    void Reset () {
        event = 0;
        host.clear();
        action.clear();
    }
    
    BwList () {
        Reset();
    }
};

class IdsPolicy {
public: 
    
    int severity;
    bool log;
    
    std::vector<BwList*> bwl;
    
    void Reset() {
        bwl.clear();
        severity = 0;
        log = false;
    }
};


class Threshold {
public: 
    string host;
    string element;
    string parameter;
    string action;
    
    long int value_min;
    long int value_max;
    long int value_count;
        
    time_t trigger_time;
    
    Aggregator agr;
        
    void Reset() {
        value_count = 0;
        value_min = 0;
        value_max = 0;
        trigger_time = time(NULL);
        host.clear();
        action.clear();
        element.clear();
        parameter.clear();
    }
    
    Threshold () {
        Reset();
    }
};

class NetflowPolicy {
public:
    
    int top_talkers;
    bool log;
    
    std::vector<Threshold*> th;
    
    void Reset() {
        th.clear();
        top_talkers = 0;
        log = false;
    }
    
};

class MetricPolicy {
public:
    
    int severity;
    bool log;
    
    std::vector<Threshold*> th;
    
    void Reset() {
        th.clear();
        severity = 0;
        log = false;
    }
    
};

class Filters {
public:
    string ref_id;
    string desc;
    	
    std::vector<Network*> home_nets;
    std::vector<Alias*> alias;
           
    IdsPolicy nids;
    
    IdsPolicy hids;
    
    IdsPolicy waf;
    
    MetricPolicy metric;
    
    NetflowPolicy traf;
    
    void Reset() {
        ref_id.clear();
        desc.clear();
        home_nets.clear();
        alias.clear();
        nids.Reset();
        hids.Reset();
        waf.Reset();
        traf.Reset();
        metric.Reset();
    }
};


class FiltersSingleton : public CollectorObject {
public:
    // FS states
    static int status;
    static boost::shared_mutex agents_update;
    static boost::shared_mutex filters_update;
    
    static Filters filter;
    
    static std::vector<Agent> agents_list;
        
    static int GetFiltersConfig();
    static int ParsFiltersConfig(string f);
    
    static void UpdateAgentsList(string id, string ip, string name, string status, 
        string date, string version, string manager, string os_platf, string os_ver, string os_name);
    static string GetAgentNameByIP(string ip);
    static Alias* GetAliasByAgentName(string name);
        
    int GetStatus() { return status; }
};


#endif	/* FILTERS_H */

