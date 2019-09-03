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

// 4. field location = "altprobe collector"

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
    string node;
    bool alert_suppress;
        
    void Reset() {
        node.clear();
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
        
    void Reset () {
        reproduced = 0;
        in_period = 0;
    }
    
    Aggregator () {
        Reset();
    }
};

class Response {
public:
    string profile;
    string new_event;
    int new_severity;
    string new_category;
    string new_description;
    
    void Reset () {
        profile.clear();
        new_event.clear();
        new_category.clear();
        new_description.clear();
    }
    
    Response () {
        Reset();
    }
};

class GrayList {
public:  
    string event;
    string host;
    
    Aggregator agr;
    Response rsp;
    
    void Reset () {
        event.clear();
        host.clear();
        
    }
    
    GrayList () {
        Reset();
    }
};

class Severity {
public: 
    
    int threshold;
    int level0;
    int level1;
    int level2;
        
    void Reset() {
        threshold = 0;
        level0 = 0;
        level1 = 0;
        level2 = 0;
    }
};


class IdsPolicy {
public: 
    
    bool log;
    Severity severity;
    
    std::vector<GrayList*> gl;
    
    void Reset() {
        gl.clear();
        severity.Reset();
        log = false;
    }
};


class Filters {
public:
    string ref_id;
    string desc;
    	
    std::vector<Network*> home_nets;
    std::vector<Alias*> alias;
    
    IdsPolicy crs;
           
    IdsPolicy nids;
    
    IdsPolicy hids;
    
    IdsPolicy waf;
    
    void Reset() {
        ref_id.clear();
        desc.clear();
        home_nets.clear();
        alias.clear();
        crs.Reset();
        nids.Reset();
        hids.Reset();
        waf.Reset();
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
    static string GetAgentIdByName(string name);
    static Alias* GetAliasByAgentName(string name);
        
    int GetStatus() { return status; }
};


#endif	/* FILTERS_H */

