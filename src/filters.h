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

#ifndef FILTERS_H
#define	FILTERS_H


#include "main.h"
#include "cobject.h"

using namespace std;

// 1. If alert reproduce X times within of period X seconds 
// then if event_id != 0 
// new alert with new event_id
// else alert - msg was repeated several times

// 2. At begin first alert will be sent whithout change if reproduce != 0

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
    string group;
    
    Agent(string i, string a, string n, string s, string d, string v, string m, string op, string ov, string on, string gr) {
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
        group = gr;
    }
};

class Group {
    
public:
    string name;
    int count;
    string ref;
    
            
    Group(string n, int c, string r) {
        name = n;
        count = c;
        ref = r;
    }
};

class Network {
public:
    string network;
    string netmask;
    string node;
    bool alert_suppress;
        
    void Reset() {
        network.clear();
        netmask.clear();
        node.clear();
        alert_suppress = false;
    }
    
    Network () {
        Reset();
    }
};

class Host {
public:
    string name;
    string ip;
    string agent;
    string ec2;
        
    void Reset() {
        name.clear();
        ip.clear();
        agent.clear();
        ec2.clear();
    }
    
    Host (string n, string i, string a, string e) {
        name = n;
        ip = i;
        agent = a;
        ec2 = e;
    }
};

class NetflowPolicy {
public:
    int floodMaxRequests;
    int trafficMaxVolume;
    int floodSeverity;
    int trafficSeverity;
    bool log;
        
    void Reset() {
        floodMaxRequests = 0;
        trafficMaxVolume = 0;
        floodSeverity = 0;
        trafficSeverity = 0;
        log = false;
    }
    
    NetflowPolicy () {
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
    string new_type;
    string new_source;
    string new_event;
    int new_severity;
    string new_category;
    string new_description;
    
    void Reset () {
        profile.clear();
        new_type.clear();
        new_source.clear();
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
    string match;
    
    Aggregator agr;
    Response rsp;
    
    void Reset () {
        event.clear();
        host.clear();
        match.clear();
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
    string name;
    	
    std::vector<Network*> home_nets;
        
    IdsPolicy crs;
           
    IdsPolicy nids;
    
    IdsPolicy hids;
    
    IdsPolicy waf;
    
    NetflowPolicy netflow;
    
    void Reset() {
        ref_id.clear();
        name.clear();
        home_nets.clear();
        crs.Reset();
        nids.Reset();
        hids.Reset();
        waf.Reset();
        netflow.Reset();
    }
};


class FiltersSingleton : public CollectorObject {
public:
    // FS states
    static int status;
    static boost::shared_mutex agents_update;
    static boost::shared_mutex groups_update;
    static boost::shared_mutex filters_update;
    
    static Filters filter;
    
    static std::vector<Agent> agents_list;
    
    static std::vector<Group> groups_list;
    
    static std::vector<Host> hosts_list;
        
    static int GetFiltersConfig();
    static int ParsFiltersConfig(string f);
    
    static void UpdateAgentsList(string id, string ip, string name, string status, 
        string date, string version, string manager, string os_platf, string os_ver, string os_name, string group);
    static void UpdateAgentsList(string id, string ip, string name);
    static void UpdateGroupsListCount(string name, int count);
    static void UpdateGroupsListRef(string name, string ref);
    static string GetAgentIdByName(string name);
    static string GetNameByAgentId(string id);
    static string GetHostnameByIP(string ip);
    static string GetHostnameByAgentname(string agent);
    static string GetRefByAgentName(string name);
    static string GetRefByGroupName(string name);
            
    int GetStatus() { return status; }
};


#endif	/* FILTERS_H */

