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

class Network {
public:
    string network;
    string netmask;
};

class Aggregate {
public:
    int reproduced;
    int in_period;
    int new_event;
    int new_severity;
    string new_category;
    string new_description;
};

class BwList {
public:  
    int event;
    string ip;
    string action;
    Aggregate agr;
};

class IdsPolicy {
public: 
    
    int severity;
    bool log;
    
    std::vector<BwList*> bwl;
};

class Threshold {
public: 
    string ip;
    string app_proto;
    string action;
    
    long int traffic_min;
    long int traffic_max;
    long int traffic_count;
        
    time_t trigger_time;
    
    Aggregate agr;
        
    void Reset() {
        traffic_count = 0;
        trigger_time = time(NULL);
    }
    
    Threshold () {
        ip.clear();
        action.clear();
        app_proto.clear();
        Reset();
    }
};

class TrafficPolicy {
public:
    
    int top_talkers;
    bool log;
    
    std::vector<Threshold*> th;
    
};

class Filters {
public:
    string ref_id;
    string name;
    	
    std::vector<Network*> home_nets;
           
    IdsPolicy nids;
    
    IdsPolicy hids;
    
    TrafficPolicy traffic;
};


class FiltersSingleton : public CollectorObject {
public:
    // FS states
    static int status;
    
    // Buffer for data
    static char* config_data;
    static int config_data_len;

    // local file settings
    static FILE *f;
    static char config_file[OS_STRING_SIZE];

    static Filters filter;
    
    static int GetFiltersConfig();
    static int ParsConfig();
    static void Update(string f) {
        
    }
    
    int GetStatus() { return status; }
};


#endif	/* FILTERS_H */

