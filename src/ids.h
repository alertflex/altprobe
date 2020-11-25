/* 
 * File:   ids.h
 * Author: Oleg Zharkov
 *
 * Created on June 15, 2015, 8:57 PM
 */

#ifndef IDS_H
#define	IDS_H

#include "main.h"
#include "filters.h"

using namespace std;

class IdsRecord
{
public:
    
    string ref_id;
    int ids_type; // 1 - fim, 2 - hids, 3 - nids, 4 - waf, 5 - crs
    string src_ip;             
    string dst_ip; 
    string ids;
    string location;
    string action;
    int severity;
    string desc; 
    
    string event; 
    string process;
    string file;
    string user;
    string agent;
    string container;
    
                        
    std::vector<string> list_cats;
    
    // for checking of reproduce the alert
    bool filter = false;
    
    string match;
    string host;
    
    Aggregator agr;
    Response rsp;
    
    int count;
    time_t alert_time;
        
    void Reset() {
        
        ref_id.clear();
        ids_type = 0;
        src_ip.clear();
        dst_ip.clear(); 
        ids.clear(); 
        location.clear(); 
        action.clear();
        severity = 0;
        desc.clear(); 
        
        user.clear();
        event.clear(); 
        process.clear();
        file.clear();
        agent.clear();
        container.clear();
        
        list_cats.clear();
        
        filter = false;
        
        match.clear();
        host.clear();
        
        agr.reproduced = 0;
        count = 0;
        alert_time = time (NULL);
    }
    
    IdsRecord () {
        Reset();
    }
    
    ~IdsRecord () {
        Reset();
    }
};

class IdsStat {
public:
    
    unsigned long filter_counter;
    unsigned long agg_counter;
    unsigned long s0_counter;
    unsigned long s1_counter;
    unsigned long s2_counter;
    unsigned long s3_counter;
    
    void Reset() {
        filter_counter = 0;
        agg_counter = 0;
        s0_counter = 0;
        s1_counter = 0;
        s2_counter = 0;
        s3_counter = 0;
    }
    
    IdsStat () {
        Reset();
    }
    
    ~IdsStat () {
        Reset();
    }
};

extern boost::lockfree::spsc_queue<IdsRecord> q_hids;
extern boost::lockfree::spsc_queue<IdsRecord> q_nids;
extern boost::lockfree::spsc_queue<IdsRecord> q_waf;
extern boost::lockfree::spsc_queue<IdsRecord> q_crs;

#endif	/* IDS_H */

