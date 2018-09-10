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
    int ids_type; // 1 - fim, 2 - hids, 3 - nids, 4 - waf
    string src_ip;             
    string dst_ip; 
    string agent;
    string user;
    string ids;
    string location;
    string action;
    int event;
    int severity;
    string desc;  
                    
    std::vector<string> list_cats;
    
    // for checking of reproduce the alert
    Aggregator agr;
    Response rsp;
    
    int count;
    time_t alert_time;
        
    void Reset() {
        ref_id.clear();
        ids_type = 0;
        src_ip.clear();
        dst_ip.clear(); 
        agent.clear();
        user.clear();
        ids.clear(); 
        location.clear(); 
        action.clear();
        event = 0;
        severity = 0;
        desc.clear(); 
                                
        list_cats.clear();
        
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

class IdsBuffers {
public:
    
    unsigned long hids_alerts_list;
    
    unsigned long nids_alerts_list;
    
    unsigned long nids_srcip;
    
    unsigned long nids_dstip;
    
    unsigned long hids_srcip;
    
    unsigned long hids_location;
    
    unsigned long fim_file;
    
    unsigned long fim_cause;
    
    unsigned long ids_category;
    
    unsigned long ids_event;
    
    unsigned long waf_source;
    
    unsigned long waf_target;
    
    unsigned long user_event;
    
};

extern boost::lockfree::spsc_queue<IdsRecord> q_hids;
extern boost::lockfree::spsc_queue<IdsRecord> q_nids;

#endif	/* IDS_H */

