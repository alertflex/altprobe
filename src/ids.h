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
    string hostname;
    string location;
    string action;
    int event;
    int severity;
    string desc;  
                    
    std::vector<string> list_cats;
    
    // for checking of reproduce the alert
    Aggregator agr;
    int count;
    time_t alert_time;
        
    void Reset() {
        ref_id.clear();
        ids_type = 0;
        src_ip.clear();
        dst_ip.clear(); 
        hostname.clear(); 
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
    
    unsigned int hids_alerts_list;
    
    unsigned int nids_alerts_list;
    
    unsigned int nids_srcip;
    
    unsigned int nids_dstip;
    
    unsigned int hids_hostname;
    
    unsigned int hids_location;
    
    unsigned int fim_file;
    
    unsigned int fim_cause;
    
    unsigned int ids_category;
    
    unsigned int ids_event;
    
};

extern boost::lockfree::spsc_queue<IdsRecord> q_hids;
extern boost::lockfree::spsc_queue<IdsRecord> q_nids;

#endif	/* IDS_H */

