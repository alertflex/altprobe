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
    int ids_type; // 1 - nids, 2 - hids, 3 - fim
    string src_ip;             
    string dst_ip;         
    string hostname;
    string location;
    int event;
    int severity;
    string desc;  
    string action;
            
    std::vector<string> list_cats;
    
    // for checking of reproduce the alert
    Aggregate agr;
    int count;
    time_t alert_time;
    
    void Reset() {
        ref_id.clear();
        ids_type = 0;
        src_ip.clear();
        dst_ip.clear(); 
        hostname.clear(); 
        location.clear(); 
        event = 0;
        severity = 0;
        desc.clear(); 
        action.clear(); 
                
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

extern boost::lockfree::spsc_queue<IdsRecord> q_ids;

#endif	/* IDS_H */

