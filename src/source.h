/* 
 * File:   source.h
 * Author: Oleg Zharkov
 *
 */

#ifndef SOURCE_H
#define	SOURCE_H

#include <mutex>

#include "hiredis.h"
#include "GeoIP.h"
#include "GeoIPCity.h"

#include "sinks.h"
#include "ids.h"
#include "filters.h"
#include "config.h"

using namespace std;

class Source : public CollectorObject {
public:
    int status;
    string config_key;
    string redis_key;
    static int config_flag;
    
    std::mutex m_monitor_counter;
    unsigned long events_counter;
    unsigned long alerts_counter;
    
    redisReply *reply;
    redisContext *c;
    
    static char maxmind_path[OS_BUFFER_SIZE]; 
    int maxmind_state;
    GeoIP *gi;
    string country_code;
    
    //JSON strings for regex and log output 
    string jsonPayload;
    string report;
            
    // interfaces
    Sinks sk;
    FiltersSingleton fs;
    
    Source () {
        config_key = "";
        status = 0;
        events_counter = 0;
        alerts_counter = 0;
        maxmind_state = 0;
    }
    
    Source (string ckey) {
        config_key = ckey;
        status = 0;
        events_counter = 0;
    }
    
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    virtual int GetStatus() {
        return status;
    }
    
    long ResetEventsCounter();
    void IncrementEventsCounter();
    void sendAlertMultiple(int type_source);
    int CheckHomeNetwork(string ip);
};

#endif	/* SOURCE_H */

