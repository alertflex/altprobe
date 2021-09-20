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
    int redis_status;
    string config_key;
    string redis_key;
    static int config_flag;
    
    GeoIP *gi;
    string src_cc;
    string src_latitude;
    string src_longitude;
    string dst_cc;
    string dst_latitude;
    string dst_longitude;
    
    std::mutex m_monitor_counter;
    unsigned long events_counter;
    unsigned long alerts_counter;
    
    redisReply *reply;
    redisContext *c;
    
    //JSON strings for regex and log output 
    string jsonPayload;
    string report;
    
    // interfaces
    Sinks sk;
    FiltersSingleton fs;
    
    Source () {
        config_key = "indef";
        src_cc = "indef";
        src_latitude = "0.0";
        src_longitude = "0.0";
        dst_cc = "indef";
        dst_latitude = "0.0";
        dst_longitude = "0.0";
        status = 1;
        redis_status = 1;
        events_counter = 0;
        alerts_counter = 0;
    }
    
    Source (string ckey) {
        config_key = ckey;
        status = 1;
        redis_status = 1;
        events_counter = 0;
        alerts_counter = 0;
    }
    
    virtual int GetConfig();
    
    virtual int GetStatus() {
        return status;
    }
    
    long ResetEventsCounter();
    void IncrementEventsCounter();
    void SendAlertMultiple(int type);
    string GetHostname(string ip);
    bool SuppressAlert(string ip);
    void SetGeoBySrcIp(string ip);
    void SetGeoByDstIp(string ip);
    
};

#endif	/* SOURCE_H */

