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

#ifndef AGGNET_H
#define AGGNET_H

#include "netstat.h"
#include "filters.h"
#include "config.h"
#include "source.h"

using namespace std;

class Counters {
public:
    
    string ref_id;
    string sensor;
    int type; // 0 - suri, 1 - aws-fw, 2 - modsec-waf, 3 - aws-waf
   
    long bytes; 
    long sessions; 
       
    Counters (string ref, string sen, int t, unsigned long b, unsigned long ses) {  
        ref_id = ref;
        sensor = sen;
        type = t;
        bytes = b;
        sessions = ses;
    }
    
    void ResetCounters() {
        ref_id.clear();
        sensor.clear();
        type = 0;
        bytes = 0;
        sessions = 0;
    }
    
};

class TopTalker : public Counters {
public:  
    
    string src_ip;
    string dst_ip;
    string src_country;
    string dst_country;
    string src_hostname;
    string dst_hostname;
        
                
    void Reset() {
        src_ip.clear();
        dst_ip.clear();
        src_country.clear();
        dst_country.clear();
        src_hostname.clear();
        dst_hostname.clear();
        ResetCounters();
    }
        
    TopTalker (string ref, string sen, int t, unsigned long b, unsigned long ses, string srcip, string dstip, string scc, string dcc, string sh, string dh) 
        : Counters(ref, sen, t, b, ses) {
        src_ip = srcip;
        dst_ip = dstip;
        src_country = scc;
        dst_country = dcc;
        src_hostname = sh;
        dst_hostname = dh;
    }
};

class Country : public Counters {
public:  
    
    string country;
               
    void Reset() {
        country.clear();
        ResetCounters();
    }
        
    Country (string ref, string sen, int t, unsigned long b, unsigned long ses, string cc) : Counters(ref, sen, t, b, ses) {
        country = cc;
    }
};

class TrafficThresholds : public Counters {
public:
    string ip;
                    
    void Reset() {
        ip.clear();
        ResetCounters();
    }
        
    TrafficThresholds (string ref, string sen, int t, unsigned long b, unsigned long ses, string i) : Counters(ref, sen, t, b, ses) {
        ip = i;
    }
};

class AggNet : public Source {
public: 
    
    Netstat netstat_rec;
    Netflow netflow_rec;
    
    int counter;
        
    //Statistics data
    std::vector<Netstat> netstat_list;
    
    std::vector<TopTalker> top_talkers;
    
    std::vector<Country> countries;
    
    //TrafficThresholds data
    std::vector<TrafficThresholds> traf_thres;
            
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    int Go();
    void ProcessNetData();
    void RoutineJob();
        
    bool UpdateNetstat(Netstat ns);
    void FlushNetStat();
    
    void UpdateTrafficThresholds(Netflow nf);
    void FlushTrafficThresholds();
    
    void UpdateTopTalkers(Netflow nf);
    void FlushTopTalkers();
    
    void UpdateCountries(Netflow nf);
    void FlushCountries();
    
    void SendAlertFlood(std::vector<TrafficThresholds>::iterator r);
    void SendAlertTraffic(std::vector<TrafficThresholds>::iterator r);
            
};

extern boost::lockfree::spsc_queue<string> q_agg_net;

#endif /* AGGNET_H */

