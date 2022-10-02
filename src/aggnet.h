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

class AggNet : public Source {
public: 
    
    Netstat netstat_rec;
    Netflow netflow_rec;
    
    int counter;
    
    //Statistics data
    std::vector<Netstat> netstat_list;
    
    std::vector<Country> countries;
        
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    int Go();
    void ProcessNetData();
    void RoutineJob();
        
    bool UpdateNetstat(Netstat ns);
    void FlushNetStat();
    
    void UpdateCountries(Netflow nf);
    void FlushCountries();
    
};

extern boost::lockfree::spsc_queue<string> q_agg_net;

#endif /* AGGNET_H */

