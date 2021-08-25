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

class TrafficThresholds {
public:
    string ref_id;
    int type; // 1 - suri, 2 - modsec-waf, 3 - aws-waf
    string ids;
    string ip;
    unsigned int volume;
    unsigned int counter;
                
    void Reset() {
        ref_id.clear();
        type = 0;
        ids.clear();
        ip.clear();
        volume = 0;
        counter = 0;
    }
        
    TrafficThresholds (string r, int t, string id, string i, unsigned int v) {
        ref_id = r;
        type = t;
        ids = id;
        ip = i;
        volume = v;
        counter = 1;
    }
};

class AggNet : public Source {
public: 
    
    Netstat netstat_rec;
    Netflow netflow_rec;
    int counter;
        
    //Statistics data
    std::vector<Netstat> netstat_list;
    
    //TrafficThresholds data
    std::vector<TrafficThresholds> traf_thres;
            
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    int Go();
    void ProcessNetData();
    void RoutineJob();
        
    bool UpdateNetstat(Netstat ns);
    void UpdateTrafficThresholds(Netflow nf);
    void FlushTrafficThresholds();
    
    void SendAlertFlood(std::vector<TrafficThresholds>::iterator r);
    void SendAlertTraffic(std::vector<TrafficThresholds>::iterator r);
            
};

extern boost::lockfree::spsc_queue<string> q_agg_net;

#endif /* AGGNET_H */

