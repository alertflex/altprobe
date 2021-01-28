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

class AggNet : public Source {
public: 
    
    Netstat netstat_rec;
    int counter;
        
    //Statistics data
    std::vector<Netstat> netstat_list;
        
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    int Go();
    void ProcessNetstat();
    void RoutineJob();
    
    bool UpdateNetstat(Netstat ns);
    void FlushNetstat();
        
};

extern boost::lockfree::spsc_queue<string> q_agg_net;

#endif /* AGGNET_H */

