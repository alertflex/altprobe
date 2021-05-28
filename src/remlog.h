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

#ifndef REMLOG_H
#define	REMLOG_H

#include "sinks.h"
#include "source.h"
#include "hids.h"
#include "nids.h"
#include "crs.h"
#include "waf.h"
#include "aws.h"

using namespace std;

class RemLog : public Source {
public:  
    
    unsigned long events_volume;
    
    int counter;
    int timeout;
    
    std::stringstream ss, comp;
        
    string rec;
    BinData bd;
    
    //logs 
    std::vector<string> logs_list;
    
    RemLog () {
        events_volume = 0;
        counter = 0;
        timeout = 0;
        
        ResetStreams();
    }
    
    void ResetStreams() {
        comp.str("");
        comp.clear();
        ss.str("");
        ss.clear();
    }
    
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    int Go();
    void ProcessLogs();
    long ResetEventsVolume();
    void IncrementEventsVolume(int inc);
};

#endif	/* REMLOG_H */

