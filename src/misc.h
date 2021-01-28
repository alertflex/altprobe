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

#ifndef MISC_H
#define	MISC_H

#include "source.h"

using namespace std;
namespace bpt = boost::property_tree;

class Misc : public Source {
public:
    
    bpt::ptree pt;
    stringstream ss;
    
    Misc (string skey) : Source(skey) {
        ClearRecords();
        ResetStream();
    }
    
    void ResetStream() {
        ss.str("");
        ss.clear();
    }
    
    void ResetJsontree() {
        pt.clear();
    }
    
    int Open();
    void Close();
    int Go();
    
    int ParsJson (char* redis_payload);
    
    void ClearRecords() {
        
        ResetJsontree();
        jsonPayload.clear();
        
    }
};

extern boost::lockfree::spsc_queue<string> q_logs_misc;

#endif	/* MISC_H */


