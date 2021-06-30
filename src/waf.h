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

#ifndef WAF_H
#define WAF_H

#include <string>
#include <vector>

#include "hiredis.h"

#include "sinks.h"
#include "ids.h"
#include "filters.h"
#include "config.h"
#include "source.h"
#include "netstat.h"

using namespace std;

//  ModeSecurity record                              
class ModsecAudit {
public:
    
    unsigned int severity;
    string id;
    string hostname;
    string client;
    string uri;
    string file; //location
    string msg;  // info
        
    vector<string> list_tags; //categories
    
    void Reset() {
        
        /* Extracted from the decoders */
        severity = 0;
        id.clear();
        file.clear();
        msg.clear();
        client.clear();
        hostname.clear();
        uri.clear();
        
        list_tags.clear();
    }
};


//  ModeSecurity record                              
class ModsecRecord : CollectorObject {
public:    
    
    bool mod_rec;
    
    string sensor;
    ModsecAudit ma;
    
    string buffer;
    string parameters;
        
    vector<string> strs;
    
    ModsecRecord() {
        mod_rec = false;
    }
            
    bool IsModsec(const string str) {
        mod_rec = str.find("ModSecurity: Warning") != str.npos;
        return mod_rec;
    } 
    
    void GetClient(const string str); 
    void GetAuditHeader(const string str); 
    void CheckAuditFields(const string str);
    void RemoveAuditParametersName(const string field, const string str);
    int ParsRecord(const string rec);
    
    void Reset() {
        
        mod_rec = false;
        sensor.clear();
        ma.Reset();
        strs.clear();
        buffer.clear();
        parameters.clear();
    }
};

namespace bpt = boost::property_tree;

class Waf : public Source {
public:
    
    FILE *fp;
    struct stat buf;
    unsigned long file_size;
    int ferror_counter;
    char file_payload[OS_PAYLOAD_SIZE];
    
    // ModSecurity record
    ModsecRecord rec;
    
    // create netflow record
    Netflow net_flow;
    
    string event_time;
        
    bpt::ptree pt;
    stringstream ss;
    
    Waf (string skey) : Source(skey) {
        ClearRecords();
        ResetStreams();
        ferror_counter = 0;
    }
    
    void ResetStreams() {
        ss.str("");
        ss.clear();
    }
    
    void ResetJsontree() {
        pt.clear();
    }
    
    int Open();
    void Close();
    int ReadFile();
    void IsFileModified();
    int Go();
        
    int ParsJson ();
    
    GrayList* CheckGrayList();
    void CreateLog();
    void SendAlert (int s, GrayList*  gl);
    int PushRecord(GrayList* gl);
        
    void ClearRecords() {
        event_time.clear();
	rec.Reset();
        net_flow.Reset();
        jsonPayload.clear();
        ResetJsontree();
    }
    
};

extern boost::lockfree::spsc_queue<string> q_logs_waf;

#endif /* WAF_H */

