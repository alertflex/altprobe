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

#ifndef AWS_WAF_H
#define AWS_WAF_H

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


//  AWS WAF record                              
class AwsWafRecord : CollectorObject {
public:
    
    bool is_alert;
    string httpSourceName;
    string httpSourceId;
    string webaclId;
    
    unsigned int severity;
    
    string terminatingRuleId;
    string terminatingRuleType;
    
    string ruleGroupId;
    string ruleId;
    string action; // BLOCK or ALLOW , if block then alert
    
    string clientIp;
    string country;
    string uri;
    string args;
    string httpMethod;
    string host;
    
    vector<string> list_cats; //categories
    
    void Reset() {
        is_alert = false;
        httpSourceName.clear();
        httpSourceId.clear();
        webaclId.clear();
        severity = 0;
        terminatingRuleId.clear();
        terminatingRuleType.clear();
        ruleGroupId.clear();
        ruleId.clear();
        action.clear();
        clientIp.clear();
        country.clear();
        uri.clear();
        args.clear();
        httpMethod.clear();
        host.clear();
        
        list_cats.clear();
    }
};

namespace bpt = boost::property_tree;

class AwsWaf : public Source {
public:
    
    AwsWafRecord rec;
    
    // create netflow record
    Netflow net_flow;
    
    bpt::ptree pt;
    stringstream ss;
    
    AwsWaf (string skey) : Source(skey) {
        ClearRecords();
        ResetStreams();
    }
    
    int Open();
    void Close();
    int Go();
        
    int ParsJson ();
    
    GrayList* CheckGrayList();
    void CreateLog();
    void SendAlert (int s, GrayList*  gl);
    int PushRecord(GrayList* gl);
    
    void ResetStreams() {
        ss.str("");
        ss.clear();
    }
    
    void ResetJsontree() {
        pt.clear();
    }
        
    void ClearRecords() {
        net_flow.Reset();
        rec.Reset();
        jsonPayload.clear();
        ResetJsontree();
        dst_cc = "indef";
        dst_latitude = "0.0";
        dst_longitude = "0.0";
        src_cc = "indef";
        src_latitude = "0.0";
        src_longitude = "0.0";
    }
    
};

extern boost::lockfree::spsc_queue<string> q_logs_aws;

#endif /* AWS_WAF_H */

