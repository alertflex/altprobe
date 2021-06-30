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

#ifndef NIDS_H
#define	NIDS_H


#include "sinks.h"
#include "ids.h"
#include "netstat.h"
#include "filters.h"
#include "config.h"
#include "source.h"

using namespace std;

class SuricataAlert
{
public:
    string action;
    unsigned int gid;
    long signature_id;
    string signature;
    string category;
    unsigned int severity;
    
    void Reset() {
        action.clear();
        gid = 0;
        signature_id = 0;
        signature.clear();
        category.clear();
        severity = 0;
    }
};


class SuricataDns
{
public:
    string type;
    unsigned int id;
    string rrname;
    string rcode;
    string rrtype;
    unsigned int tx_id;
    unsigned int ttl;
    string rdata;
    
    void Reset() {
        type.clear();
        id = 0;
        rrname.clear();
        rcode.clear();
        rrtype.clear();
        rdata.clear();
        tx_id = 0;
        ttl = 0;
    }
};

class SuricataHttp
{
public:
    string hostname;
    string url;
    string http_user_agent;
    string http_content_type;
    
    void Reset() {
        hostname.clear();
        url.clear();
        http_user_agent.clear();
        http_content_type.clear();
    }
};

class SuricataNetflow
{
public:
    string app_proto;
    unsigned int pkts;
    unsigned int bytes;
    string start;
    string end;
    int age;
    
    void Reset() {
        app_proto.clear();
        bytes = 0;
        pkts = 0;
        age = 0;
        start.clear();
        end.end();
    }
};

class SuricataFile
{
public:
    string name;
    unsigned int size;
    string state;
    string md5;
    string app_proto;
        
    void Reset() {
        
        name.clear();
        size = 0;
        state.clear();
        md5.clear();
        app_proto.clear();
    }
};

//  Suricata record                              
class SuricataRecord {
public:
    
    // *** Common fields
    string ref_id;
    int event_type;
    string time_stamp;
    string iface;
    long flow_id;
        
    string src_agent;
    string src_ip;
    unsigned int src_port;
    
    string dst_agent;
    string dst_ip;
    unsigned int dst_port;
    
    string sensor;
    string protocol;
            
    //  Record  Alert 
    SuricataAlert alert;
    //  Record  DNS 
    SuricataDns dns;
    //  Record  Flow
    SuricataNetflow netflow;
    //  Record  File
    SuricataFile file;
    //  Record  HTTP
    SuricataHttp http;
    
    
    void Reset() {
        //reset rule class object
        ref_id.clear();
        event_type = 0;
        time_stamp.clear();
        iface.clear();
        flow_id = 0;
        src_agent.clear();
        src_ip.clear();
        src_port = 0;
        dst_agent.clear();
        dst_ip.clear();
        dst_port = 0;
        protocol.clear();
        sensor.clear();    
        
        alert.Reset();
        dns.Reset();
        netflow.Reset();
        file.Reset();
        http.Reset();
    }
};

namespace bpt = boost::property_tree;

class Nids : public Source {
public: 
    
    FILE *fp;
    struct stat buf;
    unsigned long file_size;
    int ferror_counter;
    char file_payload[OS_PAYLOAD_SIZE];
    
    //Suricata record
    SuricataRecord rec;
    int counter_repetition;
    
    // create netstat record
    Netstat net_stat;
    // create netflow record
    Netflow net_flow;
    
    bpt::ptree pt, pt1;
    stringstream ss, ss1;
    
    Nids (string skey) : Source(skey) {
        ClearRecords();
        ResetStream();
        ferror_counter = 0;
    }
    
    void ResetStream() {
        ss.str("");
        ss.clear();
        ss1.str("");
        ss1.clear();
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
    bool CheckFlowsLog(int r);
    void CreateLogPayload(int r);
    void SendAlert (int s, GrayList* gl);
    int PushIdsRecord(GrayList* gl);
                        
    void ClearRecords() {
        rec.Reset();
        net_stat.Reset();
        net_flow.Reset();
        ResetJsontree();
        jsonPayload.clear();
    }
};

extern boost::lockfree::spsc_queue<string> q_logs_nids;

#endif	/* NIDS_H */

