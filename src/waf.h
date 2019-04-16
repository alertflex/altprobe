/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   waf.h
 * Author: root
 *
 * Created on May 27, 2018, 2:35 PM
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

using namespace std;

//  ModeSecurity record                              
class ModsecAudit {
public:
    
    unsigned int id;
    unsigned int severity;
    string hostname;
    string uri;
    string file; //location
    string msg;  // info
        
    vector<string> list_tags; //categories
    
    void Reset() {
        
        /* Extracted from the decoders */
        id = 0;
        severity = 0;
        file.clear();
        msg.clear();
        hostname.clear();
        uri.clear();
        
        list_tags.clear();
    }
};


//  ModeSecurity record                              
class ModsecRecord : CollectorObject {
public:    
    
    bool mod_rec;
    
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
    
    void GetAuditHeader(const string str); 
    void CheckAuditFields(const string str);
    void RemoveAuditParametersName(const string field, const string str);
    int ParsRecord(const string rec);
    
    void Reset() {
        
        mod_rec = false;
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
    int eof_counter;
    char file_payload[OS_PAYLOAD_SIZE];
    
    // ModSecurity record
    ModsecRecord rec;
    
    string event_time;
        
    bpt::ptree pt;
    stringstream ss;
    
    Waf (string skey) : Source(skey) {
        ClearRecords();
        ResetStreams();
        eof_counter = 0;
    }
    
    void ResetStreams() {
        ss.str("");
        ss.clear();
    }
    
    void ResetJsontree() {
        pt.clear();
    }
    
    virtual int Open();
    virtual void Close();
    int ReadFile(void);
    int Go();
        
    int ParsJson ();
    
    GrayList* CheckGrayList();
    void CreateLog();
    void SendAlert (int s, GrayList*  gl);
    int PushRecord(GrayList* gl);
        
    void ClearRecords() {
        event_time.clear();
	rec.Reset();
        jsonPayload.clear();
        ResetJsontree();
    }
    
};

extern boost::lockfree::spsc_queue<string> q_logs_waf;

#endif /* WAF_H */

