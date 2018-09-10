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
class ModsecRecord {
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

#endif /* WAF_H */

