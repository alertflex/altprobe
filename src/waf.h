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
    string unique_id;
    string hostname;
    string uri;
    string header;
    string file; //location
    string msg;  // info
        
    vector<string> list_tags; //categories
    
    void Reset() {
        
        /* Extracted from the decoders */
        id = 0;
        severity = 0;
        file.clear();
        msg.clear();
        header.clear();
        unique_id.clear();
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
        
    vector<string> strs;
            
    bool IsModsec(string str) {
        mod_rec = str.find("ModSecurity") != str.npos;
        return mod_rec;
    } 
    void GetAuditHeader(string str); 
    void CheckAuditFields(string str);
    string RemoveAuditParametersName(string str);
    int ParsRecord(string rec);
    
    void Reset() {
        mod_rec = false;
        ma.Reset();
        strs.clear();
        buffer.clear();
    }
};

#endif /* WAF_H */

