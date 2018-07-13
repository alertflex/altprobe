/* 
 * File:   cobject.cpp
 * Author: Oleg Zharkov
 *
 */

#include "waf.h"

#include <boost/algorithm/string.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

void ModsecRecord::GetAuditHeader(const string str) {
    
    int pointer = str.find("[file");
    
    parameters = str.substr(pointer);
}

void ModsecRecord::RemoveAuditParametersName(const string field, const string str) {
    
    int b = field.length();
    int l = str.length() - b - 2;
    
    buffer = str.substr(b, l);
}

void ModsecRecord::CheckAuditFields(const string str) {
    
    
    
    if(str.find("file") == 0) {
        
        RemoveAuditParametersName("file", str);
        ma.file = buffer;
        
        return;
    }
    
    if(str.find("id") == 0) {
        
        RemoveAuditParametersName("id", str);
        
        try {
            // string -> integer
            ma.id = std::stoi(buffer);

        } catch (const std::exception & ex) {
            ma.id = 0;
        }
        
        return;
    }
    
    if(str.find("severity") == 0) {
        
        RemoveAuditParametersName("severity", str);
        
        try {
            // string -> integer
            ma.severity = std::stoi(buffer);

        } catch (const std::exception & ex) {
            ma.severity = 0;
        }
        
        return;
    }
    
    if(str.find("tag") == 0) {
            
        RemoveAuditParametersName("tag", str);
        ma.list_tags.push_back(buffer);
        
        return;
    }
    
    if(str.find("msg") == 0) {
        
        RemoveAuditParametersName("msg", str);
        ma.msg = buffer;
        
        return;
    }
    
    if(str.find("hostname") == 0) {
        
        RemoveAuditParametersName("hostname", str);
        ma.hostname = buffer;
        
        return;
    }
    
    if(str.find("uri") == 0) {
        
        RemoveAuditParametersName("uri", str);
        ma.uri = buffer;
        
        return;
    }
    
}

int ModsecRecord::ParsRecord(const string rec) {
    
    GetAuditHeader(rec);
    
    boost::split(strs,parameters,boost::is_any_of("["));
    
    std::vector<string>::iterator i, end;
    
    for (vector<string>::const_iterator it = strs.begin(); it != strs.end(); ++it) {
        
        CheckAuditFields(*it);
    }
        
    return 1;
}




