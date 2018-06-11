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

const string forbiddenChars = "\\/:?\"<>|";
char ClearForbidden(char toCheck)
{
    if(forbiddenChars.find(toCheck) != string::npos) {
        
        return ' ';
    }

    return toCheck;
}

void ModsecRecord::GetAuditHeader(string str) {
    
    int pointer = str.find("[file");
    
    buffer = str.substr(0,pointer);
    
    transform(buffer.begin(), buffer.end(), buffer.begin(), ClearForbidden);
}

string ModsecRecord::RemoveAuditParametersName(string str) {
    
    int str_size = str.length();
    char tab[str_size];
    
    strncpy(tab, str.c_str(), str_size);
    
    int i,j;
    
    for (i = 0; i < str_size; i++) {
        if (tab[i] == '"') break;
    }
    
    if (i == str_size + 1) return "";
    
    for (j = i+1; j < str_size; j++) {
        if (tab[j] == '"') break;
    }
    
    if (j == str_size + 1) return "";
    
    buffer = string(tab + i + 1, tab + j);
    
    return buffer;
}

void ModsecRecord::CheckAuditFields(string str) {
    
    if(str.find("file") == 0) {
        
        ma.file = RemoveAuditParametersName(str);
        
        return;
    }
    
    if(str.find("id") == 0) {
        
        buffer = RemoveAuditParametersName(str);
        
        try {
            // string -> integer
            ma.id = std::stoi(buffer);

        } catch (const std::exception & ex) {
            ma.id = 0;
        }
        
        return;
    }
    
    if(str.find("tag") == 0) {
            
        buffer = RemoveAuditParametersName(str);
        ma.list_tags.push_back(buffer);
        
        return;
    }
    
   
    if(str.find("severity") == 0) {
        
        buffer = RemoveAuditParametersName(str);
        
        if (buffer.compare("EMERGENCY") == 0) {
            ma.severity = 3;
            return;
        }
        
        if (buffer.compare("ALERT") == 0) {
            ma.severity = 3;
            return;
        }
        
        if (buffer.compare("CRITICAL") == 0) {
            ma.severity = 3;
            return;
        }
        
        if (buffer.compare("ERROR") == 0) {
            ma.severity = 2;
            return;
        }
        
        if (buffer.compare("WARNING") == 0) {
            ma.severity = 2;
            return;
        }
        
        if (buffer.compare("NOTICE") == 0) {
            ma.severity = 1;
            return;
        }
        
        if (buffer.compare("TRANSACTION") == 0) {
            ma.severity = 1;
            return;
        }
        
        
        if (buffer.compare("INFO") == 0) {
            ma.severity = 0;
            return;
        }
        
        if (buffer.compare("DEBUG") == 0) {
            ma.severity = 0;
            return;
        }
        
        ma.severity = 1;
        return;
    }
    
    if(str.find("msg") == 0) {
        
        ma.msg = RemoveAuditParametersName(str);
        
        return;
    }
    
    if(str.find("unique_id") == 0) {
        
        ma.unique_id = RemoveAuditParametersName(str);
        
        return;
    }
    
    if(str.find("hostname") == 0) {
        
        ma.hostname = RemoveAuditParametersName(str);
        
        return;
    }
    
    if(str.find("uri") == 0) {
        
        ma.uri = RemoveAuditParametersName(str);
        
        return;
    }
}

int ModsecRecord::ParsRecord(string rec) {
    
    GetAuditHeader(rec);
    
    ma.header = buffer; 
        
    boost::split(strs,rec,boost::is_any_of("["));
    
    std::vector<string>::iterator i, end;
    
    for (vector<string>::const_iterator it = strs.begin(); it != strs.end(); ++it) {
        CheckAuditFields(*it);
    }
        
    return 1;
}



