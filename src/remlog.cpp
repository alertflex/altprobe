/* 
 * File:   remlog.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */

#include <sstream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>

#include "remlog.h"

int RemLog::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    status = 1; 
    return status;
}

int RemLog::Open() {
    
    if (!sk.Open()) return 0;
    
    return 1;
}

void  RemLog::Close() {
    sk.Close();
}

int RemLog::Go(void) {
    
        
    while (!q_logs_nids.empty() || !q_logs_hids.empty()) {
        
        string rec;
        
        if (!q_logs_nids.empty()) {
            q_logs_nids.pop(rec);
            logs_list.push_back(rec);
            counter++;
        }
        
        if (!q_logs_hids.empty()) {
            q_logs_hids.pop(rec);
            logs_list.push_back(rec);
            counter++;
        }
    }    
        
    if (counter < 100 && timeout < 10) {
        usleep(GetGosleepTimer()*60);
        timeout++;
    }
    else {
        ProcessLogs();
        counter = 0;
        timeout = 0;
    }
    
    return 1;
}


void RemLog::ProcessLogs() {
    
    if (!logs_list.empty()) {
        string log_string = "{ \"logs\" : [";
        
        std::vector<string>::iterator i, end;
        
        int j = 0;
        for(i = logs_list.begin(), end = logs_list.end(); i != end; ++i) {
            
            log_string += *i;
            
            if ( j < logs_list.size() - 1) {
                log_string += ", "; 
                j++;
            }
        }
        log_string += " ] }";
        
        //SysLog((char*) log_string.c_str());
        
        std::stringstream ss, comp;
        ss << log_string;
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(ss);
        boost::iostreams::copy(in, comp);

        int rep_size = comp.str().length();
        IncrementEventsCounter();
        IncrementEventsVolume(rep_size);
        
        //string s = std::to_string(rep_size);
        //string output = "logs compressed = " + s;
        //SysLog((char*) output.c_str());

        sk.SendMessage(new BinData(comp.str(),2));
    }
    
    logs_list.clear();
}

long RemLog::ResetEventsVolume() {
    unsigned long r;
        
    r = events_volume;
    events_volume = 0;
    
    return r;
}

void RemLog::IncrementEventsVolume(int inc) {
    
    events_volume = events_volume + inc;
    
}
