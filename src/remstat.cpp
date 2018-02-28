/* 
 * File:   remstat.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */

#include <sstream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <bits/stl_vector.h>

#include "remstat.h"

boost::lockfree::spsc_queue<string> q_stats_collr{STAT_QUEUE_SIZE};

int RemStat::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    status = 1; 
    return status;
}

int RemStat::Open() {
    
    if (!sk.Open()) return 0;
    
    return 1;
}

void  RemStat::Close() {
    sk.Close();
}

int RemStat::Go(void) {
    
    while (!q_compliance.empty() || !q_stats_flow.empty() || !q_stats_ids.empty() || !q_stats_collr.empty() || !q_stats_metric.empty()) {
        
        string rec;
        
        if (!q_compliance.empty()) {
            q_compliance.pop(rec);
            stats_list.push_back(rec);
            counter++;
        }
        
        if (!q_stats_flow.empty()) {
            q_stats_flow.pop(rec);
            stats_list.push_back(rec);
            counter++;
        }   
        
        if (!q_stats_ids.empty()) {
            q_stats_ids.pop(rec);
            stats_list.push_back(rec);
            counter++;
        }  
        
        if (!q_stats_collr.empty()) {
            q_stats_collr.pop(rec);
            stats_list.push_back(rec);
            counter++;
        }  
        
        if (!q_stats_metric.empty()) {
            q_stats_metric.pop(rec);
            stats_list.push_back(rec);
            counter++;
        }  
    }    
        
    if (counter < 100 && timeout < 10) {
        usleep(GetGosleepTimer()*60);
        timeout++;
    }
    else {
        //SysLog("stat sent");
        ProcessLogs();
        counter = 0;
        timeout = 0;
    }
    
    return 1;
}


void RemStat::ProcessLogs() {
    
    if (!stats_list.empty()) {
        string stats_string = "{ \"stats\" : [";
        
        std::vector<string>::iterator i, end;
        
        int j = 0;
        for(i = stats_list.begin(), end = stats_list.end(); i != end; ++i) {
            
            stats_string += *i;
            
            if ( j < stats_list.size() - 1) {
                stats_string += ", "; 
                j++;
            }
        }
        stats_string += " ] }";
        
        std::stringstream ss, comp;
        ss << stats_string;
        
        //SysLog((char*) ss.str().c_str());
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(ss);
        boost::iostreams::copy(in, comp);

        int rep_size = comp.str().length();
        IncrementEventsCounter();
        IncrementEventsVolume(rep_size);
        
        //string s = std::to_string(rep_size);
        //string output = "stat compressed = " + s;
        //SysLog((char*) output.c_str());

        sk.SendMessage(new BinData(comp.str(),1));
    }
    
    stats_list.clear();
}

long RemStat::ResetEventsVolume() {
    
    unsigned long r;
        
    r = events_volume;
    events_volume = 0;
            
    return r;
}

void RemStat::IncrementEventsVolume(int inc) {
    
    events_volume = events_volume + inc;
    
}
