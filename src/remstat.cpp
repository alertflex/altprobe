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
    
    return 1;
}

int RemStat::Open() {
    
    if (!sk.Open()) return 0;
    
    return 1;
}

void  RemStat::Close() {
    sk.Close();
}

int RemStat::Go(void) {
    
    while (!q_reports.empty() || !q_agg_alerts.empty() || !q_stats_collr.empty()) {
        
        if (!q_reports.empty()) {
            q_reports.pop(rec);
            stats_list.push_back(rec);
            counter++;
        }
        
        if (!q_agg_alerts.empty()) {
            q_agg_alerts.pop(rec);
            stats_list.push_back(rec);
            counter++;
        }  
        
        if (!q_stats_collr.empty()) {
            q_stats_collr.pop(rec);
            stats_list.push_back(rec);
            counter++;
        }  
        
    }    
        
    if (counter < 100 && timeout < 10) {
        usleep(GetGosleepTimer()*60);
        timeout++;
    } else {
        //SysLog("stat sent");
        ProcessLogs();
        counter = 0;
        timeout = 0;
    }
    
    return 1;
}


void RemStat::ProcessLogs() {
    
    if (!stats_list.empty()) {
        report = "{ \"stats\" : [";
        
        std::vector<string>::iterator i, end;
        
        for(i = stats_list.begin(), end = stats_list.end(); i != end; ++i) {
            
            report += *i;
            
            report += " ,"; 
        }
        
        report.resize(report.size() - 1);
        report += " ] }";
        stats_list.clear();
        
        //SysLog((char*) report.c_str());
        
        ss << report;
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(ss);
        boost::iostreams::copy(in, comp);
        boost::iostreams::close(in);

        int rep_size = comp.str().length();
        IncrementEventsCounter();
        IncrementEventsVolume(rep_size);
        
        //string s = std::to_string(rep_size);
        //string output = "stat compressed = " + s;
        //SysLog((char*) output.c_str());
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 1;
        sk.SendMessage(&bd);
        
        ResetStreams();
    }
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
