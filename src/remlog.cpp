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

#include "remlog.h"

int RemLog::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    return 1;
}

int RemLog::Open() {
    
    if (!sk.Open()) return 0;
    
    return 1;
}

void  RemLog::Close() {
    sk.Close();
}

int RemLog::Go(void) {
    
        
    while (!q_logs_nids.empty() || !q_logs_hids.empty() || !q_logs_crs.empty() || !q_logs_waf.empty() || !q_logs_aws.empty()) {
        
        if (!q_logs_crs.empty()) {
            q_logs_crs.pop(rec);
            logs_list.push_back(rec);
            counter++;
        }
        
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
        
        if (!q_logs_waf.empty()) {
            q_logs_waf.pop(rec);
            logs_list.push_back(rec);
            counter++;
        }
        
        if (!q_logs_aws.empty()) {
            q_logs_aws.pop(rec);
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
        report = "{ \"logs\" : [";
        
        std::vector<string>::iterator i, end;
        
        for(i = logs_list.begin(), end = logs_list.end(); i != end; ++i) {
            
            report += *i;
            
            report += " ,"; 
        }
        
        report.resize(report.size() - 1);
        report += " ] }";
        logs_list.clear();
        
        // SysLog((char*) report.c_str());
        
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
        //string output = "logs compressed = " + s;
        //SysLog((char*) output.c_str());
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 2;
        sk.SendMessage(&bd);
        
        ResetStreams();
    }
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
