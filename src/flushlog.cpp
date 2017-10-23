/* 
 * File:   flushlog.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */

#include <sstream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>

#include "flushlog.h"

int FlushLog::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    if (sk.GetStateCtrl()) flushlog_status = 1;
    
    report.SetEventType(et_log);
    
    return 1;
}

int  FlushLog::Open() {
    
    if (!sk.Open()) return 0;
    
    return 1;
}

void  FlushLog::Close() {
    sk.Close();
}

int FlushLog::Go(void) {
    
    int counter = 0;
            
    while(1) {    
        while (!q_log.empty() && (counter < 100)) {
        
            string rec;
            q_log.pop(rec);
            log_list.push_back(rec);
            counter++;    
        }    
    
        if (counter < 50) usleep(GetGosleepTimer());
        else {
            ProcessLogs();
            counter = 0;
        }
    }
    
    return 1;
}


void FlushLog::ProcessLogs() {
    
    if (sk.GetStateCtrl()) {
        string log_string = "{ \"log\" : [";
        
        std::vector<string>::iterator i, end;
        
        int j = 0;
        for(i = log_list.begin(), end = log_list.end(); i != end; ++i) {
            
            log_string += *i;
            
            if ( j < log_list.size() - 1) {
                log_string += ", "; 
                j++;
            }
        }
        log_string += " ] }";
        
        std::stringstream ss, comp;
        ss << log_string;
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(ss);
        boost::iostreams::copy(in, comp);

        report.info = comp.str();
        int rep_size = report.info.length();
        
        IncrementEventsCounter(rep_size);
        
        //string s = std::to_string(rep_size);
        //string output = "size compressed = " + s;
        //SysLog((char*) output.c_str());

        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
    
    log_list.clear();
}