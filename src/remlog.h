/* 
 * File:  remlog.h
 * Author: Oleg Zharkov
 *
 * Created on September 25, 2016, 12:48 PM
 */

#ifndef REMLOG_H
#define	REMLOG_H

#include "sinks.h"
#include "source.h"
#include "hids.h"
#include "nids.h"
#include "waf.h"

using namespace std;

class RemLog : public Source {
public:  
    
    unsigned long events_volume;
    
    int counter;
    int timeout;
    
    std::stringstream ss, comp;
        
    string rec;
    BinData bd;
    
    //logs 
    std::vector<string> logs_list;
    
    RemLog () {
        events_volume = 0;
        counter = 0;
        timeout = 0;
        
        ResetStreams();
    }
    
    void ResetStreams() {
        comp.str("");
        comp.clear();
        ss.str("");
        ss.clear();
    }
    
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    int Go();
    void ProcessLogs();
    long ResetEventsVolume();
    void IncrementEventsVolume(int inc);
};

#endif	/* REMLOG_H */

