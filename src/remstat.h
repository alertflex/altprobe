/* 
 * File:  remstat.h
 * Author: Oleg Zharkov
 *
 * Created on September 25, 2016, 12:48 PM
 */

#ifndef REMSTAT_H
#define	REMSTAT_H

#include "sinks.h"
#include "source.h"
#include "statflows.h"
#include "statids.h"
#include "hids.h"

using namespace std;

class RemStat : public Source {
public:  
    
    unsigned long events_volume;
    
    int counter;
    int timeout;
    
    std::stringstream ss, comp;
    
    string rec;
    BinData bd;
    
    //logs 
    std::vector<string> stats_list;
    
    RemStat () {
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
    
    virtual int Open(int mode, int pid);
    virtual void Close();
    
    int Go();
    void ProcessLogs();
    long ResetEventsVolume();
    void IncrementEventsVolume(int inc);
};

extern boost::lockfree::spsc_queue<string> q_stats_collr;

#endif	/* REMSTAT_H */

