/* 
 * File:   flushlog.h
 * Author: Oleg Zharkov
 *
 * Created on September 25, 2016, 12:48 PM
 */

#ifndef FLUSHLOG_H
#define	FLUSHLOG_H

#include "sinks.h"
#include "filelog.h"

using namespace std;

class FlushLog : public CollectorObject {
public:  
    
    int flushlog_status;
    
    Sinks sk;
    
    Report report;
    
    //logs 
    vector<string> log_list;
    
    FlushLog () {
        flushlog_status = 0;
    }
    
    virtual int GetConfig();
    int Open();
    void Close();
    
    int Go();
    void ProcessLogs();
        
    int GetStatus() { 
        if (sk.GetStateCtrl() == 0) flushlog_status = 0;
        return flushlog_status; 
    }
        
};



#endif	/* FLUSHLOG_H */

