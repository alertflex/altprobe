/* 
 * File:   monitor.h
 * Author: Oleg Zharkov
 */
 

#ifndef MONITOR_H
#define	MONITOR_H

#include <sys/types.h>
#include <sys/statvfs.h>
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unistd.h> // sleep
using namespace std;

#include "sinks.h"
#include "hids.h"
#include "nids.h"
#include "flushlog.h"

/** Memory status in megabytes */
struct MemoryStatus {
    float used_mem;
    float total_mem;
};

class Monitor : public CollectorObject {
public: 
    
    int monitor_status;
    MemoryStatus status;    
    
    Hids* hids;
    Nids* nids; 
    FlushLog* logs;
    
    Sinks sk;
    Report report;
    
    ifstream m_stat_file;
    unsigned long long m_current_user;
    unsigned long long m_current_system;
    unsigned long long m_current_nice;
    unsigned long long m_current_idle;
    unsigned long long m_next_user;
    unsigned long long m_next_system;
    unsigned long long m_next_nice;
    unsigned long long m_next_idle;
    unsigned long long m_diff_user;
    unsigned long long m_diff_system;
    unsigned long long m_diff_nice;
    unsigned long long m_diff_idle;

    string m_stat_line;
    size_t m_line_start_pos;
    size_t m_line_end_pos;
    istringstream m_iss;

    float m_percentage;
    
    string ref_id;
    
    Monitor(Hids* h, Nids* n, FlushLog* l):
        m_current_user(0),
        m_current_system(0),
        m_current_nice(0),
        m_current_idle(0),
        m_next_user(0),
        m_next_system(0),
        m_next_nice(0),
        m_next_idle(0),
        m_diff_user(0),
        m_diff_system(0),
        m_diff_nice(0),
        m_diff_idle(0), 
        monitor_status(0) {
        
        hids = h;
        nids = n;
        logs = l;
    }
        
    int Open();
    void Close();
    
    virtual int GetConfig();
    int Go();
    void RoutineJob();
    
    void GetMemoryStatus();
    float& GetCpuStatus();
    
    int GetStatus() { 
        if (sk.GetStateCtrl() == 0) monitor_status = 0;
        return monitor_status; 
    }
};

#endif	/* MONITOR_H */


