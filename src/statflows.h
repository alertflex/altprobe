/* 
 * File:   statflows.h
 * Author: Oleg Zharkov
 *
 * Created on June 16, 2015, 10:54 AM
 */

#ifndef STATFLOWS_H
#define	STATFLOWS_H

#include "flows.h"
#include "filters.h"
#include "config.h"
#include "source.h"

using namespace std;

class Counter {
public:
   string ref_id;
   string ids;
   
   unsigned long counter;
       
    Counter (string ref, string i, unsigned long  c) {  
        ref_id = ref;
        ids = i;
        counter = c;
    }
};

class SshSession : public Counter {
public:  
    string client;
    string server;
    string src_ip;
    string dst_ip;
    string src_agent;
    string dst_agent;
            
    void Reset() {
        client.clear();
        server.clear();
        src_ip.clear();
        dst_ip.clear();
        src_agent.clear();
        dst_agent.clear();
        ids.clear();
        counter = 0;
    }
        
    SshSession (string ref, string i, string c, string s, string si, string di, string sa, string da) : Counter(ref, i, 1) {
        client = c;
        server = s;
        src_ip = si;
        dst_ip = di;
        src_agent = sa;
        dst_agent = da;
    }
};


class StatFlows : public Source {
public: 
    
    FlowsRecord flows_rec;
    
    Traffic traffic_rec;
        
    //Statistics data
    std::vector<SshSession> ssh_sessions;
    
    std::vector<Traffic> traffics;
        
    virtual int GetConfig();
    
    virtual int Open(int mode, int pid);
    virtual void Close();
    
    int Go();
    void ProcessFlows();
    void ProcessTraffic();
    void RoutineJob();
    
    void UpdateSshSessions();
    void FlushSshSessions();
    
    bool UpdateTraffic(Traffic t);
    void FlushTraffic();
        
};

extern boost::lockfree::spsc_queue<string> q_stats_flow;

#endif	/* STATFLOWS_H */


