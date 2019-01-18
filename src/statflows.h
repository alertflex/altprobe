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

class TopTalker : public Counter {
public:  
    string src_ip;
    string dst_ip;
    string src_agent;
    string dst_agent;
    
                
    void Reset() {
        src_ip.clear();
        dst_ip.clear();
        src_agent.clear();
        dst_agent.clear();
        ids.clear();
        counter = 0;
    }
        
    TopTalker (string ref, string i, string s, string d, string sa, string da, unsigned long c) : Counter(ref, i, c) {
        src_ip = s;
        dst_ip = d;
        src_agent = sa;
        dst_agent = da;
    }
};

class Application : public Counter {
public:  
    string app;
    string agent;
            
    void Reset() {
        app.clear();
        agent.clear();
        ids.clear();
        counter = 0;
    }
        
    Application (string ref, string i, string ap, string ag, unsigned long c) : Counter(ref, i, c) {
        app = ap;
        agent = ag;
    }
};

class Country : public Counter {
public:  
    string country;
               
    void Reset() {
        country.clear();
        ids.clear();
        counter = 0;
    }
        
    Country ( string ref, string i, string cntry, unsigned long c) : Counter(ref, i, c) {
        country = cntry;
    }
};


class DnsQuery : public Counter {
public:  
    string query;
    string agent;
                
    void Reset() {
        query.clear();
        agent.clear();
        ids.clear();
        counter = 0;
    }
        
    DnsQuery (string ref, string i, string q, string ag) : Counter(ref, i, 1) {
        query = q;
        agent = ag;
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
        
    FlowsBuffers mem_mon;
        
    //Statistics data
    std::vector<TopTalker> top_talkers;
    
    std::vector<Application> applications;
    
    std::vector<Country> countries;
    
    std::vector<DnsQuery> dns_queries;
    
    std::vector<SshSession> ssh_sessions;
    
    std::vector<Traffic> traffics;
        
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    int Go();
    void ProcessFlows();
    void ProcessTraffic();
    void RoutineJob();
    
    void UpdateTopTalkers();
    void FlushTopTalkers();
    
    void UpdateCountries();
    void FlushCountries();
    
    void UpdateApplications();
    void FlushApplications();
    
    void UpdateDnsQueries();
    void FlushDnsQueries();
    
    void UpdateSshSessions();
    void FlushSshSessions();
    
    bool UpdateTraffic(Traffic t);
    void FlushTraffic();
        
    void UpdateThresholds();
    void CheckThresholds(Threshold* th);
    void SendAlert(Threshold* th, bool type_alert);
    void FlushThresholds();
    
    FlowsBuffers* GetBuffers(void) {
        return &mem_mon;
    }
};

extern boost::lockfree::spsc_queue<string> q_stats_flow;

#endif	/* STATFLOWS_H */


