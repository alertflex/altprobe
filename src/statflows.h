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
   
   unsigned long counter;
       
    Counter (string id, unsigned long  c) {  
        ref_id = id;
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
        counter = 0;
    }
        
    TopTalker (string id, string s, string d, string sa, string da, unsigned long c) : Counter(id, c) {
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
        counter = 0;
    }
        
    Application (string id, string ap, string ag, unsigned long c) : Counter(id, c) {
        app = ap;
        agent = ag;
    }
};

class Country : public Counter {
public:  
    string country;
            
    void Reset() {
        country.clear();
        counter = 0;
    }
        
    Country ( string id, string cntry, unsigned long c) : Counter(id, c) {
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
        counter = 0;
    }
        
    DnsQuery (string id, string q, string ag) : Counter(id, 1) {
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
        counter = 0;
    }
        
    SshSession (string id, string c, string s, string si, string di, string sa, string da) : Counter(id, 1) {
        client = c;
        server = s;
        src_ip = si;
        dst_ip = di;
        src_agent = sa;
        dst_agent = da;
    }
};



class DstPort : public Counter {
public:
    string ip;
    string agent;
    int port;
        
    void Reset() {
        ip.clear();
        agent.clear();
        port = 0;
        counter = 0;
    }
        
    DstPort (string id, string i, string ag, int p) : Counter(id, 1) {
        ip = i;
        agent = ag;
        port = p;
    }
};

class StatFlows : public Source {
public: 
    
    Traffic traffic;
    
    FlowsBuffers mem_mon;
    
    //Statistics data
    std::vector<TopTalker> top_talkers;
    
    std::vector<Application> applications;
    
    std::vector<Country> countries;
    
    std::vector<DnsQuery> dns_queries;
    
    std::vector<SshSession> ssh_sessions;
    
    std::vector<DstPort> dst_ports;
    
    
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    int Go();
    void ProcessTraffic();
    void RoutineJob();
    
    void UpdateTopTalkers(FlowsRecord r);
    void FlushTopTalkers();
    
    void UpdateCountries(FlowsRecord r);
    void FlushCountries();
    
    void UpdateApplications(FlowsRecord r);
    void FlushApplications();
    
    void UpdateDnsQueries(FlowsRecord r);
    void FlushDnsQueries();
    
    void UpdateSshSessions(FlowsRecord r);
    void FlushSshSessions();
    
    void UpdateDstPorts(FlowsRecord r);
    void FlushDstPorts();
    
    void UpdateTraffic();
    void FlushTraffic();
        
    void UpdateThresholds(FlowsRecord r);
    void CheckThresholds(Threshold* th);
    void SendAlert(Threshold* th, bool type_alert);
    void FlushThresholds();
    
    FlowsBuffers* GetBuffers(void) {
        return &mem_mon;
    }
};

extern boost::lockfree::spsc_queue<string> q_stats_flow;

#endif	/* STATFLOWS_H */


