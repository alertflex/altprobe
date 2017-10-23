/* 
 * File:   statflow.h
 * Author: Oleg Zharkov
 *
 * Created on June 16, 2015, 10:54 AM
 */

#ifndef STATFLOW_H
#define	STATFLOW_H

#include "sinks.h"
#include "netflow.h"
#include "filters.h"
#include "config.h"

using namespace std;

class Traffic {
public:
   string ref_id;
   
   unsigned long bytes;
       
    Traffic (string id, unsigned long  b) {  
        ref_id = id;
        bytes = b;
    }
};

class NetflowConversation : public Traffic {
public:  
    string src_ip;
    string dst_ip;
            
    void Reset() {
        src_ip.clear();
        dst_ip.clear();
        bytes = 0;
    }
        
    NetflowConversation (string id, string s, string d, unsigned long b) : Traffic(id, b) {
        src_ip = s;
        dst_ip = d;
    }
};

class NetflowCountries : public Traffic {
public:  
    string country;
        
    void Reset() {
        country.clear();
        bytes = 0;
    }
        
    NetflowCountries ( string id, string c, unsigned long b) : Traffic(id, b) {
        country = c;
    }
};

class NetflowApplications : public Traffic {
public:  
    string application;
        
    void Reset() {
        application.clear();
        bytes = 0;
    }
        
    NetflowApplications (string id, string a, unsigned long b) : Traffic(id, b) {
        application = a;
    }
};

class NetflowProtocols : public Traffic {
public:  
    string protocol;
        
    void Reset() {
        protocol.clear();
        bytes = 0;
    }
        
    NetflowProtocols (string id, string p, unsigned long b) : Traffic(id, b) {
        protocol = p;
    }
};


class StatFlow : public CollectorObject {
public: 
    
    int statflow_status;
    
    Sinks sk;
    FiltersSingleton fs;
    Report report;
    
    //Statistics data
    std::vector<NetflowConversation> flow_conv;
    
    std::vector<NetflowApplications> flow_appl;
    
    std::vector<NetflowProtocols> flow_proto;
    
    std::vector<NetflowCountries> flow_countries;
    
    std::vector<Traffic> flow_traffic;
    
    StatFlow () {
        statflow_status = 0;
    }
    
    int Open();
    void Close();
    
    virtual int GetConfig();
    int Go();
    void ProcessTraffic();
    void RoutineJob();
    
    void UpdateConversation(NetflowRecord r);
    void FlushConversation();
    
    void UpdateCountries(NetflowRecord r);
    void FlushCountries();
    
    void UpdateApplications(NetflowRecord r);
    void FlushApplications();
    
    void UpdateProtocols(NetflowRecord r);
    void FlushProtocols();
    
    void UpdateTraffic(NetflowRecord r);
    void FlushTraffic();
        
    void UpdateThresholds(NetflowRecord r);
    void CheckThresholds(Threshold* th);
    void SendAlert(Threshold* th, bool type_alert);
    void FlushThresholds();
    
    int GetStatus() { 
        if (sk.GetStateCtrl() == 0) statflow_status = 0;
        return statflow_status; 
    }
};

#endif	/* STATFLOW_H */


