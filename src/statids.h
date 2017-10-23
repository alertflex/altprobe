/* 
 * File:   statids.h
 * Author: Oleg Zharkov
 *
 * Created on June 16, 2015, 10:54 AM
 */

#ifndef STAT_IDS_H
#define	STAT_IDS_H

#include <vector>

#include "sinks.h"
#include "ids.h"
#include "config.h"

using namespace std;

class Ids {
public:
    int ids_type; // 1 - suricata, 2 - ossec
    unsigned int counter;
    string ref_id;
    
    Ids (int type, string id) {  
        ids_type = type;
        counter = 1;
        ref_id = id;
    }
};

class NidsSrcIp : public Ids {
public: 
    string ip;
        
    NidsSrcIp (string id, string i) : Ids(1, id)  {
        ip = i;
    }
};

class NidsDstIp : public Ids {
public: 
    string ip;
    
    NidsDstIp (string id, string i) : Ids(1, id)  {
        ip = i;
    }
};

class HidsHostname : public Ids {
public: 
    string hostname;
    
    HidsHostname (string id, string h) : Ids(2, id)  {
        hostname = h;
    }
};

class HidsLocation : public Ids {
public: 
    string location;
    
    HidsLocation (string id, string l) : Ids(2, id)  {
        location = l;
    }
};

class IdsCategory : public Ids {
public: 
    string ids_cat;
    
    IdsCategory (int type, string id, string cat) : Ids(type, id)  {
        ids_cat = cat;
    }
};

class IdsEvent : public Ids  {
public: 
    unsigned int event;
    unsigned int severity;
    string desc;
    
    IdsEvent (int type, string id, unsigned int e, unsigned int s, string d) : Ids(type, id)  {
        event = e;
        severity = s;
        desc = d;
    }
};

class StatIds : public CollectorObject {
public:  
    
    int statids_status;
    
    Sinks sk;
    FiltersSingleton fs;
    Report report;
    
    //waiting alerts 
    std::list<IdsRecord> hids_alerts_list;
    
    std::list<IdsRecord> nids_alerts_list;
    
    //Statistics data
    std::vector<NidsSrcIp> nids_srcip;
    
    std::vector<NidsDstIp> nids_dstip;
    
    std::vector<HidsHostname> hids_hostname;
    
    std::vector<HidsLocation> hids_location;
    
    std::vector<IdsCategory> ids_category;
    
    std::vector<IdsEvent> ids_event;
    
    StatIds () {
        statids_status = 0;
    }
    
    virtual int GetConfig();
    int Open();
    void Close();
    
    int Go();
    void ProcessStatistic();
    void RoutineJob();
    
    void UpdateHidsAlerts(IdsRecord r);
    void SendHidsAlert(std::list<IdsRecord>::iterator r, int c);
    void FlushHidsAlert();
    
    void UpdateNidsAlerts(IdsRecord r);
    void SendNidsAlert(std::list<IdsRecord>::iterator r, int c);
    void FlushNidsAlert();
   
    void UpdateNidsSrcIp(IdsRecord r);
    void FlushNidsSrcIp();
    
    void UpdateNidsDstIp(IdsRecord r);
    void FlushNidsDstIp();
    
    void UpdateHidsHostname(IdsRecord r);
    void FlushHidsHostname();
    
    void UpdateHidsLocation(IdsRecord r);
    void FlushHidsLocation();
    
    void UpdateIdsCategory(IdsRecord r);
    void FlushIdsCategory();
    
    void UpdateIdsEvent(IdsRecord r);
    void FlushIdsEvent();
    
    int GetStatus() { 
        if (sk.GetStateCtrl() == 0) statids_status = 0;
        return statids_status; 
    }
        
};

#endif	/* STAT_IDS_H */


