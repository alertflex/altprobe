/* 
 * File:   statids.h
 * Author: Oleg Zharkov
 *
 * Created on June 16, 2015, 10:54 AM
 */

#ifndef STAT_IDS_H
#define	STAT_IDS_H

#include <vector>

#include "ids.h"
#include "config.h"
#include "source.h"
#include "filters.h"

using namespace std;

class Ids {
public:
    unsigned int counter;
    string ref_id;
    
    Ids (string id) {  
        counter = 1;
        ref_id = id;
    }
};

class NidsSrcIp : public Ids {
public: 
    string ip;
    string agent;
        
    NidsSrcIp (string id, string i, string a) : Ids(id)  {
        ip = i;
        agent = a;
    }
};

class NidsDstIp : public Ids {
public: 
    string ip;
    string agent;
    
    NidsDstIp (string id, string i, string a) : Ids(id)  {
        ip = i;
        agent = a;
    }
};

class HidsHostname : public Ids {
public: 
    string hostname;
    
    HidsHostname (string id, string h) : Ids(id)  {
        hostname = h;
    }
};

class HidsLocation : public Ids {
public: 
    string location;
    string agent;
    
    HidsLocation (string id, string l, string a) : Ids(id)  {
        location = l;
        agent = a;
    }
};

class FimFile : public Ids {
public: 
    string file;
    string agent;
    
    FimFile (string id, string f, string a) : Ids(id)  {
        file = f;
        agent = a;
    }
};

class FimCause : public Ids {
public: 
    string cause;
    string agent;
    
    FimCause (string id, string c, string a) : Ids(id)  {
        cause = c;
        agent = a;
    }
};

class IdsCategory : public Ids {
public: 
    int ids_type;
    string ids_cat;
    string agent;
    
    IdsCategory ( string id, int type, string cat, string a) : Ids(id)  {
        ids_cat = cat;
        ids_type = type;
        agent = a;
    }
};

class IdsEvent : public Ids  {
public: 
    int ids_type;
    unsigned int event;
    unsigned int severity;
    string desc;
    string agent;
    
    IdsEvent (string id, int type, unsigned int e, unsigned int s, string d, string a) : Ids(id)  {
        event = e;
        severity = s;
        ids_type = type;
        desc = d;
        agent = a;
    }
};


class StatIds : public Source {
public: 
    
    IdsRecord ids_rec;
    IdsBuffers mem_mon;
    int counter;
    
    //waiting alerts 
    std::list<IdsRecord> hids_alerts_list;
    
    std::list<IdsRecord> nids_alerts_list;
    
    //Statistics data
    std::vector<NidsSrcIp> nids_srcip;
    
    std::vector<NidsDstIp> nids_dstip;
    
    std::vector<HidsHostname> hids_hostname;
    
    std::vector<HidsLocation> hids_location;
    
    std::vector<FimFile> fim_file;
    
    std::vector<FimCause> fim_cause;
    
    std::vector<IdsCategory> ids_category;
    
    std::vector<IdsEvent> ids_event;
    
    virtual int Open();
    virtual void Close();
    
    virtual int GetConfig();
    
    int Go();
    void PushRecord();
    void ProcessStatistic();
    void RoutineJob();
    
    void UpdateHidsAlerts();
    void SendHidsAlert(std::list<IdsRecord>::iterator r, int c);
    void FlushHidsAlert();
    
    void UpdateNidsAlerts();
    void SendNidsAlert(std::list<IdsRecord>::iterator r, int c);
    void FlushNidsAlert();
    
    void UpdateNidsSrcIp();
    void FlushNidsSrcIp();
    
    void UpdateNidsDstIp();
    void FlushNidsDstIp();
    
    void UpdateHidsHostname();
    void FlushHidsHostname();
    
    void UpdateHidsLocation();
    void FlushHidsLocation();
    
    void UpdateFimCause();
    void FlushFimCause();
    
    void UpdateFimFile();
    void FlushFimFile();
    
    void UpdateIdsCategory();
    void FlushIdsCategory();
    
    void UpdateIdsEvent();
    void FlushIdsEvent();
    
    IdsBuffers* GetBuffers(void) {
        return &mem_mon;
    }
    
};

extern boost::lockfree::spsc_queue<string> q_stats_ids;

#endif	/* STAT_IDS_H */


