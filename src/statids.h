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
    string ids_name;
        
    NidsSrcIp (string id, string i, string a, string n) : Ids(id)  {
        ip = i;
        agent = a;
        ids_name = n;
    }
};

class NidsDstIp : public Ids {
public: 
    string ip;
    string agent;
    string ids_name;
    
    NidsDstIp (string id, string i, string a, string n) : Ids(id)  {
        ip = i;
        agent = a;
        ids_name = n;
    }
};

class HidsSrcIp : public Ids {
public: 
    string ip;
    string agent;
    
    HidsSrcIp (string id, string i, string a) : Ids(id)  {
        ip = i;
        agent = a;
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
    string ids_name;
    
    IdsCategory ( string id, int type, string cat, string a, string n) : Ids(id)  {
        ids_cat = cat;
        ids_type = type;
        agent = a;
        ids_name = n;
    }
};

class IdsEvent : public Ids  {
public: 
    int ids_type;
    unsigned int event;
    unsigned int severity;
    string desc;
    string agent;
    string ids_name;
    
    IdsEvent (string id, int type, unsigned int e, unsigned int s, string d, string a, string n) : Ids(id)  {
        event = e;
        severity = s;
        ids_type = type;
        desc = d;
        agent = a;
        ids_name = n;
    }
};

class WafSource : public Ids {
public: 
    string source;
    string agent;
    string ids_name;
        
    WafSource (string id, string s, string a, string n) : Ids(id)  {
        source = s;
        agent = a;
        ids_name = n;
    }
};

class WafTarget : public Ids {
public: 
    string target;
    string agent;
    string ids_name;
    
    WafTarget (string id, string t, string a, string n) : Ids(id)  {
        target = t;
        agent = a;
        ids_name = n;
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
    
    std::list<IdsRecord> waf_alerts_list;
    
    //Statistics data
    std::vector<NidsSrcIp> nids_srcip;
    
    std::vector<NidsDstIp> nids_dstip;
    
    std::vector<HidsSrcIp> hids_srcip;
    
    std::vector<HidsLocation> hids_location;
    
    std::vector<FimFile> fim_file;
    
    std::vector<FimCause> fim_cause;
    
    std::vector<IdsCategory> ids_category;
    
    std::vector<IdsEvent> ids_event;
    
    std::vector<WafSource> waf_source;
    
    std::vector<WafTarget> waf_target;
    
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
    
    void UpdateWafAlerts();
    void SendWafAlert(std::list<IdsRecord>::iterator r, int c);
    void FlushWafAlert();
    
    void UpdateNidsSrcIp();
    void FlushNidsSrcIp();
    
    void UpdateNidsDstIp();
    void FlushNidsDstIp();
    
    void UpdateHidsSrcIp();
    void FlushHidsSrcIp();
    
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
    
    void UpdateWafSource();
    void FlushWafSource();
    
    void UpdateWafTarget();
    void FlushWafTarget();
    
    IdsBuffers* GetBuffers(void) {
        return &mem_mon;
    }
    
};

extern boost::lockfree::spsc_queue<string> q_stats_ids;

#endif	/* STAT_IDS_H */


