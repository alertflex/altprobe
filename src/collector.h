/* 
 * File:   collector.h
 * Author: Oleg Zharkov
 */
 

#ifndef COLLECTOR_H
#define	COLLECTOR_H

#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unistd.h> // sleep
#include <istream>
#include <ostream>
#include <boost/asio.hpp>
#include "base64.h"
#include "ids.h"
#include "flows.h"
#include "hids.h"
#include "nids.h"
#include "waf.h"
#include "misc.h"
#include "crs.h"
#include "packetbeat.h"
#include "statflows.h"
#include "statids.h"
#include "remlog.h"
#include "remstat.h"
#include "filters.h"

using boost::asio::ip::tcp;
using namespace std;
namespace bpt = boost::property_tree;


class Collector : public Source {
public: 
    
    std::vector<Agent> agents_list;
        
    Hids* hids;
    Nids* nids; 
    Waf* waf; 
    Misc* misc; 
    Crs* crs;
    Packetbeat* packetbeat;
    RemLog* rem_log;
    RemStat* rem_stat;
    StatFlows* stat_flows;
    StatIds* stat_ids;
    
    BinData bd;
    Rule rd;
    std::stringstream strStream, comp;
    
    string ref_id;
    
    Collector(Crs* c, Hids* h, Nids* n, Waf* w, Misc* m, Packetbeat* p, RemLog* rl, RemStat* rs, StatFlows* f, StatIds* i) {
    
        crs = c;
        hids = h;
        nids = n;
        waf = w;
        misc = m;
        packetbeat = p;
        rem_log = rl;
        rem_stat = rs;
        stat_flows = f;
        stat_ids = i;
        
        wazuhServerStatus = false;
        agents_list.clear();
    }
        
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    int Go();
    void RoutineJob();
    void UpdateFilters();
    void UpdateFalcoConfig();
    void UpdateSuriConfig();
    void UpdateModsecConfig();
    void UpdateOssecConfig();
    void UpdateFalcoRules();
    void UpdateSuriRules();
    void UpdateOssecRules();
    void UpdateModsecRules();
        
    void ParsAgents(string json);
    void ControllerPush(string json, string type, string agent);
    string WazuhGet(string query);
    
    void ResetStreams() {
        comp.str("");
        comp.clear();
        strStream.str("");
        strStream.clear();
    }
};

#endif	/* COLLECTOR_H */


