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
#include "metric.h"
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
    Metric* met;
    RemLog* rem_log;
    RemStat* rem_stat;
    StatFlows* stat_flows;
    StatIds* stat_ids;
    
    BinData bd;
    Rule rd;
    std::stringstream strStream, comp;
    
    string ref_id;
    
    Collector(Hids* h, Nids* n, Waf* w, Misc* mi, Metric* me, RemLog* rl, RemStat* rs, StatFlows* f, StatIds* i) {
    
        hids = h;
        nids = n;
        waf = w;
        misc = mi;
        met = me;
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
    void UpdateSuriConfig();
    void UpdateModsecConfig();
    void UpdateOssecConfig();
    void UpdateSuriRules();
    void UpdateOssecRules();
    void UpdateModsecRule();
    void UpdateModsecRules();
    void UpdateOwaspRule();
    void UpdateOwaspRules();
    
    void ParsAgentsStatus(string status);
    string GetAgentsStatus();
    
    void ResetStreams() {
        comp.str("");
        comp.clear();
        strStream.str("");
        strStream.clear();
    }
};

#endif	/* COLLECTOR_H */


