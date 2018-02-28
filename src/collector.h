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
    
    bool ossecServerStatus;
    // Wazuh config parameters
    static char wazuh_host[OS_HEADER_SIZE];
    static int wazuh_port;
    static char wazuh_user[OS_HEADER_SIZE];
    static char wazuh_pwd[OS_HEADER_SIZE];
    
    std::vector<Agent> agents_list;
    
    Hids* hids;
    Nids* nids; 
    Metric* met;
    RemLog* rem_log;
    RemStat* rem_stat;
    StatFlows* stat_flows;
    StatIds* stat_ids;
    
    string ref_id;
    
    Collector(Hids* h, Nids* n, Metric* m, RemLog* rl, RemStat* rs, StatFlows* f, StatIds* i) {
    
        hids = h;
        nids = n;
        met = m;
        rem_log = rl;
        rem_stat = rs;
        stat_flows = f;
        stat_ids = i;
                
        ossecServerStatus = false;
        agents_list.clear();
    }
        
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    int Go();
    void RoutineJob();
    
    void ParsAgentsStatus(string status);
    string GetAgentsStatus();
};

#endif	/* COLLECTOR_H */


