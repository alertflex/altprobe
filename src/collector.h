/*
 *   Copyright 2021 Oleg Zharkov
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
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
#include "hids.h"
#include "nids.h"
#include "misc.h"
#include "crs.h"
#include "remlog.h"
#include "remstat.h"
#include "filters.h"

using boost::asio::ip::tcp;
using namespace std;
namespace bpt = boost::property_tree;

class Container {
public:
    string id;
    string image;
    string image_id;
        
    void Reset() {
        id.clear();
        image.clear();
        image_id.clear();
    }
    
    Container () {
        Reset();
    }
    
    Container(string i, string img, string img_id) {
        id = i;
        image = img;
        image_id = img_id;
    }
};


class Collector : public Source {
public: 
    
    std::vector<Container> containers_list;
        
    Hids* hids;
    Nids* nids; 
    Misc* misc; 
    Crs* crs;
    RemLog* rem_log;
    RemStat* rem_stat;
        
    BinData bd;
    Rule rd;
    std::stringstream strStream, comp;
    
    string ref_id;
    
    Collector(Crs* c, Hids* h, Nids* n, Misc* m, RemLog* rl, RemStat* rs) {
    
        crs = c;
        hids = h;
        nids = n;
        misc = m;
        rem_log = rl;
        rem_stat = rs;
                
        wazuhServerStatus = false;
    }
        
    virtual int GetConfig();
    
    int Open();
    void Close();
    int Go();
    
    void StatJob();
    
    void UpdateRulesConfigs();
    void UpdateFalcoConfig();
    void UpdateSuriConfig();
    void UpdateModsecConfig();
    void UpdateOssecConfig();
    void UpdateFalcoRules();
    void UpdateSuriRules();
    void UpdateOssecRules();
    
    string GetAgents(string query);
    void ParsAgents(string json);
    void UpdateAgents(void);
    void PushAgents(string json, string type, string agent);
    
    string GetContainers(void);  
    void ParsContainers(string json);
    void UpdateContainers(void);
        
    void DockerBenchJob();
    void TrivyJob();
    
    void ResetStreams() {
        comp.str("");
        comp.clear();
        strStream.str("");
        strStream.clear();
    }
};

#endif	/* COLLECTOR_H */


