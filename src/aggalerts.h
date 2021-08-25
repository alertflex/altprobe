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

#ifndef AGG_ALERTS_H
#define	AGG_ALERTS_H

#include <vector>

#include "ids.h"
#include "config.h"
#include "source.h"
#include "filters.h"

using namespace std;

class AggAlerts : public Source {
public: 
    
    IdsRecord ids_rec;
    int counter;
    
    //waiting alerts 
    std::list<IdsRecord> crs_alerts_list;
    std::list<IdsRecord> hids_alerts_list;
    std::list<IdsRecord> nids_alerts_list;
    std::list<IdsRecord> waf_alerts_list;
       
    //Alerts stat
    IdsStat crs_stat;
    IdsStat hids_stat;
    IdsStat nids_stat;
    IdsStat waf_stat;
        
    virtual int Open();
    virtual void Close();
    
    virtual int GetConfig();
    
    int Go();
    void ProcessAlerts();
    void RoutineJob();
    
    void UpdateCrsAlerts();
    void SendCrsAlert(std::list<IdsRecord>::iterator r, int c);
    void ResetCrsAlert();
    
    void UpdateHidsAlerts();
    void SendHidsAlert(std::list<IdsRecord>::iterator r, int c);
    void ResetHidsAlert();
    
    void UpdateNidsAlerts();
    void SendNidsAlert(std::list<IdsRecord>::iterator r, int c);
    void ResetNidsAlert();
    
    void UpdateWafAlerts();
    void SendWafAlert(std::list<IdsRecord>::iterator r, int c);
    void ResetWafAlert();
    
};

extern boost::lockfree::spsc_queue<string> q_agg_alerts;

#endif	/* AGG_IDS_H */


