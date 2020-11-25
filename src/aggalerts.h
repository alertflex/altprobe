/* 
 * File:   aggalerts.h
 * Author: Oleg Zharkov
 *
 * Created on June 16, 2015, 10:54 AM
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
    void PushRecord();
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


