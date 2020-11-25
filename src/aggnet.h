/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   aggnet.h
 * Author: Oleg Zharkov
 *
 * Created on May 15, 2020, 11:01 PM
 */

#ifndef AGGNET_H
#define AGGNET_H

#include "netstat.h"
#include "filters.h"
#include "config.h"
#include "source.h"

using namespace std;

class AggNet : public Source {
public: 
    
    Netstat netstat_rec;
    int counter;
        
    //Statistics data
    std::vector<Netstat> netstat_list;
        
    virtual int GetConfig();
    
    virtual int Open();
    virtual void Close();
    
    int Go();
    void ProcessNetstat();
    void RoutineJob();
    
    bool UpdateNetstat(Netstat ns);
    void FlushNetstat();
        
};

extern boost::lockfree::spsc_queue<string> q_agg_net;

#endif /* AGGNET_H */

