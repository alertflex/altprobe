/* 
 * File:   flows.h
 * Author: Oleg Zharkov
 *
 * Created on June 15, 2015, 8:57 PM
 */

#ifndef NETFLOW_H
#define	NETFLOW_H

#include "main.h"

using namespace std;

class NetflowRecord
{
public:
    string ref_id;
    string src_ip;             
    string src_country;    
    string dst_ip;         
    string dst_country;   
    unsigned int bytes; 
    string proto;
    string app_proto; 
            
    void Reset() {
        ref_id.clear();
        src_ip.clear();
        src_country.clear();
        dst_ip.clear();
        dst_country.clear();
        bytes = 0;
        proto.clear();
        app_proto.clear();
    }
    
    NetflowRecord () {
        Reset();
    }
    
    ~NetflowRecord () {
        Reset();
    }
};

extern boost::lockfree::spsc_queue<NetflowRecord> q_netflow;

#endif	/* NETFLOW_H */

