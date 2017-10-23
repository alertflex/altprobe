/* 
 * File:   nids.h
 * Author: Oleg Zharkov
 *
 * Created on January 6, 2015, 3:34 PM
 */

#ifndef NIDS_H
#define	NIDS_H

#include "GeoIP.h"
#include "GeoIPCity.h"
#include "hiredis.h"

#include "sinks.h"
#include "ids.h"
#include "netflow.h"
#include "filters.h"
#include "config.h"


using namespace std;

class SuricataAlert
{
public:
    string action;
    unsigned int gid;
    unsigned int signature_id;
    unsigned int rev;
    string signature;
    string category;
    unsigned int severity;
    
    void Reset() {
        action.clear();
        gid = 0;
        signature_id = 0;
        rev = 0;
        signature.clear();
        category.clear();
        severity = 0;
    }
};


class SuricataDns
{
public:
    string type;
    unsigned int id;
    string rrname;
    string rcode;
    string rrtype;
    unsigned int tx_id;
    unsigned int ttl;
    string rdata;
    
    void Reset() {
        type.clear();
        id = 0;
        rrname.clear();
        rcode.clear();
        rrtype.clear();
        rdata.clear();
        tx_id = 0;
        ttl = 0;
    }
};

class SuricataNetflow
{
public:
    string app_proto;
    unsigned int pkts;
    unsigned int bytes;
    string start;
    string end;
    int age;
    
    void Reset() {
        app_proto.clear();
        bytes = 0;
        pkts = 0;
        age = 0;
        start.clear();
        end.end();
    }
};

//  Suricata record                              
class SuricataRecord {
public:
    
    // *** Common fields
    string ref_id;
    string event_type;
    string time_stamp;
    unsigned long flow_id;
    string in_iface;
    string src_ip;
    unsigned int src_port;
    string dst_ip;
    unsigned int dst_port;
    string protocol;
    string payload_printable;
    unsigned int stream;
    string datetime; 
    string hostname; 
    
    //  Record  Alert 
    SuricataAlert alert;
    //  Record  Dns 
    SuricataDns dns;
    //  Record  Flow
    SuricataNetflow netflow;
    
    
    void Reset() {
        //reset rule class object
        ref_id.clear();
        event_type.clear();
        time_stamp.clear();
        flow_id = 0;
        in_iface.clear();
        src_ip.clear();
        src_port = 0;
        dst_ip.clear();
        dst_port = 0;
        protocol.clear();
        payload_printable.clear();
        unsigned int stream = 0;
        datetime.clear();
        hostname.clear();
        
        alert.Reset();
        dns.Reset();
        netflow.Reset();
    }
};


class Nids : public CollectorObject {
public:  
    
    int nids_status;
    
    static char maxmind_path[OS_BUFFER_SIZE]; 
    int maxmind_state;
    GeoIP *gi;
    string country_code;
    
    std::mutex m_net_counter;
    unsigned long net_events_counter;
        
    // Redis config parameters
    static char host[OS_HEADER_SIZE];
    static long int port;
    redisReply *reply;
    redisContext *c;
    
    //JSON string from suricata
    string logPayload;
    
    //Suricata record
    SuricataRecord rec;
    
    // interfaces
    Sinks sk;
    FiltersSingleton fs;
        
    Nids () {
        rec.Reset();
        nids_status = 0;
        maxmind_state = 0;
        net_events_counter = 0;
    }
    
    int Open();
    void Close();
    
    virtual int GetConfig();
    int Go();
    
    int ParsJson (char* redis_payload);
    bool CheckTraffic();
    bool CheckHomeNetwork();
    BwList* CheckBwList();
    int ReceiveEvent();
    void CreateLogPayload(int r);
    void SendAlert (int s, BwList* bwl);
    int PushIdsRecord(BwList* bwl);
    void PushFlowRecord();
    string CountryByIp(string ip);
        
    int GetStatus() {
        return nids_status;
    }
    
    long ResetNetEventsCounter() {
        unsigned long r;
        
        m_net_counter.lock();
        r = net_events_counter;
        net_events_counter = 0;
        m_net_counter.unlock();
        
        return r;
    }
    
    void IncrementNetEventsCounter() {
        m_net_counter.lock();
        net_events_counter++;
        m_net_counter.unlock();
    }
                
    void ClearRecords() {
        rec.Reset();
        logPayload.clear();
    }
};

#endif	/* NIDS_H */

