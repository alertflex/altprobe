/* 
 * File:   hids.h
 * Author: Oleg Zharkov
 *
 * Created on January 6, 2015, 3:34 PM
 */

#ifndef HIDS_H
#define	HIDS_H

#include "sinks.h"
#include "ids.h"
#include "filters.h"
#include "config.h"

using namespace std;

class OssecRule
{
public:
    int sidid;  /* id attribute -- required*/
    int level;  /* level attribute --required */
    string comment; /* description in the xml */
    string cve;
    string info;
        
    std::vector<string> list_cats;
        
    void Reset() {
        sidid = 0;  /* id attribute -- required*/
        level = 0;  /* level attribute --required */
        comment.clear();
        cve.clear();
        info.clear();
                
        list_cats.clear();
    }
    
};

class OssecFile
{
public:
    string filename;
    string md5_before;
    string md5_after;
    string sha1_before;
    string sha1_after;
    string owner_before;
    string owner_after;
    string gowner_before;
    string gowner_after;
    
    void Reset() {
        filename.clear();
        md5_before.clear();
        md5_after.clear();
        sha1_before.clear();
        sha1_after.clear();
        owner_before.clear();
        owner_after.clear();
        gowner_before.clear();
        gowner_after.clear();
    }
    
};

//  OSSEC record                              
class OssecRecord {
public:
    /* rule that generated it */
    OssecRule rule;
    /* file info */
    OssecFile file;
    
    string ref_id;
    /* Extracted from the event */
    string location;
    string hostname;
    
    /* Extracted from the decoders */
    string srcip;
    string dstip;
    unsigned int srcport;
    unsigned int dstport;
    string protocol;
    string action;
    string srcuser;
    string dstuser;
    
    string datetime;    
    
    
    void Reset() {
        //reset rule class object
        rule.Reset();
        //reset rule class object
        file.Reset();
        
        ref_id.clear();
        /* Extracted from the event */
        location.clear();
        hostname.clear();
        /* Extracted from the decoders */
        srcip.clear();
        dstip.clear();
        srcport = 0;
        dstport = 0;
        protocol.clear();
        action.clear();
        srcuser.clear();
        dstuser.clear();
        
        /* Additional parameters */
        datetime.clear();
    }
};


class Hids : public CollectorObject {
public:
    int hids_status;
    
    // ZeroMQ variables
    char url[OS_HEADER_SIZE];
    void* context;
    void* subscriber;
    int rc;
    
    //JSON string from ossec
    char payload[OS_PAYLOAD_SIZE];
    
    //JSON string for log
    string logPayload;
    
    //OSSEC record
    OssecRecord rec;
    
    // interfaces
    Sinks sk;
    FiltersSingleton fs;
        
    Hids () {
        memset(payload, 0, sizeof(payload));
        rec.Reset();
        hids_status = 0;
    }
    
    int Open();
    void Close(); 
    
    virtual int GetConfig();
    int Go();
    
    int OpenZmq();
    int ReceiveEvent();
    void ParsJson ();
    BwList* CheckBwList();
    void CreateLogPayload();
    void SendAlert (int s, BwList*  bwl);
    int PushIdsRecord(BwList* bwl);
    int GetStatus() {
        return hids_status;
    }
    
    void ClearRecords() {
	memset(payload, 0, sizeof(payload));
        rec.Reset();
        logPayload.clear();
    }
    
};

#endif	/* HIDS_H */

