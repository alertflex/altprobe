/* 
 * File:   hids.h
 * Author: Oleg Zharkov
 *
 * Created on January 6, 2015, 3:34 PM
 */

#ifndef HIDS_H
#define	HIDS_H

#include "hiredis.h"

#include "sinks.h"
#include "ids.h"
#include "filters.h"
#include "config.h"
#include "source.h"

using namespace std;

class OssecRule
{
public:
    int id;  /* id attribute -- required*/
    int level;  /* level attribute --required */
    string desc; /* description in the xml */
    string info;
        
    std::vector<string> list_cats;
        
    void Reset() {
        id = 0;  /* id attribute -- required*/
        level = 0;  /* level attribute --required */
        desc.clear();
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
                
        /* Additional parameters */
        datetime.clear();
    }
};


class Hids : public Source {
public:
    //OSSEC record
    OssecRecord rec;
    
    
    Hids (string skey) : Source(skey) {
        rec.Reset();
    }
    
    int Go();
    
    int ParsJson (char* redis_payload);
    
    BwList* CheckBwList();
    void CreateLog();
    void SendAlert (int s, BwList*  bwl);
    int PushRecord(BwList* bwl);
    
    void ClearRecords() {
	rec.Reset();
        jsonPayload.clear();
    }
    
};

extern boost::lockfree::spsc_queue<string> q_logs_hids;
extern boost::lockfree::spsc_queue<string> q_compliance;

#endif	/* HIDS_H */

