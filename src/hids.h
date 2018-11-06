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
#include "waf.h"
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
    string agent;
    string user;
    string hostname;
    
    /* Extracted from the decoders */
    string srcip;
    string dstip;
            
    string timestamp;    
    
    
    void Reset() {
        //reset rule class object
        rule.Reset();
        //reset rule class object
        file.Reset();
        
        ref_id.clear();
        /* Extracted from the event */
        agent.clear();
        user.clear();
        location.clear();
        hostname.clear();
        /* Extracted from the decoders */
        srcip.clear();
        dstip.clear();
                
        /* Additional parameters */
        timestamp.clear();
    }
};

namespace bpt = boost::property_tree;

class Hids : public Source {
public:
    //OSSEC record
    OssecRecord rec;
    // ModSecurity record
    ModsecRecord mr;
    
    bpt::ptree pt, pt1, groups_cats, pcidss_cats;
    stringstream ss, ss1;
    
    Hids (string skey) : Source(skey) {
        ClearRecords();
        ResetStreams();
    }
    
    void ResetStreams() {
        ss.str("");
        ss.clear();
        ss1.str("");
        ss1.clear();
    }
    
    void ResetJsontree() {
        pt.clear();
        pt1.clear();
        groups_cats.clear();
        pcidss_cats.clear();
    }
    
    int Go();
    
    int ParsJson (char* redis_payload);
    
    GrayList* CheckGrayList();
    GrayList* CheckWafGrayList();
    void CreateLog();
    void CreateWafLog();
    void SendAlert (int s, GrayList* gl);
    void SendWafAlert (int s, GrayList*  gl);
    int PushRecord(GrayList* gl);
    int PushWafRecord(GrayList* gl);
    
    void ClearRecords() {
	rec.Reset();
        mr.Reset();
        jsonPayload.clear();
        ResetJsontree();
    }
    
};

extern boost::lockfree::spsc_queue<string> q_logs_hids;
extern boost::lockfree::spsc_queue<string> q_compliance;

#endif	/* HIDS_H */

