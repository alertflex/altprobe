/**
 * This file is part of Altprobe.
 *
 * Altprobe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Altprobe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Altprobe.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OSSEC_H
#define	OSSEC_H

#include "sinks.h"

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
    string full_log;
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
        full_log.clear();
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


class Ossec : public ProbeObject {
public:
    int state;
    
    Sinks sk;
    
    //OSSEC record
    OssecRecord rec;
    
    // ZeroMQ variables
    char url[OS_HEADER_SIZE];
    
    void* context;
    void* subscriber;
    int rc;
    
    //JSON string from ossec
    char payload[OS_PAYLOAD_SIZE];
    
    int black_list[BLACKLIST_SIZE];
    int white_list[BLACKLIST_SIZE];
    int size_black_list; 
    int size_white_list; 
    
    
    int alerts_priority;
            
    Ossec () {
        alerts_priority = 7;
        size_black_list = 0;
        size_white_list = 0;
        rec.Reset();
    }
    
    int Open();
    void Close(); 
    
    virtual int GetConfig(config_t cfg);
    int Go();
    
    int OpenZmq();
    void ParsJson ();
    bool CheckBlackList();
    bool CheckWhiteList();
    int ReceiveEvent();
    void SendEvent();
    int GetState() { return state; }
    
    void Reset() {
        rec.Reset();
        memset(payload, 0, sizeof(payload));
    }
    
};

#endif	/* OSSEC_H */

