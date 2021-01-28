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

#ifndef CRS_H
#define	CRS_H

#include "hiredis.h"

#include "sinks.h"
#include "ids.h"
#include "filters.h"
#include "config.h"
#include "source.h"

using namespace std;

class OutputFields
{
public:
    
    string user_name;
    
    string fd_cip;  // client IP address.
    string fd_sip;  // server IP address.
    unsigned int fd_cport; // for TCP/UDP FDs, the client port.
    unsigned int fd_sport; // for TCP/UDP FDs, server port.
    string fd_cip_name; // Domain name associated with the client IP address.
    string fd_sip_name; // Domain name associated with the server IP address.
    
    string fd_name; // name file
    string fd_directory; // path to file
    
    unsigned int  proc_pid; 
    string proc_cmdline; 
    string proc_name;
    string proc_cwd; //process dir
    
    string container_id;
    string container_name;
    
    void Reset() {
        
        user_name.clear();
        
        fd_cip.clear();
        fd_sip.clear();
        fd_cport = 0;
        fd_sport = 0;
        fd_cip_name.clear();
        fd_sip_name.clear();
        
        fd_name.clear();
        fd_directory.clear();
        
        proc_pid = 0;
        proc_cmdline.clear();
        proc_name.clear();
        proc_cwd.clear();
        
        container_id.clear();
        container_name.clear();
    }
};

//  Falco record                              
class FalcoRecord {
public:
    
    OutputFields fields;
    
    string sensor;
    string rule;
    string priority;
    int level;
    string output;
    string timestamp; 
    
    void Reset() {
        
        fields.Reset();
        
        sensor.clear();
        rule.clear();
        priority.clear();
        level = 0;
        output.clear();
        timestamp.clear();
    }
};

namespace bpt = boost::property_tree;

class Crs : public Source {
public:
    
    FILE *fp;
    struct stat buf;
    unsigned long file_size;
    int ferror_counter;
    char file_payload[OS_PAYLOAD_SIZE];
    
    //Falco record
    FalcoRecord rec;
    
    bpt::ptree pt, pt1;
    stringstream ss, ss1;
    
    Crs (string skey) : Source(skey) {
        ClearRecords();
        ResetStreams();
        ferror_counter = 0;
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
    }
    
    int Open();
    void Close();
    int ReadFile();
    void IsFileModified();
    int Go();
    
    int ParsJson ();
    
    GrayList* CheckGrayList();
    void CreateLog();
    void SendAlert (int s, GrayList* gl);
    int PushRecord(GrayList* gl);
        
    void ClearRecords() {
	rec.Reset();
        jsonPayload.clear();
        ResetJsontree();
    }
    
};

extern boost::lockfree::spsc_queue<string> q_logs_crs;

#endif	/* CRS_H */

