/* 
 * File:   crs.h
 * Author: Oleg Zharkov
 *
 * Created on July 1, 2019, 3:34 PM
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
    string fd_name;
    string proc_cmdline;
    string proc_name;
    string container_id;
    string container_name;
        
    void Reset() {
        user_name.clear();
        fd_name.clear();
        proc_cmdline.clear();
        proc_name.clear();
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
    
    virtual int Open();
    virtual void Close();
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

