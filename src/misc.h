/* 
 * File:   misc.h
 * Author: Oleg Zharkov
 *
 * Created on November 12, 2018, 3:41 PM
 */

#ifndef MISC_H
#define	MISC_H

#include "source.h"

using namespace std;
namespace bpt = boost::property_tree;

class Misc : public Source {
public:
    
    bpt::ptree pt;
    stringstream ss;
    
    Misc (string skey) : Source(skey) {
        ClearRecords();
        ResetStream();
    }
    
    void ResetStream() {
        ss.str("");
        ss.clear();
    }
    
    void ResetJsontree() {
        pt.clear();
    }
    
    int Open();
    void Close();
    int Go();
    
    int ParsJson (char* redis_payload);
    
    void ClearRecords() {
        
        ResetJsontree();
        jsonPayload.clear();
        
    }
};

extern boost::lockfree::spsc_queue<string> q_logs_misc;

#endif	/* MISC_H */


