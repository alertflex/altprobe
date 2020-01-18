/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   packetbeat.h
 * Author: root
 *
 * Created on December 30, 2019, 5:01 PM
 */

#ifndef PACKETBEAT_H
#define PACKETBEAT_H

#include "source.h"

using namespace std;

class PacketbeatRecord {
public:
    
    // *** Common fields
    string time_stamp;
    
    string agent;
    string host;
    string os;
    string protocol;
    string process;
    unsigned int  pid;
    unsigned int  ppid;
    string work_path;
    string exe_path;
    
    string src_agent;
    string src_ip;
    unsigned int src_port;
    unsigned int src_packets;
    unsigned int src_bytes;
    
    
    string dst_agent;
    string dst_ip;
    unsigned int dst_port;
    unsigned int dst_packets;
    unsigned int dst_bytes;
    
    void Reset() {
        //reset rule class object
        time_stamp.clear();
        
        agent.clear();
        host.clear();
        os.clear();
        protocol.clear();
        process.clear();
        pid = 0;
        ppid = 0;
        work_path.clear();
        exe_path.clear();
        
        src_agent.clear();
        src_ip.clear();
        src_port = 0;
        src_packets = 0;
        src_bytes = 0;
        
        dst_agent.clear();
        dst_ip.clear();
        dst_port = 0;
        dst_packets = 0;
        dst_bytes = 0;
    }
};

namespace bpt = boost::property_tree;

class Packetbeat : public Source {
public:
    
    bpt::ptree pt;
    stringstream ss;
    
    PacketbeatRecord rec;
    
    Packetbeat (string skey) : Source(skey) {
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
    
    int Go();
    
    int ParsJson (char* redis_payload);
    void CreateLogPayload(int r);
    
    void ClearRecords() {
        rec.Reset();
        ResetJsontree();
        jsonPayload.clear();
        
    }
};

extern boost::lockfree::spsc_queue<string> q_logs_packetbeat;

#endif /* PACKETBEAT_H */

