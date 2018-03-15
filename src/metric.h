/* 
 * File:   metric.h
 * Author: Oleg Zharkov
 *
 * Created on November 30, 2017, 3:41 PM
 */

#ifndef METRIC_H
#define	METRIC_H

#include "source.h"

using namespace std;

                       
class MetricMemory {
public:    
    string ref_id;
    string agent_name;
    string timestamp;
    long used;
    float used_pct;
    long free;
    long total;
    long actual_free;
    long actual_used;
    float actual_used_pct;
    long swap_total;
    long swap_free;
    long swap_used;
    float swap_used_pct;
    
    void Reset() {
        
        ref_id.clear();
        agent_name.clear();
        timestamp.clear();
        used = 0;
        used_pct = 0;
        free = 0;
        total = 0;
        actual_free = 0;
        actual_used = 0;
        actual_used_pct = 0;
        swap_total = 0;
        swap_free = 0;
        swap_used = 0;
        swap_used_pct = 0;
    }
};


class MetricNetwork {
public:    
    string ref_id;
    string agent_name;
    string timestamp;
    
    string network_name;
    long in_dropped;
    long in_bytes;
    long in_packets;
    long in_errors;
    long out_dropped;
    long out_bytes;
    long out_packets;
    long out_errors;
    
    void Reset() {
        
        ref_id.clear();
        agent_name.clear();
        timestamp.clear();
        
        network_name.clear();
        in_dropped = 0;
        in_bytes = 0;
        in_packets = 0;
        in_errors = 0;
        out_dropped = 0;
        out_bytes = 0;
        out_packets = 0;
        out_errors = 0;
    }
};

                      
class MetricFilesystem {
public:    
    string ref_id;
    /* Extracted from the decoders */
    string agent_name;
    string timestamp;
    
    string mount_point;
    string device_name;
    string fs_type;
    long free_files;
    long free;
    long used_bytes;
    float used_pct;
    long total;
    long available;
    long files;
    
    void Reset() {
        
        ref_id.clear();
        agent_name.clear();
        timestamp.clear();
        
        mount_point.clear();
        device_name.clear();
        fs_type.clear();
        free_files = 0;
        free = 0;
        used_bytes = 0;
        used_pct = 0;
        total = 0;
        available = 0;
        files = 0;
    }
};

class MetricCpu {
public:    
    string ref_id;
    /* Extracted from the decoders */
    string agent_name;
    string timestamp;
    
    int core;
    float nice;
    float irq;
    float steal;
    float user;
    float idle;
    float iowait;
    float total;
    float softirq;
    float system;
    
    void Reset() {
        
        ref_id.clear();
        agent_name.clear();
        timestamp.clear();
        
        core = 0;
        nice = 0;
        irq = 0;
        steal = 0;
        user = 0;
        idle = 0;
        iowait = 0;
        total = 0;
        softirq = 0;
        system = 0;
    }
};

class MetricProcess {
public:    
    string ref_id;
    string agent_name;
    string timestamp;
    
    string process_name;
    string cmdline;
    string user_name;
    string state;
    
    void Reset() {
        
        ref_id.clear();
        agent_name.clear();
        timestamp.clear();
        
        process_name.clear();
        user_name.clear();
        cmdline.clear();
        state.clear();
    }
};

namespace bpt = boost::property_tree;

class Metric : public Source {
public:
    
    bpt::ptree pt;
    stringstream ss;
    
    //
    MetricMemory rec_mem;
    MetricNetwork rec_net;
    MetricFilesystem rec_fs;
    MetricCpu rec_cpu;
    MetricProcess rec_pro;
    
    Metric (string skey) : Source(skey) {
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
    
    void SendMemoryStat();
    void SendNetworkStat();
    void SendFilesystemStat();
    void SendCpuStat();
    void SendProcessStat();
    
    void ClearRecords() {
        rec_mem.Reset();
        rec_net.Reset();
        rec_fs.Reset();
        rec_cpu.Reset();
        rec_pro.Reset();
        ResetJsontree();
        jsonPayload.clear();
    }
};

extern boost::lockfree::spsc_queue<string> q_stats_metric;

#endif	/* METRIC_H */


