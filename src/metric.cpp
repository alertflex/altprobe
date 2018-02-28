/* 
 * File:   metric.cpp
 * Author: Oleg Zharkov
 *
 */
 
#include "metric.h"

boost::lockfree::spsc_queue<string> q_stats_metric{STAT_QUEUE_SIZE};

#include <boost/algorithm/string.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

namespace bpt = boost::property_tree;


int Metric::Go(void) {
    
    int res = 0;
    
    ClearRecords();
        
    if (status) {
        
        // read data 
        // reply = (redisReply *) redisCommand( c, (const char *) "rpop altprobe_metrics");
        reply = (redisReply *) redisCommand( c, (const char *) redis_key.c_str());
        
        
        if (!reply) {
            SysLog("failed reading logs events from redis");
            freeReplyObject(reply);
            
            alerts_counter = 0;
            return 1;
        }
        
        if (reply->type == REDIS_REPLY_STRING) {
            res = ParsJson(reply->str);
        } else {
            freeReplyObject(reply);
            usleep(GetGosleepTimer()*60);
            return 1;
        }
        
        IncrementEventsCounter();
        
        if (res != 0) {
            switch (res) {
                case 1:
                    SendMemoryStat();
                    break;
                case 2:
                    SendNetworkStat();
                    break;
                case 3:
                    SendFilesystemStat();
                    break;
                case 4:
                    SendCpuStat();
                    break;
                case 5:
                    SendProcessStat();
                    break;
                default:
                    break;
            }
        }
        
        freeReplyObject(reply);
    }
            
    return 1;
}


int Metric::ParsJson(char* redis_payload) {
    
    bpt::ptree pt;
    int module_type = 0;
    
    // SysLog(redis_payload);
    
    jsonPayload.assign(reply->str, GetBufferSize(reply->str));
    
    try {
    
        stringstream ss(redis_payload);
        bpt::read_json(ss, pt);
    
        string module = pt.get<string>("metricset.module","");
        
        if (module.compare("system") != 0) {
            pt.clear();
            return 0;
        }
        
        string module_name = pt.get<string>("metricset.name","");
        
        if (module_name.compare("memory") == 0) {
            module_type = 1;
            
            rec_mem.agent_name = pt.get<string>("beat.name");
            rec_mem.timestamp = pt.get<string>("@timestamp");
            
            rec_mem.used = pt.get<long>("system.memory.used.bytes",0);
            rec_mem.used_pct = pt.get<float>("system.memory.used.pct",0);
            rec_mem.free = pt.get<long>("system.memory.free",0);
            rec_mem.total = pt.get<long>("system.memory.total",0);
            rec_mem.actual_free = pt.get<long>("system.memory.actual.free",0);
            rec_mem.actual_used = pt.get<long>("system.memory.actual.used.bytes",0);
            rec_mem.actual_used_pct = pt.get<float>("system.memory.actual.used.pct",0);
            rec_mem.swap_free = pt.get<long>("system.memory.swap.free",0);
            rec_mem.swap_used = pt.get<long>("system.memory.swap.used.bytes",0);
            rec_mem.swap_used_pct = pt.get<float>("system.memory.swap.used.pct",0);
            rec_mem.swap_total = pt.get<long>("system.memory.swap.total",0);
        }
        if (module_name.compare("network") == 0) {
            module_type = 2;
            
            rec_net.agent_name = pt.get<string>("beat.name");
            rec_net.timestamp = pt.get<string>("@timestamp");
            
            rec_net.network_name = pt.get<string>("system.network.name","");
            rec_net.in_dropped = pt.get<long>("system.network.in.dropped",0);
            rec_net.in_bytes = pt.get<long>("system.network.in.bytes",0);
            rec_net.in_packets = pt.get<long>("system.network.in.packets",0);
            rec_net.in_errors = pt.get<long>("system.network.in.errors",0);
            rec_net.out_dropped = pt.get<long>("system.network.out.dropped",0);
            rec_net.out_bytes = pt.get<long>("system.network.out.bytes",0);
            rec_net.out_packets = pt.get<long>("system.network.out.packets",0);
            rec_net.out_errors = pt.get<long>("system.network.out.errors",0);
        }
        if (module_name.compare("filesystem") == 0) {
            module_type = 3;
            
            rec_fs.agent_name = pt.get<string>("beat.name");
            rec_fs.timestamp = pt.get<string>("@timestamp");
            
            rec_fs.mount_point = pt.get<string>("system.filesystem.mount_point","");
            ReplaceAll(rec_fs.mount_point, "\"", "");
            ReplaceAll(rec_fs.mount_point, "\\", "\\\\\\\\");
            rec_fs.device_name = pt.get<string>("system.filesystem.device_name","");
            ReplaceAll(rec_fs.device_name, "\"", "");
            ReplaceAll(rec_fs.device_name, "\\", "\\\\\\\\");
            rec_fs.fs_type = pt.get<string>("system.filesystem.type","");
            ReplaceAll(rec_fs.fs_type, "\"", "");
            ReplaceAll(rec_fs.fs_type, "\\", "\\\\\\\\");
            rec_fs.free_files = pt.get<long>("system.filesystem.free_files",0);
            rec_fs.free = pt.get<long>("system.filesystem.free",0);
            rec_fs.used_bytes = pt.get<long>("system.filesystem.used.bytes",0);
            rec_fs.used_pct = pt.get<float>("system.filesystem.used.pct",0);
            rec_fs.total = pt.get<long>("system.filesystem.total",0);
            rec_fs.available = pt.get<long>("system.filesystem.available",0);
            rec_fs.files = pt.get<long>("system.filesystem.files",0);
            
        }
        if (module_name.compare("cpu") == 0) {
            module_type = 4;
            
            rec_cpu.agent_name = pt.get<string>("beat.name");
            rec_cpu.timestamp = pt.get<string>("@timestamp");
            
            rec_cpu.core = pt.get<int>("system.cpu.cores",0);
            rec_cpu.nice = pt.get<float>("system.cpu.nice.pct",0);
            rec_cpu.irq = pt.get<float>("system.cpu.irq.pct",0);
            rec_cpu.steal = pt.get<float>("system.cpu.steal.pct",0);
            rec_cpu.user = pt.get<float>("system.cpu.user.pct",0);
            rec_cpu.idle = pt.get<float>("system.cpu.idle.pct",0);
            rec_cpu.iowait = pt.get<float>("system.cpu.iowait.pct",0);
            rec_cpu.total = pt.get<float>("system.cpu.total.pct",0);
            rec_cpu.softirq = pt.get<float>("system.cpu.softirq.pct",0);
            rec_cpu.system = pt.get<float>("system.cpu.system.pct",0);
        }
        if (module_name.compare("process") == 0) {
            module_type = 5;
            
            rec_pro.agent_name = pt.get<string>("beat.name");
            rec_pro.timestamp = pt.get<string>("@timestamp");
            
            rec_pro.process_name = pt.get<string>("system.process.name","");
            rec_pro.user_name = pt.get<string>("system.process.username","");
            ReplaceAll(rec_pro.user_name, "\"", "");
            ReplaceAll(rec_pro.user_name, "\\", "\\\\\\\\");
            if (rec_pro.user_name.size() > 511) rec_pro.user_name.resize(511);
            rec_pro.cmdline = pt.get<string>("system.process.cmdline","");
            ReplaceAll(rec_pro.cmdline, "\"", "");
            ReplaceAll(rec_pro.cmdline, "\\", "\\\\\\\\");
            if (rec_pro.cmdline.size() > 1023) rec_pro.cmdline.resize(1023);
            rec_pro.state = pt.get<string>("system.process.state","");
        }
    
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    pt.clear();
    return module_type;
}

void Metric::SendMemoryStat() {
    
    string report = "{ \"type\": \"agent_memory\", \"data\": ";
        
    report += "{ \"ref_id\": \"";
    report += fs.filter.ref_id;
            
    report += "\", \"agent_name\": \"";
    report += rec_mem.agent_name;
            
    report += "\", \"used\": ";
    report += std::to_string(rec_mem.used);
            
    report += ", \"used_pct\": ";
    report += std::to_string(rec_mem.used_pct);
        
    report += ", \"free\": ";
    report += std::to_string(rec_mem.free);  
        
    report += ", \"total\": ";
    report += std::to_string(rec_mem.total);
        
    report += ", \"actual_free\": ";
    report += std::to_string(rec_mem.actual_free);
        
    report += ", \"actual_used\": ";
    report += std::to_string(rec_mem.actual_used);
        
    report += ", \"actual_used_pct\": ";
    report += std::to_string(rec_mem.actual_used_pct);
        
    report += ", \"swap_free\": ";
    report += std::to_string(rec_mem.swap_free);
        
    report += ", \"swap_used\": ";
    report += std::to_string(rec_mem.swap_used);
        
    report += ", \"swap_used_pct\": ";
    report += std::to_string(rec_mem.swap_used_pct);
        
    report += ", \"swap_total\": ";
    report += std::to_string(rec_mem.swap_total);
            
    report += ", \"time_of_survey\": \"";
    report += GetNodeTime();
    report += "\" } }";
        
    q_stats_metric.push(report);
}

void Metric::SendNetworkStat() {
    
    string report = "{ \"type\": \"agent_network\", \"data\": ";
        
    report += "{ \"ref_id\": \"";
    report += fs.filter.ref_id;
            
    report += "\", \"agent_name\": \"";
    report += rec_net.agent_name;
            
    report += "\", \"network_name\": \"";
    report += rec_net.network_name;
            
    report += "\", \"in_dropped\": ";
    report += std::to_string(rec_net.in_dropped);
        
    report += ", \"in_bytes\": ";
    report += std::to_string(rec_net.in_bytes);  
        
    report += ", \"in_packets\": ";
    report += std::to_string(rec_net.in_packets);
        
    report += ", \"in_errors\": ";
    report += std::to_string(rec_net.in_errors);
        
    report += ", \"out_dropped\": ";
    report += std::to_string(rec_net.out_dropped);
        
    report += ", \"out_bytes\": ";
    report += std::to_string(rec_net.out_bytes);  
        
    report += ", \"out_packets\": ";
    report += std::to_string(rec_net.out_packets);
        
    report += ", \"out_errors\": ";
    report += std::to_string(rec_net.out_errors);
            
    report += ", \"time_of_survey\": \"";
    report += GetNodeTime();
    report += "\" } }";
        
    q_stats_metric.push(report);
        
}

void Metric::SendFilesystemStat() {
    
    string report = "{ \"type\": \"agent_filesystem\", \"data\": ";
        
    report += "{ \"ref_id\": \"";
    report += fs.filter.ref_id;
            
    report += "\", \"agent_name\": \"";
    report += rec_fs.agent_name;
            
    report += "\", \"mount_point\": \"";
    report += rec_fs.mount_point;
        
    report += "\", \"device_name\": \"";
    report += rec_fs.device_name;
        
    report += "\", \"fs_type\": \"";
    report += rec_fs.fs_type;
            
    report += "\", \"free_files\": ";
    report += std::to_string(rec_fs.free_files);
        
    report += ", \"free\": ";
    report += std::to_string(rec_fs.free);
        
    report += ", \"used_bytes\": ";
    report += std::to_string(rec_fs.used_bytes);
        
    report += ", \"used_pct\": ";
    report += std::to_string(rec_fs.used_pct);
        
    report += ", \"total\": ";
    report += std::to_string(rec_fs.total);
        
    report += ", \"available\": ";
    report += std::to_string(rec_fs.available);
        
    report += ", \"files\": ";
    report += std::to_string(rec_fs.files);
            
    report += ", \"time_of_survey\": \"";
    report += GetNodeTime();
    report += "\" } }";
        
    q_stats_metric.push(report);
}

void Metric::SendCpuStat() {
    
    string report = "{ \"type\": \"agent_cpu\", \"data\": ";
        
    report += "{ \"ref_id\": \"";
    report += fs.filter.ref_id;
            
    report += "\", \"agent_name\": \"";
    report += rec_cpu.agent_name;
        
    report += "\", \"core\": ";
    report += std::to_string(rec_cpu.core);
            
    report += ", \"nice\": ";
    report += std::to_string(rec_cpu.nice);
        
    report += ", \"irq\": ";
    report += std::to_string(rec_cpu.irq);
        
    report += ", \"steal\": ";
    report += std::to_string(rec_cpu.steal);
        
    report += ", \"user\": ";
    report += std::to_string(rec_cpu.user);
        
    report += ", \"idle\": ";
    report += std::to_string(rec_cpu.idle);
        
    report += ", \"iowait\": ";
    report += std::to_string(rec_cpu.iowait);
        
    report += ", \"total\": ";
    report += std::to_string(rec_cpu.total);
        
    report += ", \"softirq\": ";
    report += std::to_string(rec_cpu.softirq);
        
    report += ", \"system\": ";
    report += std::to_string(rec_cpu.system);
            
    report += ", \"time_of_survey\": \"";
    report += GetNodeTime();
    report += "\" } }";
        
    q_stats_metric.push(report);
}

void Metric::SendProcessStat() {
    
    string report = "{ \"type\": \"agent_process\", \"data\": ";
        
    report += "{ \"ref_id\": \"";
    report += fs.filter.ref_id;
            
    report += "\", \"agent_name\": \"";
    report += rec_pro.agent_name;
            
    report += "\", \"process_name\": \"";
    report += rec_pro.process_name;
        
    report += "\", \"user_name\": \"";
    report += rec_pro.user_name;
        
    report += "\", \"cmd_line\": \"";
    report += rec_pro.cmdline;
        
    report += "\", \"state\": \"";
    report += rec_pro.state;
            
    report += "\", \"time_of_survey\": \"";
    report += GetNodeTime();
    report += "\" } }";
        
    q_stats_metric.push(report);
}