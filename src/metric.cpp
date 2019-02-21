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
        
        if (res != 0 && fs.filter.metric.log) {
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
                case 6:
                    SendNginxStat();
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
    
    std::vector<Threshold*>::iterator i, end;
    int module_type = 0;
    
    // SysLog(redis_payload);
    
    try {
    
        jsonPayload.assign(reply->str, GetBufferSize(reply->str));
    
        ss << redis_payload;
        bpt::read_json(ss, pt);
        
        agent = pt.get<string>("beat.name");
        metric = pt.get<string>("metricset.module","");
        string timestamp = pt.get<string>("@timestamp");
                        
        for ( i = fs.filter.metric.th.begin(), end = fs.filter.metric.th.end(); i != end; ++i ) {
        
            if (!(*i)->host.compare(agent)) {
        
                if (!(*i)->element.compare(metric)) {
                    
                    parameter = (*i)->parameter;
                    filter_flag = true;
                    goto metrics_check;
                }
            }
        }
        
metrics_check:    
        if (metric.compare("system") != 0) goto final_check;            
                    
        if (metric.compare("nginx") == 0) {
            module_type = 6;
            
            rec_nginx.agent_name = agent;
            rec_nginx.timestamp = timestamp;
            
            rec_nginx.accepts = pt.get<long>("nginx.stubstatus.accepts",0);
            rec_nginx.active = pt.get<long>("nginx.stubstatus.active",0);
            rec_nginx.dropped = pt.get<long>("nginx.stubstatus.dropped",0);
            rec_nginx.handled = pt.get<long>("nginx.stubstatus.handled",0);
            rec_nginx.reading = pt.get<long>("nginx.stubstatus.reading",0);
            rec_nginx.requests = pt.get<long>("nginx.stubstatus.requests",0);
            rec_nginx.writing = pt.get<long>("nginx.stubstatus.writing",0);
            
            if (!filter_flag) {
                
                if (!parameter.compare("accepts")) {
                    value = rec_nginx.accepts;
                    goto final_check;
                }
                if (!parameter.compare("active")) {
                    value = rec_nginx.active;
                    goto final_check;
                }
                if (!parameter.compare("dropped")) {
                    value = rec_nginx.dropped;
                    goto final_check;
                }
                
                if (!parameter.compare("handled")) {
                    value = rec_nginx.handled;
                    goto final_check;
                }
                
                if (!parameter.compare("reading")) {
                    value = rec_nginx.reading;
                    goto final_check;
                }
                
                if (!parameter.compare("requests")) {
                    value = rec_nginx.requests;
                    goto final_check;
                }
                
                if (!parameter.compare("accepts")) value = rec_nginx.accepts;
            }
            
            goto final_check;
        }
        
        metric = pt.get<string>("metricset.name","");
        
        if (metric.compare("memory") == 0) {
            module_type = 1;
            
            rec_mem.agent_name = agent;
            rec_mem.timestamp = timestamp;
            
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
            
            if (!filter_flag) {
                
                if (!parameter.compare("used")) {
                    value = rec_mem.used;
                    goto final_check;
                }
                
                if (!parameter.compare("used_pct")) {
                    value = rec_mem.used_pct;
                    goto final_check;
                }
                
                if (!parameter.compare("free")) {
                    value = rec_mem.free;
                    goto final_check;
                }
                
                if (!parameter.compare("total")) {
                    value = rec_mem.total;
                    goto final_check;
                }
                
                if (!parameter.compare("actual_free")) {
                    value = rec_mem.actual_free;
                    goto final_check;
                }
                
                if (!parameter.compare("actual_used")) {
                    value = rec_mem.actual_used;
                    goto final_check;
                }
                
                if (!parameter.compare("swap_free")) {
                    value = rec_mem.swap_free;
                    goto final_check;
                }
                
                if (!parameter.compare("swap_used")) {
                    value = rec_mem.swap_used;
                    goto final_check;
                }
                
                if (!parameter.compare("swap_total")) {
                    value = rec_mem.swap_total;
                    goto final_check;
                }
            }
            
            goto final_check;
        }
        
        if (metric.compare("network") == 0) {
            module_type = 2;
            
            rec_net.agent_name = agent;
            rec_net.timestamp = timestamp;
            
            rec_net.network_name = pt.get<string>("system.network.name","");
            rec_net.in_dropped = pt.get<long>("system.network.in.dropped",0);
            rec_net.in_bytes = pt.get<long>("system.network.in.bytes",0);
            rec_net.in_packets = pt.get<long>("system.network.in.packets",0);
            rec_net.in_errors = pt.get<long>("system.network.in.errors",0);
            rec_net.out_dropped = pt.get<long>("system.network.out.dropped",0);
            rec_net.out_bytes = pt.get<long>("system.network.out.bytes",0);
            rec_net.out_packets = pt.get<long>("system.network.out.packets",0);
            rec_net.out_errors = pt.get<long>("system.network.out.errors",0);
            
            if (!filter_flag) {
                
                if (!parameter.compare("in_dropped")) {
                    value = rec_net.in_dropped;
                    goto final_check;
                }
                
                if (!parameter.compare("in_bytes")) {
                    value = rec_net.in_bytes;
                    goto final_check;
                }
                
                if (!parameter.compare("in_packets")) {
                    value = rec_net.in_packets;
                    goto final_check;
                }
                
                if (!parameter.compare("in_errors")) {
                    value = rec_net.in_errors;
                    goto final_check;
                }
                
                if (!parameter.compare("out_dropped")) {
                    value = rec_net.out_dropped;
                    goto final_check;
                }
                
                if (!parameter.compare("out_bytes")) {
                    value = rec_net.out_bytes;
                    goto final_check;
                }
                
                if (!parameter.compare("out_packets")) {
                    value = rec_net.out_packets;
                    goto final_check;
                }
                 
                if (!parameter.compare("out_errors")) value = rec_net.out_errors;
                
            }
            
            goto final_check;
        }
        
        if (metric.compare("filesystem") == 0) {
            module_type = 3;
            
            rec_fs.agent_name = agent;
            rec_fs.timestamp = timestamp;
            
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
            
            if (!filter_flag) {
                
                if (!parameter.compare("free_files")) {
                    value = rec_fs.free_files;
                    goto final_check;
                }
                
                if (!parameter.compare("free")) {
                    value = rec_fs.free;
                    goto final_check;
                }
                
                if (!parameter.compare("used_bytes")) {
                    value = rec_fs.used_bytes;
                    goto final_check;
                }
                
                if (!parameter.compare("used_pct")) {
                    value = rec_fs.used_pct;
                    goto final_check;
                }
                
                if (!parameter.compare("total")) {
                    value = rec_fs.total;
                    goto final_check;
                }
                
                if (!parameter.compare("available")) {
                    value = rec_fs.available;
                    goto final_check;
                }
                
                if (!parameter.compare("files")) value = rec_fs.files;
            }
            
            goto final_check;
        }
        
        if (metric.compare("cpu") == 0) {
            module_type = 4;
            
            rec_cpu.agent_name = agent;
            rec_cpu.timestamp = timestamp;
            
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
            
            if (!filter_flag) {
                if (!parameter.compare("cores")) value = rec_cpu.core;
            }
            
            goto final_check;
        }
        
        if (metric.compare("process") == 0) {
            module_type = 5;
            
            rec_pro.agent_name = agent;
            rec_pro.timestamp = timestamp;
            
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
    
final_check:
    
        if (filter_flag) CheckThresholds(*i);
    
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 

    ResetStream();
    return module_type;
}

void Metric::SendMemoryStat() {
    
    report = "{ \"type\": \"agent_memory\", \"data\": ";
        
    report += "{ \"ref_id\": \"";
    report += fs.filter.ref_id;
            
    report += "\", \"agent\": \"";
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
    
    report.clear();
}

void Metric::SendNetworkStat() {
    
    report = "{ \"type\": \"agent_network\", \"data\": ";
        
    report += "{ \"ref_id\": \"";
    report += fs.filter.ref_id;
            
    report += "\", \"agent\": \"";
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
    
    report.clear();
}

void Metric::SendFilesystemStat() {
    
    report = "{ \"type\": \"agent_filesystem\", \"data\": ";
        
    report += "{ \"ref_id\": \"";
    report += fs.filter.ref_id;
            
    report += "\", \"agent\": \"";
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
    
    report.clear();
}

void Metric::SendCpuStat() {
    
    report = "{ \"type\": \"agent_cpu\", \"data\": ";
        
    report += "{ \"ref_id\": \"";
    report += fs.filter.ref_id;
            
    report += "\", \"agent\": \"";
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
    
    report.clear();
}

void Metric::SendProcessStat() {
    
    report = "{ \"type\": \"agent_process\", \"data\": ";
        
    report += "{ \"ref_id\": \"";
    report += fs.filter.ref_id;
            
    report += "\", \"agent\": \"";
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
    
    report.clear();
}

void Metric::SendNginxStat() {
    
    report = "{ \"type\": \"nginx\", \"data\": ";
        
    report += "{ \"ref_id\": \"";
    report += fs.filter.ref_id;
            
    report += "\", \"agent\": \"";
    report += rec_nginx.agent_name;
    
    report += "\", \"accepts\": \"";
    report += std::to_string(rec_nginx.accepts);
        
    report += "\", \"dropped\": \"";
    report += std::to_string(rec_nginx.dropped);
        
    report += "\", \"active\": \"";
    report += std::to_string(rec_nginx.active);
        
    report += "\", \"handled\": \"";
    report += std::to_string(rec_nginx.handled);
    
    report += "\", \"requests\": \"";
    report += std::to_string(rec_nginx.requests);
        
    report += "\", \"reading\": \"";
    report += std::to_string(rec_nginx.reading);
    
    report += "\", \"writing\": \"";
    report += std::to_string(rec_nginx.writing);
        
    report += "\", \"time_of_survey\": \"";
    report += GetNodeTime();
    report += "\" } }";
    
    // SysLog((char*) report.c_str());
    
    q_stats_metric.push(report);
    
    report.clear();
}

void Metric::CheckThresholds(Threshold* th) {
    
    time_t current_time = time(NULL);
    
    boost::shared_lock<boost::shared_mutex> lock(fs.filters_update);
    
    if (value != 0) {
        
        if ((value > th->value_max) && (th->value_max != 0)) th->value_count++;
    
        if ((value < th->value_min) && (th->value_min != 0)) th->value_count++;
    
        if ((th->trigger_time + th->agr.in_period) <= current_time) {
       
            if (th->value_count > th->agr.reproduced ) SendAlert(th);
            else th->Reset();
        }
    }
}
    
void Metric::SendAlert(Threshold* th) {
    
    sk.alert.description = "Metric parameter has been reached limits";
    sk.alert.ref_id  = fs.filter.ref_id;
    sk.alert.source = "Metric";
    sk.alert.type = "HOST";
    sk.alert.score = 0;
    
    sk.alert.dstip = "";
    sk.alert.srcip = "";
    sk.alert.dstport = 0;
    sk.alert.srcport = 0;
    sk.alert.dstagent = agent;
    sk.alert.srcagent = "none";
    sk.alert.user = "none";
    
    string strNodeId(node_id);
    sk.alert.sensor = sensor_id;
    sk.alert.filter = fs.filter.desc;
    sk.alert.event_time = GetNodeTime();
    
    if ( th->rsp.new_event != 0) sk.alert.event = th->rsp.new_event;
    else sk.alert.event = 1;
    
    if ( th->rsp.new_severity != 0) sk.alert.severity = th->rsp.new_severity;
    else sk.alert.severity = 1;
    
    if (th->rsp.new_category.compare("") != 0) sk.alert.list_cats.push_back(th->rsp.new_category);
    else sk.alert.list_cats.push_back("metrics threshold");
        
    if (th->rsp.profile.compare("none") != 0) sk.alert.action = th->rsp.profile;
    else sk.alert.action = "none";
    
    // hostname location 
    sk.alert.location = metric;
    
    sk.alert.info = "\"last value\":";
    sk.alert.info += std::to_string(value);    
    sk.alert.info = ", \"metrics counter\":";
    sk.alert.info += std::to_string(th->value_count);
    sk.alert.info += ", \"max limit\":";
    sk.alert.info += std::to_string(th->value_max);
    sk.alert.info += ", \"min limit\":";
    sk.alert.info += std::to_string(th->value_min);
    sk.alert.info += ", \"for parameter\": \"";
    sk.alert.info += parameter;
    sk.alert.info += "\", \"for period in sec\": ";
    sk.alert.info += std::to_string(th->agr.in_period);
        
    sk.alert.event_json = "";
        
    sk.alert.status = "aggregated_new";
    sk.SendAlert();
        
    th->Reset();
}