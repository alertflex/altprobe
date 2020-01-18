/* 
 * File:   packetbeat.cpp
 * Author: Oleg Zharkov
 *
 */
 
#include "packetbeat.h"

boost::lockfree::spsc_queue<string> q_logs_packetbeat{FLOWS_QUEUE_SIZE};

#include <boost/algorithm/string.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

int Packetbeat::Go(void) {
    
    int res = 0;
    
    ClearRecords();
        
    if (status) {
        
        // read data 
        // reply = (redisReply *) redisCommand( c, (const char *) "rpop altprobe_packetbeat");
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
        
        if (res != 0) CreateLogPayload(res);
            
        freeReplyObject(reply);
    }
            
    return 1;
}


int Packetbeat::ParsJson(char* redis_payload) {
    
    try {
        
        jsonPayload.assign(reply->str, GetBufferSize(reply->str));
    
        ss << redis_payload;
        bpt::read_json(ss, pt);
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    string event_cat = pt.get<string>("event.category","");
    string event_type = pt.get<string>("event.action","");
    
    if (event_type.compare("network_flow") == 0 && event_cat.compare("network_traffic") == 0) {
        
        rec.time_stamp = pt.get<string>("@timestamp","");
        
        rec.agent = pt.get<string>("host.name","indef");
        rec.host = pt.get<string>("host.hostname","indef");
        rec.os = pt.get<string>("host.os.name","indef");
        rec.protocol = pt.get<string>("network.transport","indef");
        rec.process = pt.get<string>("process.name","indef");
        rec.pid = pt.get<int>("process.pid",0);
        rec.ppid = pt.get<int>("process.ppid",0);
        string work_path = pt.get<string>("process.working_directory","indef");
        ReplaceAll(work_path, "\\", "\\\\");
        rec.work_path = work_path;
        string exe_path = pt.get<string>("process.executable","indef");
        ReplaceAll(exe_path, "\\", "\\\\");
        rec.exe_path = exe_path;
        rec.src_ip = pt.get<string>("source.ip","indef");
        rec.src_agent = GetAgent(rec.src_ip);
        rec.src_port = pt.get<int>("source.port",0);
        rec.src_packets = pt.get<int>("source.packets",0);
        rec.src_bytes = pt.get<int>("source.bytes",0);
        
        rec.dst_ip = pt.get<string>("destination.ip","indef");
        rec.dst_agent = GetAgent(rec.dst_ip);
        rec.dst_port = pt.get<int>("destination.port",0);
        rec.dst_packets = pt.get<int>("destination.packets",0);
        rec.dst_bytes = pt.get<int>("destination.bytes",0);
        
        ResetStream();
        
        return 1;
    } 

    ResetStream();
    
    return 0;
}

void Packetbeat::CreateLogPayload(int r) {
    
    switch (r) {
            
        case 1: // flow record
            
            report = "{\"version\": \"1.1\",\"host\":\"";
            report += node_id;
            report += "\",\"short_message\":\"netflow-packetbeat\"";
            report += ",\"full_message\":\"Netflow event from Packetbeat\"";
            report += ",\"level\":";
            report += std::to_string(7);
            report += ",\"_type\":\"NET\"";
            report += ",\"_source\":\"Packetbeat\"";
			
            report +=  ",\"_project_id\":\"";
            report +=  fs.filter.ref_id;
			
            report +=  "\",\"_event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"_collected_time\":\"";
            report += GetGraylogFormat();
        
            report += "\",\"_agent\":\"";
            report += rec.agent;
			
            report += "\",\"_host\":\"";
            report += rec.host;
            
            report += "\",\"_os\":\"";
            report += rec.os;
            
            report += "\",\"_protocol\":\"";
            report += rec.protocol;
            
            report += "\",\"_process\":\"";
            report += rec.process;
            
            report += "\",\"_pid\":";
            report += std::to_string(rec.pid);
			
            report += ",\"_ppid\":";
            report += std::to_string(rec.ppid);
			
            report += ",\"_workpath\":\"";
            report += rec.work_path;
            
            report += "\",\"_exepath\":\"";
            report += rec.exe_path;
			
            report += "\",\"_srcip\":\"";
            report += rec.src_ip;
			
            report += "\",\"_srcagent\":\"";
            report += rec.src_agent;
			
            report += "\",\"_srcport\":";
            report += std::to_string(rec.src_port);
			
            report += ",\"_srcbytes\":";
            report += std::to_string(rec.src_bytes);
			
            report += ",\"_srcpkts\":";
            report += std::to_string(rec.src_packets);
			
            report += ",\"_dstip\":\"";
            report += rec.dst_ip;
			
            report += "\",\"_dstagent\":\"";
            report += rec.dst_agent;
			
            report += "\",\"_dstport\":";
            report += std::to_string(rec.dst_port);
			
            report += ",\"_dstbytes\":";
            report += std::to_string(rec.dst_bytes);
			
            report += ",\"_dstpkts\":";
            report += std::to_string(rec.dst_packets);
			
            report += "}";
            break;
            
        case 2: // dns record  
            break;
    }
    
    q_logs_packetbeat.push(report);
    
    report.clear();
}
