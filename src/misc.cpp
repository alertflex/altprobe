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
 
#include "misc.h"

boost::lockfree::spsc_queue<string> q_logs_misc{IDS_QUEUE_SIZE};

#include <boost/algorithm/string.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

int Misc::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (redis_status == 1) {
        
        c = redisConnect(sk.redis_host, sk.redis_port);
    
        if (c != NULL && c->err) {
            // handle error
            sprintf(level, "failed open redis server interface: %s\n", c->errstr);
            SysLog(level);
            status = 0;
        }
    
    } else status = 0;
    
    return status;
}

void Misc::Close() {
    
    sk.Close();
    
    if (status == 1) {
        
        if (redis_status == 1) redisFree(c);
                
        status = 0;
    }
}

int Misc::Go(void) {
    
    int res = 0;
    
    ClearRecords();
        
    if (status ==1 && redis_status == 1) {
        
        // read data 
        // reply = (redisReply *) redisCommand( c, (const char *) "rpop altprobe_misc");
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
        
        // IncrementEventsCounter();
        
        if (res != 0) sk.SendAlert();
            
        freeReplyObject(reply);
    }
            
    return 1;
}


int Misc::ParsJson(char* redis_payload) {
    
    try {
        
        jsonPayload.assign(reply->str, GetBufferSize(reply->str));
    
        ss << redis_payload;
        bpt::read_json(ss, pt);
        
        // check is AWS WAF
        
        
        
        // check is alert
        
        sk.alert.ref_id  = fs.filter.ref_id;
        sk.alert.sensor_id = pt.get<string>("alert.sensor_id","indef");
                
        sk.alert.alert_severity = pt.get<int>("alert.alert_severity",0);
        sk.alert.alert_source = pt.get<string>("alert.alert_source","indef");
        sk.alert.alert_type = pt.get<string>("alert.alert_type","indef");
        sk.alert.event_severity = pt.get<int>("alert.event_severity",0);
        sk.alert.event_id = pt.get<string>("alert.event_id","indef");
        sk.alert.description = pt.get<string>("alert.description","indef");
        sk.alert.action = pt.get<string>("alert.action","indef");
        sk.alert.location = pt.get<string>("alert.tags","indef");
        sk.alert.info = pt.get<string>("alert.info","indef");
        sk.alert.status = "processed";
        sk.alert.user_name = pt.get<string>("alert.user_name","indef");
        sk.alert.agent_name = pt.get<string>("alert.agent_name","indef");
        sk.alert.filter = fs.filter.name;
                        
        string cats = pt.get<string>("alert.categories","indef");
        sk.alert.list_cats.push_back(cats);
        
        sk.alert.event_time = GetNodeTime();
                
        sk.alert.dst_ip = pt.get<string>("alert.dst_ip","indef");
        sk.alert.src_ip = pt.get<string>("alert.src_ip","indef");
        sk.alert.dst_port = pt.get<int>("alert.dst_port",0);
        sk.alert.src_port = pt.get<int>("alert.src_port",0);
        sk.alert.dst_hostname = pt.get<string>("alert.dst_hostname","indef");
        sk.alert.src_hostname = pt.get<string>("alert.src_hostname","indef");
        
        sk.alert.reg_value = pt.get<string>("alert.reg_value","indef");
        sk.alert.file_path = pt.get<string>("alert.file_path","indef");
	
        sk.alert.hash_md5 = pt.get<string>("alert.hash_md5","indef");
        sk.alert.hash_sha1 = pt.get<string>("alert.hash_sha1","indef");
        sk.alert.hash_sha256 = pt.get<string>("alert.hash_sha1","indef");
	
        sk.alert.process_id = pt.get<int>("alert.process_id",0);
        sk.alert.process_name = pt.get<string>("alert.process_name","indef");
        sk.alert.process_cmdline = pt.get<string>("alert.process_cmdline","indef");
        sk.alert.process_path = pt.get<string>("alert.process_path","indef");
    
        sk.alert.url_hostname = pt.get<string>("alert.url_hostname","indef");
        sk.alert.url_path = pt.get<string>("alert.url_path","indef");
    
        sk.alert.container_id = pt.get<string>("alert.container_id","indef");
        sk.alert.container_name = pt.get<string>("alert.container_name","indef");
        
        sk.alert.container_name = pt.get<string>("alert.cloud_instance","indef");
    
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 

    ResetStream();
    
    if (sk.alert.event_id.compare("") && sk.alert.alert_type.compare("") && sk.alert.alert_source.compare("")) return 1;
    
    return 0;
}
