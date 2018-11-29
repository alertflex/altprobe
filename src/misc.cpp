/* 
 * File:   misc.cpp
 * Author: Oleg Zharkov
 *
 */
 
#include "misc.h"

boost::lockfree::spsc_queue<string> q_logs_misc{IDS_QUEUE_SIZE};

#include <boost/algorithm/string.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

int Misc::Go(void) {
    
    int res = 0;
    
    ClearRecords();
        
    if (status) {
        
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
        
        sk.alert.description = pt.get<string>("alert.desc","");
        sk.alert.ref_id  = fs.filter.ref_id;
        sk.alert.source = pt.get<string>("alert.source","");
        sk.alert.type = pt.get<string>("alert.type","");
        sk.alert.score = pt.get<int>("alert.score",0);
    
        sk.alert.dstip = pt.get<string>("alert.dstip","");
        sk.alert.srcip = pt.get<string>("alert.srcip","");
        sk.alert.dstport = pt.get<int>("alert.dstport",0);
        sk.alert.srcport = pt.get<int>("alert.srcport",0);
        sk.alert.dstagent = pt.get<string>("alert.dstagent","");
        sk.alert.srcagent = pt.get<string>("alert.srcagent","");
        sk.alert.user = pt.get<string>("alert.user","");
    
        string strNodeId(node_id);
        sk.alert.sensor = strNodeId;
        sk.alert.filter = fs.filter.desc;
        sk.alert.event_time = GetNodeTime();
    
        sk.alert.event = pt.get<int>("alert.event",0);
        sk.alert.severity = pt.get<int>("alert.severity",0);
        string cat = pt.get<string>("alert.cat","");
        sk.alert.list_cats.push_back(cat);
        sk.alert.action = pt.get<string>("alert.action","");
    
        sk.alert.location = pt.get<string>("alert.location","");
        sk.alert.info = pt.get<string>("alert.info","");
        
        sk.alert.event_json = pt.get<string>("alert.info","");
        
        sk.alert.status = "processed_new";
        
                        
        
    
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 

    ResetStream();
    
    if (sk.alert.event != 0 && sk.alert.type.compare("") && sk.alert.source.compare("")) return 1;
    
    return 0;
}
