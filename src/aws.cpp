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
 
#include <stdio.h>
#include <stdlib.h>

#include "aws.h"

#include <boost/algorithm/string.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

boost::lockfree::spsc_queue<string> q_logs_aws{LOG_QUEUE_SIZE};


int AwsWaf::Open() {
    
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
    
    if (maxmind_status) {
        
        gi = GeoIP_open(maxmind_path, GEOIP_INDEX_CACHE);

        if (gi == NULL) {
            SysLog("error opening maxmind database\n");
            maxmind_status = false;
        }
    }
    
    return status;
}

void AwsWaf::Close() {
    
    sk.Close();
    
    if (status == 1) {
        
        if (redis_status == 1) redisFree(c);
        
        status = 0;
    }
}

int AwsWaf::Go(void) {
    
    GrayList* gl;
    int res = 0;
    
    ClearRecords();
        
    if (status) {
        
        // read data 
        reply = (redisReply *) redisCommand( c, (const char *) redis_key.c_str());
        
        if (!reply) {
            freeReplyObject(reply);
            return 1;
        }
        
        if (reply->type == REDIS_REPLY_STRING) {
            res = ParsJson();
        } else {
            freeReplyObject(reply);
            usleep(GetGosleepTimer()*60);
        
            alerts_counter = 0;
            return 1;
        }
        
        if (res != 0 ) {  
            
            boost::shared_lock<boost::shared_mutex> lock(fs.filters_update);
            
            if (fs.filter.waf.log ) CreateLog();
            
            if(rec.is_alert) {
            
                if (alerts_counter <= sk.alerts_threshold) {
            
                    gl = CheckGrayList();
            
                    int severity = PushRecord(gl);
            
                    if (gl != NULL) {
                        if (gl->rsp.profile.compare("suppress") != 0) SendAlert(severity, gl);
                    } else {
                        if (fs.filter.waf.severity.threshold <= severity) {
                        
                            SendAlert(severity, NULL);
                        }
                    } 
            
                    if (sk.alerts_threshold != 0) {
            
                        if (alerts_counter < sk.alerts_threshold) alerts_counter++;
                        else {
                            SendAlertMultiple(3);
                            alerts_counter++;
                        }
                    }
                }
            }
        } 
        
        if (redis_status == 1) freeReplyObject(reply);
    } 
    else {
        usleep(GetGosleepTimer()*60);
    }
            
    return 1;
}

GrayList* AwsWaf::CheckGrayList() {
    
    if (fs.filter.waf.gl.size() != 0) {
        
        std::vector<GrayList*>::iterator i, end;
        
        for (i = fs.filter.waf.gl.begin(), end = fs.filter.waf.gl.end(); i != end; ++i) {
            
            string event = (*i)->event;
            if (event.compare(rec.terminatingRuleId) == 0) {
            
                string host = (*i)->host;
                
                if (host.compare("indef") == 0 || host.compare(rec.clientIp) == 0 || host.compare(rec.host) == 0) {
                
                    string match = (*i)->match;
                    
                    if (match.compare("indef") == 0) return (*i);
                    else {
                        size_t found = jsonPayload.find(match); 
                        if (found != std::string::npos) return (*i);
                    }
                }
            }
        }
    }
    
    return NULL;
}


int AwsWaf::ParsJson() {
    
    IncrementEventsCounter();
    
    try {
        
        jsonPayload.assign(reply->str, GetBufferSize(reply->str));
        
        try {
        
            ss << jsonPayload;
            bpt::read_json(ss, pt);
            
        } catch (const std::exception & ex) {
            ss.str("");
            ss.clear();
            SysLog((char*) ex.what());
            return 0;
        } 
        
        rec.httpSourceName = pt.get<string>("httpSourceName","indef");
        rec.httpSourceId = pt.get<string>("httpSourceId","indef");
        rec.webaclId = pt.get<string>("webaclId","indef");
        
        rec.action = pt.get<string>("action","indef");
        
        if (rec.action.compare("BLOCK") == 0) {
            
            rec.severity = 2;
            rec.is_alert = true;
        }
        
        if (rec.is_alert) {
            
            bpt::ptree rule_group = pt.get_child("ruleGroupList");
            BOOST_FOREACH(bpt::ptree::value_type &rules, rule_group) {
                
                rec.ruleGroupId = rules.second.get<string>("ruleGroupId","indef");
            
                string termAction = rules.second.get<string>("terminatingRule.action","indef");
                
                if (termAction.compare("BLOCK") == 0) {
                    
                    rec.ruleId = rules.second.get<string>("terminatingRule.ruleId","indef");
                    break;
                    
                } else rec.ruleId = "indef";
            }
        }  
        
        rec.terminatingRuleId = pt.get<string>("terminatingRuleId","indef");
        rec.terminatingRuleType = pt.get<string>("terminatingRuleType","indef");
        
        rec.list_cats.push_back("waf");
        rec.list_cats.push_back("aws-waf");
        rec.list_cats.push_back(rec.terminatingRuleId);
        
        rec.clientIp = pt.get<string>("httpRequest.clientIp","indef");
        SetGeoBySrcIp(rec.clientIp);
        rec.country = pt.get<string>("httpRequest.country","indef");
        rec.uri = pt.get<string>("httpRequest.uri","indef");
        rec.args = pt.get<string>("httpRequest.args","indef");
        rec.httpMethod = pt.get<string>("httpRequest.httpMethod","indef");
        
        bpt::ptree hosts_headers = pt.get_child("httpRequest.headers");
        BOOST_FOREACH(bpt::ptree::value_type &hosts, hosts_headers) {
            
            string host = hosts.second.get<string>("name","indef");
            
            if (host.compare("host") == 0) {
                rec.host = hosts.second.get<string>("value", "indef");
                break;
            } 
        } 
        
        if (fs.filter.netflow.log) {
            
            net_flow.ref_id = fs.filter.ref_id;
            net_flow.sensor = rec.httpSourceId;
            net_flow.dst_ip = rec.host;
            net_flow.dst_country = "indef";
            net_flow.dst_hostname = rec.host;
            net_flow.src_ip = rec.clientIp;
            net_flow.src_country = src_cc;
            net_flow.src_hostname = "indef";
            net_flow.bytes = 0;
            net_flow.sessions = 1;
            net_flow.type = 3;
            
            q_netflow.push(net_flow);
        }
        
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return 0;
    } 
    
    return 1;
}

void AwsWaf::CreateLog() {
    
    report = "{\"version\": \"1.1\",\"node\":\"";
    report += node_id;
    
    if(rec.is_alert) report += "\",\"short_message\":\"alert-awswaf\"";
    else report += "\",\"short_message\":\"event-awswaf\"";
    
    report += ",\"full_message\":\"Event from AWS WAF\"";
    report += ",\"level\":";
    report += std::to_string(7);
    report += ",\"type\":\"NET\"";
    report += ",\"source\":\"AwsWaf\"";
        
    report +=  ",\"project_id\":\"";
    report +=  fs.filter.ref_id;
			
    report += "\",\"collected_time\":\"";
    report += GetGraylogFormat();
		
    report += "\",\"description\":\"web ACL event from AWS WAF\",\"sensor\":\"";
    report += rec.httpSourceId;
    
    report += "\",\"terminatingRuleId\":\"";
    report += rec.terminatingRuleId;
    
    report += "\",\"terminatingRuleType\":\"";
    report += rec.terminatingRuleType;
    
    report += "\",\"action\":\"";
    report += rec.action;
    
    report += "\",\"clientIp\":\"";
    report += rec.clientIp;
    
    report += "\",\"country\":\"";
    report += rec.country;
    
    report += "\",\"client_ip_geo_country\":\"";
    report += src_cc; 
    
    report += "\",\"client_ip_geo_location\":\"";
    report += src_latitude + "," + src_longitude; 
            
    report += "\",\"uri\":\"";
    report += rec.uri;
    
    report += "\",\"args\":\"";
    report += rec.args;
    
    report += "\",\"httpMethod\":\"";
    report += rec.httpMethod;
    
    report += "\",\"server\":\"";
    report += rec.host;
    
    report += "\"}";
    
    q_logs_aws.push(report);
    
    report.clear();
}


int AwsWaf::PushRecord(GrayList* gl) {
    // create new IDS record
    IdsRecord ids_rec;
            
    ids_rec.ref_id = fs.filter.ref_id;
    
    ids_rec.event = rec.ruleId;
            
    copy(rec.list_cats.begin(),rec.list_cats.end(),back_inserter(ids_rec.list_cats));
    
    ids_rec.severity = rec.severity;
        
    ids_rec.desc = "web ACL event from AWS WAF";
                
    ids_rec.src_ip = rec.clientIp;
    ids_rec.dst_ip = rec.host;
    
    ids_rec.agent = "indef";
    ids_rec.ids = probe_id + "." + rec.httpSourceId;
    ids_rec.action = "indef";
                
    ids_rec.location = rec.uri;
       
        
    if (gl != NULL) {
        
        ids_rec.filter = true;
        
        if (gl->agr.reproduced > 0) {
            
            ids_rec.host = gl->host;
            ids_rec.match = gl->match;
            
            ids_rec.agr.in_period = gl->agr.in_period;
            ids_rec.agr.reproduced = gl->agr.reproduced;
            
            ids_rec.rsp.profile = gl->rsp.profile;
            ids_rec.rsp.new_category = gl->rsp.new_category;
            ids_rec.rsp.new_description = gl->rsp.new_description;
            ids_rec.rsp.new_event = gl->rsp.new_event;
            ids_rec.rsp.new_severity = gl->rsp.new_severity;
            ids_rec.rsp.new_type = gl->rsp.new_type;
            ids_rec.rsp.new_source = gl->rsp.new_source;
            
        }
    }
    
    q_aws_waf.push(ids_rec);
            
    return ids_rec.severity;
}


void AwsWaf::SendAlert(int s, GrayList*  gl) {
    
    sk.alert.ref_id =  fs.filter.ref_id;
    sk.alert.sensor_id = probe_id + "." + rec.httpSourceId;
    sk.alert.alert_severity = s;
    sk.alert.alert_source = "AwsWaf";
    sk.alert.alert_type = "NET";
    sk.alert.event_severity = rec.severity;
    sk.alert.event_id = rec.ruleId;
    sk.alert.description = "web ACL event from AWS WAF";
    sk.alert.action = "BLOCK";     
    sk.alert.location = rec.webaclId;
    sk.alert.info = "httpMethod: " + rec.httpMethod + ", uri: " + rec.uri;
    sk.alert.status = "processed";
    sk.alert.user_name = "indef";
    sk.alert.agent_name = rec.httpSourceName;
    sk.alert.filter = fs.filter.name;
    sk.alert.action = rec.action;
   
    if (!rec.list_cats.empty())
        copy(rec.list_cats.begin(),rec.list_cats.end(),back_inserter(sk.alert.list_cats));
    else 
        sk.alert.list_cats.push_back("waf");
    
    sk.alert.event_time = GetGraylogFormat();
        
    if (gl != NULL) {
            
        if (gl->rsp.profile.compare("indef") != 0) {
            sk.alert.action = gl->rsp.profile;
            sk.alert.status = "modified";
        } 
        
        if (gl->rsp.new_type.compare("indef") != 0) {
            sk.alert.alert_type = gl->rsp.new_type;
            sk.alert.status = "modified";
        }  
        
        if (gl->rsp.new_source.compare("indef") != 0) {
            sk.alert.alert_source = gl->rsp.new_source;
            sk.alert.status = "modified";
        } 
        
        if (gl->rsp.new_event.compare("") != 0) {
            sk.alert.event_id = gl->rsp.new_event;
            sk.alert.status = "modified";
        }    
            
        if (gl->rsp.new_severity != 0) {
            sk.alert.alert_severity = gl->rsp.new_severity;
            sk.alert.status = "modified";
        }   
            
        if (gl->rsp.new_category.compare("") != 0) {
            sk.alert.list_cats.push_back(gl->rsp.new_category);
            sk.alert.status = "modified";
        }   
                
        if (gl->rsp.new_description.compare("") != 0) {
            sk.alert.description = gl->rsp.new_description;
            sk.alert.status = "modified";
        }   
        
    }
    
    sk.alert.dst_ip = rec.host;
    sk.alert.src_ip = rec.clientIp;
    sk.alert.dst_port = 0;
    sk.alert.src_port = 0;
    sk.alert.dst_hostname = rec.host;
    sk.alert.src_hostname = "indef";
        
    sk.alert.reg_value = "indef";
    sk.alert.file_name = "indef";
	
    sk.alert.hash_md5 = "indef";
    sk.alert.hash_sha1 = "indef";
    sk.alert.hash_sha256 = "indef";
	
    sk.alert.process_id = 0;
    sk.alert.process_name = "indef";
    sk.alert.process_cmdline = "indef";
    sk.alert.process_path = "indef";
    
    sk.alert.url_hostname = rec.host;
    sk.alert.url_path = rec.uri;
    
    sk.alert.container_id = "indef";
    sk.alert.container_name = "indef";
    
    sk.alert.cloud_instance = "indef";
    
    sk.SendAlert();
        
}
