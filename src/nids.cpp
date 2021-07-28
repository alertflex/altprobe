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

#include "nids.h"


boost::lockfree::spsc_queue<string> q_logs_nids{LOG_QUEUE_SIZE};

int Nids::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (surilog_status == 1) {
        
        fp = fopen(suri_log, "r");
        if(fp == NULL) {
            SysLog("failed open suricata log file");
            return status = 0;
        }
        
        fseek(fp,0,SEEK_END);
        stat(suri_log, &buf);    
        file_size = (unsigned long) buf.st_size;
        
    } else {
        
        if (redis_status == 1) {
            c = redisConnect(sk.redis_host, sk.redis_port);
    
            if (c != NULL && c->err) {
                // handle error
                sprintf(level, "failed open redis server interface: %s\n", c->errstr);
                SysLog(level);
                status = 0;
            }
        }  else status = 0;
    }
    
    return status;
}

void Nids::Close() {
    
    sk.Close();
    
    if (status == 1) {
        
        if (surilog_status == 1) {
            if (fp != NULL) fclose(fp);
        } else {
            if (redis_status == 1) redisFree(c);
        }
        
        status = 0;
    }
    
}

void Nids::IsFileModified() {
    
    int ret = stat(suri_log, &buf);
    if (ret == 0) {
                
        unsigned long current_size = (unsigned long) buf.st_size;
        
        if (current_size < file_size) {
            
            if (fp != NULL) fclose(fp);
            fp = fopen(suri_log, "r");
                        
            if (fp == NULL) return;
            else {
                
                fseek(fp,0,SEEK_SET);
                int ret = stat(suri_log, &buf);
                
                if (ret != 0) {
                    fp = NULL;
                    return;
                }
                
                file_size = (unsigned long) buf.st_size;
                return;
            }
        }
        
        file_size = current_size;
        return;
    } 
    
    fp = NULL;
}

int Nids::ReadFile() {
    
    if (fp == NULL) IsFileModified();
    else {
            
        if (fgets(file_payload, OS_PAYLOAD_SIZE, fp) != NULL) {
                
            ferror_counter = 0;
            return 1;
                    
        } else ferror_counter++;
            
        if(ferror_counter > EOF_COUNTER) {
            
            IsFileModified();
            ferror_counter = 0;
                    
        }
    } 
    
    return 0;
}

int Nids::Go(void) {
    
    // boost::shared_lock<boost::shared_mutex> lock(fs.filters_update_lock);
    
    GrayList* gl;
    int severity;
    int res = 0;
    
    ClearRecords();
    
    if (status) {
        
        if (surilog_status == 1) {
            
            res = ReadFile();
            
            if (res == -1) {
                SysLog("failed reading suricata events from log");
                return 1;
            }
        
            if (res == 0) {
                
                usleep(GetGosleepTimer()*60);
                alerts_counter = 0;
                return 1;
                
            } else res = ParsJson();
        
        
        } else {
        
            // read Suricata data 
            reply = (redisReply *) redisCommand( c, (const char *) redis_key.c_str());
        
        
            if (!reply) {
                SysLog("failed reading suricata events from redis");
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
        }
        
        IncrementEventsCounter();
        
        if (res != 0) {
            
            boost::shared_lock<boost::shared_mutex> lock(fs.filters_update);
            
            if (fs.filter.nids.log) CreateLogPayload(res);
        
            if (res == 1 && alerts_counter <= sk.alerts_threshold) {
                
                gl = CheckGrayList();
                
                severity = PushIdsRecord(gl);
                                    
                if (gl != NULL) {
                    if (gl->rsp.profile.compare("suppress") != 0) {
                        SendAlert(severity, gl);
                    }
                } else {
                    if (fs.filter.nids.severity.threshold <= severity) SendAlert(severity, NULL);
                }
                    
                if (sk.alerts_threshold != 0) {
            
                    if (alerts_counter < sk.alerts_threshold) alerts_counter++;
                    else {
                        SendAlertMultiple(2);
                        alerts_counter++;
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


GrayList* Nids::CheckGrayList() {
    
    if (fs.filter.nids.gl.size() != 0) {
        
        std::vector<GrayList*>::iterator i, end;
        
        for (i = fs.filter.nids.gl.begin(), end = fs.filter.nids.gl.end(); i != end; ++i) {
            
            int event_id = std::stoi((*i)->event);
            if (event_id == rec.alert.signature_id) {
                
                string host = (*i)->host;
                
                if (host.compare("indef") == 0 || host.compare(rec.dst_ip) == 0 || host.compare(rec.src_ip) == 0) {
                        
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


int Nids::ParsJson () {
    
    if (surilog_status == 1) {
        jsonPayload.assign(file_payload, GetBufferSize(file_payload));
        
    } else {
        jsonPayload.assign(reply->str, GetBufferSize(reply->str));
    }
    
    try {
        ss << jsonPayload;
        bpt::read_json(ss, pt);
    
    } catch (const std::exception & ex) {
        ResetStream();
        SysLog((char*) ex.what());
        return 0;
    } 
    
    bool is_aws_firewall = false;
    string aws_firewall = "indef";
    
    if (surilog_status != 1) {
        
        aws_firewall = pt.get<string>("firewall_name","indef");
        
        if (aws_firewall.compare("indef") != 0) {
            
            is_aws_firewall = true;
            ss1 << jsonPayload;
            bpt::read_json(ss1, pt1);
            pt = pt1.get_child("event");
        }
    }
    
    string event_type = pt.get<string>("event_type","");
    
    if (surilog_status == 1) {
    
        rec.sensor = probe_id + ".nids";
        
    } else {
        
        if (is_aws_firewall) rec.sensor = aws_firewall;
        else rec.sensor = pt.get<string>("sensor-name","indef");
        
    }
    
    if (event_type.compare("alert") == 0) {
        
        rec.event_type = 1;
        
        rec.time_stamp = pt.get<string>("timestamp","");
        
        rec.iface = pt.get<string>("in_iface","");
        
        rec.flow_id = pt.get<long>("flow_id",0);
        
        rec.src_ip = pt.get<string>("src_ip","");
        rec.src_agent = GetAgent(rec.src_ip);
        rec.src_port = pt.get<int>("src_port",0);
        
        rec.dst_ip = pt.get<string>("dest_ip","");
        rec.dst_agent = GetAgent(rec.dst_ip);
        rec.dst_port = pt.get<int>("dest_port",0);
        
        rec.protocol = pt.get<string>("proto","");
                
        // alert record
        rec.alert.action = pt.get<string>("alert.action","");
                
        rec.alert.gid = pt.get<int>("alert.gid",0); 
        
        rec.alert.signature_id = pt.get<long>("alert.signature_id",0); 
                
        rec.alert.signature = pt.get<string>("alert.signature","");
        
        rec.alert.category = pt.get<string>("alert.category","");
        
        rec.alert.severity = pt.get<int>("alert.severity",0);
        
        ResetStream();
        
        if(SuppressAlert(rec.src_ip)) return 0;
        if(SuppressAlert(rec.dst_ip)) return 0;
        
        return rec.event_type;
    }
    
    if (event_type.compare("dns") == 0) {
        
        rec.event_type = 2;
        
        rec.time_stamp = pt.get<string>("timestamp","");
        
        rec.iface = pt.get<string>("in_iface","");
        
        rec.flow_id = pt.get<long>("flow_id",0);
        
        rec.src_ip = pt.get<string>("src_ip","");
        rec.src_agent = GetAgent(rec.src_ip);
        rec.src_port = pt.get<int>("src_port",0);
        
        rec.dst_ip = pt.get<string>("dest_ip","");
        rec.dst_agent = GetAgent(rec.dst_ip);
        rec.dst_port = pt.get<int>("dest_port",0);
        
        rec.protocol = pt.get<string>("proto","");
        
        // dns record
        rec.dns.type = pt.get<string>("dns.type","");
        
        rec.dns.id = pt.get<int>("dns.id",0);
        
        rec.dns.rrname = pt.get<string>("dns.rrname","");
        
        rec.dns.rrtype = pt.get<string>("dns.rrtype","");
        
        if (!rec.dns.type.compare("answer")) {
            
            rec.dns.ttl = pt.get<int>("dns.ttl",0);
        
            rec.dns.rcode = pt.get<string>("dns.rcode","");
        
            rec.dns.rdata = pt.get<string>("dns.rdata","");
            
        }
        else rec.dns.tx_id =  pt.get<int>("dns.tx_id",0); 
        
        ResetStream();
        return rec.event_type;
    }
    
    if (event_type.compare("http") == 0) {
        
        rec.event_type = 3;
        
        rec.time_stamp = pt.get<string>("timestamp","");
        
        rec.iface = pt.get<string>("in_iface","");
        
        rec.flow_id = pt.get<long>("flow_id",0);
        
        rec.src_ip = pt.get<string>("src_ip","");
        rec.src_agent = GetAgent(rec.src_ip);
        rec.src_port = pt.get<int>("src_port",0);
        
        rec.dst_ip = pt.get<string>("dest_ip","");
        rec.dst_agent = GetAgent(rec.dst_ip);
        rec.dst_port = pt.get<int>("dest_port",0);
        
        rec.protocol = pt.get<string>("proto","");
        
        rec.http.hostname = pt.get<string>("http.hostname","indef");
        rec.http.url = pt.get<string>("http.url","indef");
        rec.http.http_user_agent = pt.get<string>("http.http_user_agent","indef");
        rec.http.http_content_type = pt.get<string>("http.http_content_type","indef");
        
        ResetStream();
        return rec.event_type;
    } 
    
        
    if (event_type.compare("netflow") == 0) {
        
        rec.event_type = 4;
        
        rec.time_stamp = pt.get<string>("timestamp","");
        
        rec.iface = pt.get<string>("in_iface","");
        
        rec.flow_id = pt.get<long>("flow_id",0);
        
        rec.src_ip = pt.get<string>("src_ip","");
        rec.src_agent = GetAgent(rec.src_ip);
        rec.src_port = pt.get<int>("src_port",0);
        
        rec.dst_ip = pt.get<string>("dest_ip","");
        rec.dst_agent = GetAgent(rec.dst_ip);
        rec.dst_port = pt.get<int>("dest_port",0);
        
        rec.protocol = pt.get<string>("proto","");
        
        rec.netflow.app_proto = pt.get<string>("app_proto","indef");
        if (rec.netflow.app_proto.compare("") == 0) rec.netflow.app_proto = "indef";
        if (rec.netflow.app_proto.compare("failed") == 0) rec.netflow.app_proto = "indef";
        
        rec.netflow.bytes = pt.get<int>("netflow.bytes",0);
        rec.netflow.pkts = pt.get<int>("netflow.pkts",0);
        rec.netflow.start = pt.get<string>("netflow.start","");
        rec.netflow.end = pt.get<string>("netflow.end","");
        rec.netflow.age = pt.get<int>("netflow.age",0);
        
        if (fs.filter.netflow.log) {
            net_flow.ids = rec.sensor;
            net_flow.flows_type = 1;
            net_flow.ref_id = rec.ref_id;
            net_flow.dst_ip = rec.dst_ip;
            net_flow.src_ip = rec.src_ip;
            net_flow.bytes = rec.netflow.bytes;
            q_netflow.push(net_flow);
        }
        
        ResetStream();
        return rec.event_type;
    } 
    
    if (event_type.compare("fileinfo") == 0) {
        
        rec.event_type = 5;
        
        rec.time_stamp = pt.get<string>("timestamp","");
        
        rec.iface = pt.get<string>("in_iface","");
        
        rec.flow_id = pt.get<long>("flow_id",0);
        
        rec.src_ip = pt.get<string>("src_ip","");
        rec.src_agent = GetAgent(rec.src_ip);
        rec.src_port = pt.get<int>("src_port",0);
        
        rec.dst_ip = pt.get<string>("dest_ip","");
        rec.dst_agent = GetAgent(rec.dst_ip);
        rec.dst_port = pt.get<int>("dest_port",0);
        
        rec.protocol = pt.get<string>("proto","");
        
        rec.file.app_proto = pt.get<string>("app_proto","indef");
        if (rec.file.app_proto.compare("") == 0) rec.netflow.app_proto = "indef";
        if (rec.file.app_proto.compare("failed") == 0) rec.netflow.app_proto = "indef";
        
        rec.file.name = pt.get<string>("fileinfo.filename","");
        rec.file.size = pt.get<int>("fileinfo.size",0);
        rec.file.state = pt.get<string>("fileinfo.state","");
        rec.file.md5 = pt.get<string>("fileinfo.md5","");
        
        ResetStream();
        return rec.event_type;
    } 
    
    if (event_type.compare("stats") == 0) {
        
        net_stat.ids = rec.sensor;
        
        net_stat.ref_id = fs.filter.ref_id;
        net_stat.invalid = pt.get<long>("stats.decoder.invalid",0);
        net_stat.pkts = pt.get<long>("stats.decoder.pkts",0);
        net_stat.bytes = pt.get<long>("stats.decoder.bytes",0);
        net_stat.ipv4 = pt.get<long>("stats.decoder.ipv4",0);
        net_stat.ipv6 = pt.get<long>("stats.decoder.ipv6",0);
        net_stat.ethernet = pt.get<long>("stats.decoder.ethernet",0);
        net_stat.tcp = pt.get<long>("stats.decoder.tcp",0);
        net_stat.udp = pt.get<long>("stats.decoder.udp",0);
        net_stat.sctp = pt.get<long>("stats.decoder.sctp",0);
        net_stat.icmpv4 = pt.get<long>("stats.decoder.icmp4",0);
        net_stat.icmpv6 = pt.get<long>("stats.decoder.icmp6",0);
        net_stat.ppp = pt.get<long>("stats.decoder.ppp",0);
        net_stat.pppoe = pt.get<long>("stats.decoder.pppoe",0);
        net_stat.gre = pt.get<long>("stats.decoder.gre",0);
        net_stat.vlan = pt.get<long>("stats.decoder.vlan",0);
        net_stat.vlan_qinq = pt.get<long>("stats.decoder.vlan_qinq",0);
        net_stat.teredo = pt.get<long>("stats.decoder.teredo",0);
        net_stat.ipv4_in_ipv6 = pt.get<long>("stats.decoder.ipv4_in_ipv6",0);
        net_stat.ipv6_in_ipv6 = pt.get<long>("stats.decoder.ipv6_in_ipv6",0);
        net_stat.mpls = pt.get<long>("stats.decoder.mpls",0);
        
        q_netstat.push(net_stat);
    } 
    
    ResetStream();
    return 0;
}

void Nids::CreateLogPayload(int r) {
    
    switch (r) {
            
        case 1: // alert record
            
            report = "{\"version\": \"1.1\",\"node\":\"";
            report += node_id;
            report += "\",\"short_message\":\"alert-nids\"";
            report += ",\"full_message\":\"Alert from Suricata NIDS\"";
            report += ",\"level\":";
            report += std::to_string(7);
            report += ",\"source_type\":\"NET\"";
            report += ",\"source_name\":\"Suricata\"";
			
            report +=  ",\"project_id\":\"";
            report +=  fs.filter.ref_id;
            
            report +=  "\",\"sensor\":\"";
            report +=  rec.sensor;
			
            report +=  "\",\"event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"collected_time\":\"";
            report += GetGraylogFormat();
			
            report += "\",\"severity\":";
            report += std::to_string(rec.alert.severity);
			
            report +=  ",\"category\":\"";
            report +=  rec.alert.category;
			
            report +=  "\",\"signature\":\"";
            report +=  rec.alert.signature;
			
            report +=  "\",\"iface\":\"";
            report +=  rec.iface;
            
            report +=  "\",\"flow_id\":";
            report +=  std::to_string(rec.flow_id);
            
            report +=  ",\"srcip\":\"";
            report +=  rec.src_ip;
			
            report +=  "\",\"dstip\":\"";
            report +=  rec.dst_ip;
            
            report += "\",\"srcagent\":\"";
            report += rec.src_agent;
			
            report += "\",\"dstagent\":\"";
            report += rec.dst_agent;
			
            report +=  "\",\"srcport\":";
            report +=  std::to_string(rec.src_port);
			
            report +=  ",\"dstport\":";
            report +=  std::to_string(rec.dst_port);
			
            report +=  ",\"gid\":";
            report +=  std::to_string(rec.alert.gid);
			
            report +=  ",\"signature_id\":";
            report +=  std::to_string(rec.alert.signature_id);
			
            report +=  ",\"action\":\"";
            report +=  rec.alert.action;
            report +=  "\"}";
            
            //SysLog((char*) report.str().c_str());
            
            break;
            
        case 2: // dns record  
			
            report = "{\"version\": \"1.1\",\"node\":\"";
            report += node_id;
            report += "\",\"short_message\":\"dns-nids\"";
            report += ",\"full_message\":\"DNS event from Suricata NIDS\"";
            report += ",\"level\":";
            report += std::to_string(7);
            report += ",\"source_type\":\"NET\"";
            report += ",\"source_name\":\"Suricata\"";
		
            report +=  ",\"project_id\":\"";
            report +=  fs.filter.ref_id;
            
            report +=  "\",\"sensor\":\"";
            report +=  rec.sensor;
			
            report +=  "\",\"event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"collected_time\":\"";
            report += GetGraylogFormat();
			
            report +=  "\",\"dns_type\":\"";
            report +=  rec.dns.type;
			
            report +=  "\",\"iface\":\"";
            report +=  rec.iface;
            
            report +=  "\",\"flow_id\":";
            report +=  std::to_string(rec.flow_id);
			
            report +=  ",\"srcip\":\"";
            report +=  rec.src_ip;
			
            report +=  "\",\"dstip\":\"";
            report +=  rec.dst_ip;
            
            report += "\",\"srcagent\":\"";
            report += rec.src_agent;
			
            report += "\",\"dstagent\":\"";
            report += rec.dst_agent;
			
            report +=  "\",\"srcport\":";
            report +=  std::to_string(rec.src_port);
			
            report +=  ",\"dstport\":";
            report +=  std::to_string(rec.dst_port);
			
            report +=  ",\"id\":";
            report +=  std::to_string(rec.dns.id);
			
            report +=  ",\"rrname\":\"";
            report +=  rec.dns.rrname;
			
            report +=  "\",\"rrtype\":\"";
            report +=  rec.dns.rrtype;
			
            if (!rec.dns.type.compare("answer")) {
			
                report +=  "\",\"rcode\":\"";
                report +=  rec.dns.rcode;
				
                report +=  "\",\"rdata\":\"";
                report +=  rec.dns.rdata;
				
                report +=  "\",\"ttl\":";
                report +=  std::to_string(rec.dns.ttl);
            }
            else {
                report +=  "\",\"tx_id\":";
                report +=  std::to_string(rec.dns.tx_id);
            }
            report +=  "}";
            
            // SysLog((char*) report.c_str());
            
            break;
            
        case 3: // http record
			
            report = "{\"version\": \"1.1\",\"node\":\"";
            report += node_id;
            report += "\",\"short_message\":\"http-nids\"";
            report += ",\"full_message\":\"HTTP event from Suricata NIDS\"";
            report += ",\"level\":";
            report += std::to_string(7);
            report += ",\"source_type\":\"NET\"";
            report += ",\"source_name\":\"Suricata\"";
		
            report +=  ",\"project_id\":\"";
            report +=  fs.filter.ref_id;
            
            report +=  "\",\"sensor\":\"";
            report +=  rec.sensor;
			
            report +=  "\",\"event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"collected_time\":\"";
            report += GetGraylogFormat();
			
            report +=  "\",\"flow_id\":";
            report +=  std::to_string(rec.flow_id);
			
            report +=  ",\"srcip\":\"";
            report +=  rec.src_ip;
			
            report +=  "\",\"dstip\":\"";
            report +=  rec.dst_ip;
            
            report += "\",\"srcagent\":\"";
            report += rec.src_agent;
			
            report += "\",\"dstagent\":\"";
            report += rec.dst_agent;
			
            report +=  "\",\"srcport\":";
            report +=  std::to_string(rec.src_port);
			
            report +=  ",\"dstport\":";
            report +=  std::to_string(rec.dst_port);
			
            report +=  ",\"url_hostname\":\"";
            report +=  rec.http.hostname;
			
            report +=  "\",\"url_path\":\"";
            report +=  rec.http.url;
			
            report +=  "\",\"http_user_agent\":\"";
            report +=  rec.http.http_user_agent;
			
            report +=  "\",\"http_content_type\":\"";
            report +=  rec.http.http_content_type;
            report +=  "\"}";
            
            break;
            
        case 4: // flow record
		
            report = "{\"version\": \"1.1\",\"node\":\"";
            report += node_id;
            report += "\",\"short_message\":\"netflow-nids\"";
            report += ",\"full_message\":\"Netflow event from Suricata NIDS\"";
            report += ",\"level\":";
            report += std::to_string(7);
            report += ",\"source_type\":\"NET\"";
            report += ",\"source_name\":\"Suricata\"";
			
            report +=  ",\"project_id\":\"";
            report +=  fs.filter.ref_id;
            
            report +=  "\",\"sensor\":\"";
            report +=  rec.sensor;
			
            report +=  "\",\"event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"collected_time\":\"";
            report += GetGraylogFormat();
			
            report += "\",\"protocol\":\"";
            report += rec.protocol;
			
            report += "\",\"process\":\"";
            report += rec.netflow.app_proto;
			
            report += "\",\"srcip\":\"";
            report += rec.src_ip;
            
            report += "\",\"srcagent\":\"";
            report += rec.src_agent;
            
            report += "\",\"srcport\":";
            report += std::to_string(rec.src_port);
			
            report += ",\"dstip\":\"";
            report += rec.dst_ip;
            
            report += "\",\"dstagent\":\"";
            report += rec.dst_agent;
			
            report += "\",\"dstport\":";
            report += std::to_string(rec.dst_port);
			
            report += ",\"bytes\":";
            report += std::to_string(rec.netflow.bytes);
			
            report += ",\"packets\":";
            report += std::to_string(rec.netflow.pkts);
			
            report += "}";
            break;
            
        case 5: // file record
		
            report = "{\"version\": \"1.1\",\"node\":\"";
            report += node_id;
            report += "\",\"short_message\":\"file-nids\"";
            report += ",\"full_message\":\"File event from Suricata NIDS\"";
            report += ",\"level\":";
            report += std::to_string(7);
            report += ",\"source_type\":\"NET\"";
            report += ",\"source_name\":\"Suricata\"";
			
            report +=  ",\"project_id\":\"";
            report +=  fs.filter.ref_id;
            
            report +=  "\",\"sensor\":\"";
            report +=  rec.sensor;
			
            report +=  "\",\"event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"collected_time\":\"";
            report += GetGraylogFormat();
			
            report += "\",\"protocol\":\"";
            report += rec.protocol;
			
            report += "\",\"process\":\"";
            report += rec.file.app_proto;
			
            report += "\",\"srcip\":\"";
            report += rec.src_ip;
            
            report += "\",\"srcagent\":\"";
            report += rec.src_agent;
            
            report += "\",\"srcport\":";
            report += std::to_string(rec.src_port);
			
            report += ",\"dstip\":\"";
            report += rec.dst_ip;
            
            report += "\",\"dstagent\":\"";
            report += rec.dst_agent;
			
            report += "\",\"dstport\":";
            report += std::to_string(rec.dst_port);
			
            report += ",\"filename\":\"";
            report += rec.file.name;
			
            report += "\",\"size\":";
            report += std::to_string(rec.file.size);
			
            report += ",\"state\":\"";
            report += rec.file.state;
			
            report += "\",\"md5\":\"";
            report += rec.file.md5;
			
            report += "\"}";
            break;
    }
    
    q_logs_nids.push(report);
    report.clear();
}

void Nids::SendAlert(int s, GrayList* gl) {
    
    sk.alert.ref_id =  fs.filter.ref_id;
    sk.alert.sensor_id = rec.sensor;
    
    sk.alert.alert_severity = s;
    sk.alert.alert_source = "Suricata";
    sk.alert.alert_type = "NET";
    sk.alert.event_severity = rec.alert.severity;
    sk.alert.event_id = std::to_string(rec.alert.signature_id);
    sk.alert.description = rec.alert.signature;
    sk.alert.action = "indef";     
    sk.alert.location = std::to_string(rec.flow_id);
    sk.alert.info = "{\"artifacts\": [{\"dataType\": \"ip\",\"data\":\"";
    sk.alert.info += rec.src_ip;
    sk.alert.info += "\",\"message\":\"src ip\" }, {\"dataType\": \"ip\",\"data\":\"";
    sk.alert.info += rec.dst_ip;
    sk.alert.info += "\",\"message\":\"dst ip\" }]}";
    sk.alert.status = "processed";
    sk.alert.user_name = "indef";
    sk.alert.agent_name = probe_id;
    sk.alert.filter = fs.filter.name;
        
    sk.alert.list_cats.push_back(rec.alert.category);
    
    sk.alert.event_time = rec.time_stamp;
                
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
        
        if (gl->rsp.new_event.compare("indef") != 0) {
            sk.alert.event_id = gl->rsp.new_event;
            sk.alert.status = "modified";
        }    
            
        if (gl->rsp.new_severity != 0) {
            sk.alert.alert_severity = gl->rsp.new_severity;
            sk.alert.status = "modified";
        }   
            
        if (gl->rsp.new_category.compare("indef") != 0) {
            sk.alert.list_cats.push_back(gl->rsp.new_category);
            sk.alert.status = "modified";
        }   
                
        if (gl->rsp.new_description.compare("indef") != 0) {
            sk.alert.description = gl->rsp.new_description;
            sk.alert.status = "modified";
        }   
        
    }
        
    sk.alert.src_ip = rec.src_ip;
    sk.alert.dst_ip = rec.dst_ip;
    
    sk.alert.src_port = rec.src_port;
    sk.alert.dst_port = rec.dst_port;
    
    sk.alert.src_hostname = rec.src_agent;
    sk.alert.dst_hostname = rec.dst_agent;
    
    sk.alert.reg_value = "indef";
    sk.alert.file_name = "indef";
	
    sk.alert.hash_md5 = "indef";
    sk.alert.hash_sha1 = "indef";
    sk.alert.hash_sha256 = "indef";
	
    sk.alert.process_id = 0;
    sk.alert.process_name = "indef";
    sk.alert.process_cmdline = "indef";
    sk.alert.process_path = "indef";
    
    sk.alert.url_hostname = "indef";
    sk.alert.url_path = "indef";
    
    sk.alert.container_id = "indef";
    sk.alert.container_name = "indef";
    
    sk.alert.cloud_instance = "indef";
    
    sk.SendAlert();
    ResetStream();
}

int Nids::PushIdsRecord(GrayList* gl) {
    // create new ids record
    IdsRecord ids_rec;
                
    ids_rec.ids_type = 3;
                
    ids_rec.ref_id = fs.filter.ref_id;
                
    ids_rec.list_cats.push_back(rec.alert.category);
                
    ids_rec.event = std::to_string(rec.alert.signature_id);
    ids_rec.desc = rec.alert.signature;
    ids_rec.severity = rec.alert.severity;
        
    switch (rec.alert.severity) {
        case 1 :
            ids_rec.severity = 3; 
            break;
        case 2 :
            ids_rec.severity = 2; 
            break;
        case 3 :
            ids_rec.severity = 1; 
            break;
        default :
            ids_rec.severity = 0; 
            break;
    }
    
    ids_rec.src_ip = rec.src_ip;
    ids_rec.dst_ip = rec.dst_ip;
    
    ids_rec.agent = probe_id;
    ids_rec.ids = rec.sensor;
    ids_rec.location = rec.dst_agent;
                            
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
                                    
    q_nids.push(ids_rec);
    
    return ids_rec.severity;
}
