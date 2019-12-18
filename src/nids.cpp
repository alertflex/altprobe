/* 
 * File:   nids.cpp
 * Author: Oleg Zharkov
 *
 * Created on May 26, 2014, 10:43 AM
 */

#include "nids.h"


boost::lockfree::spsc_queue<string> q_logs_nids{LOG_QUEUE_SIZE};

int Nids::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (status == 1) {
        
        if (surilog_status == 2) {
            
            fp = fopen(suri_log, "r");
            if(fp == NULL) {
                SysLog("failed open suricata log file");
                return 0;
            }
            
            fseek(fp,0,SEEK_END);
            stat(suri_log, &buf);    
            file_size = (unsigned long) buf.st_size;
            
        } else {
            
            if (surilog_status == 1) {
                c = redisConnect(sk.redis_host, sk.redis_port);
    
                if (c != NULL && c->err) {
                    // handle error
                    sprintf(level, "failed open redis server interface: %s\n", c->errstr);
                    SysLog(level);
                    return 0;
                }
            }  else return 0;
        }
    }
    
    return 1;
}

void Nids::Close() {
    
    sk.Close();
    
    if (status == 1) {
        
        if (surilog_status == 2) {
            if (fp != NULL) fclose(fp);
        } else redisFree(c);
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
        
        if (surilog_status == 2) {
            
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
            } else {
                
                if (res == 3) PushFlowsRecord();
            
            }
        } 
            
        if (surilog_status == 1) freeReplyObject(reply);
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
                
                string agent = (*i)->host;
                
                if (agent.compare("all") == 0 || agent.compare(rec.src_agent) == 0 || agent.compare(rec.dst_agent) == 0) {
                        
                    return (*i);
                }
            }
        }
    }
    
    return NULL;
}


int Nids::ParsJson () {
    
    // SysLog(payload);
    
    if (surilog_status == 1) jsonPayload.assign(reply->str, GetBufferSize(reply->str));
    else jsonPayload.assign(file_payload, GetBufferSize(file_payload));
    
    try {
        ss << jsonPayload;
        bpt::read_json(ss, pt);
    
    } catch (const std::exception & ex) {
        ResetStream();
        SysLog((char*) ex.what());
        return 0;
    } 
    
    string event_type = pt.get<string>("event_type","");
    
    if (event_type.compare("alert") == 0) {
        
        IncrementEventsCounter();
        
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
        
        rec.ids = sensor;
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
        
        rec.ids = sensor;
        
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
    
    if (event_type.compare("ssh") == 0) {
        
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
        
        rec.ids = sensor;
        rec.protocol = pt.get<string>("proto","");
        
        rec.ssh.client_proto = pt.get<string>("ssh.client.proto_version","indef");
        rec.ssh.server_proto = pt.get<string>("ssh.server.proto_version","indef");
        rec.ssh.client_sw = pt.get<string>("ssh.client.software_version","indef");
        rec.ssh.server_sw = pt.get<string>("ssh.server.software_version","indef");
        
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
        
        rec.ids = sensor;
        rec.protocol = pt.get<string>("proto","");
        
        rec.netflow.app_proto = pt.get<string>("app_proto","indef");
        if (rec.netflow.app_proto.compare("") == 0) rec.netflow.app_proto = "indef";
        if (rec.netflow.app_proto.compare("failed") == 0) rec.netflow.app_proto = "indef";
        
        rec.netflow.bytes = pt.get<int>("netflow.bytes",0);
        rec.netflow.pkts = pt.get<int>("netflow.pkts",0);
        rec.netflow.start = pt.get<string>("netflow.start","");
        rec.netflow.end = pt.get<string>("netflow.end","");
        rec.netflow.age = pt.get<int>("netflow.age",0);
        
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
        
        rec.ids = sensor;
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
    
    rec.event_type = 0;
    
    if (event_type.compare("stats") == 0) {
        
        net_stat.ids = sensor;
        
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
    return rec.event_type;
}

void Nids::CreateLogPayload(int r) {
    
    switch (r) {
            
        case 1: // alert record
            
            report = "{\"version\": \"1.1\",\"host\":\"";
            report += node_id;
            report += "\",\"short_message\":\"alert-nids\"";
            report += ",\"full_message\":\"Alert from Suricata NIDS\"";
            report += ",\"level\":";
            report += std::to_string(7);
            report += ",\"_type\":\"NET\"";
            report += ",\"_source\":\"Suricata\"";
			
            report +=  ",\"_project_id\":\"";
            report +=  fs.filter.ref_id;
			
            report +=  "\",\"_event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"_collected_time\":\"";
            report += GetGraylogFormat();
			
            report += "\",\"_severity\":";
            report += std::to_string(rec.alert.severity);
			
            report +=  ",\"_category\":\"";
            report +=  rec.alert.category;
			
            report +=  "\",\"_signature\":\"";
            report +=  rec.alert.signature;
			
            report +=  "\",\"_iface\":\"";
            report +=  rec.iface;
            
            report +=  "\",\"_flow_id\":";
            report +=  std::to_string(rec.flow_id);
            
            report +=  ",\"_srcip\":\"";
            report +=  rec.src_ip;
			
            report +=  "\",\"_dstip\":\"";
            report +=  rec.dst_ip;
            
            report +=  "\",\"_ids\":\"";
            report +=  rec.ids;
			
            report += "\",\"_srcip_host\":\"";
            report += rec.src_agent;
			
            report += "\",\"_dstip_host\":\"";
            report += rec.dst_agent;
			
            report +=  "\",\"_srcport\":";
            report +=  std::to_string(rec.src_port);
			
            report +=  ",\"_dstport\":";
            report +=  std::to_string(rec.dst_port);
			
            report +=  ",\"_gid\":";
            report +=  std::to_string(rec.alert.gid);
			
            report +=  ",\"_signature_id\":";
            report +=  std::to_string(rec.alert.signature_id);
			
            report +=  ",\"_action\":\"";
            report +=  rec.alert.action;
            report +=  "\"}";
            
            //SysLog((char*) report.str().c_str());
            
            break;
            
        case 2: // dns record  
			
            report = "{\"version\": \"1.1\",\"host\":\"";
            report += node_id;
            report += "\",\"short_message\":\"dns-nids\"";
            report += ",\"full_message\":\"DNS event from Suricata NIDS\"";
            report += ",\"level\":";
            report += std::to_string(7);
            report += ",\"_type\":\"NET\"";
            report += ",\"_source\":\"Suricata\"";
		
            report +=  ",\"_project_id\":\"";
            report +=  fs.filter.ref_id;
			
            report +=  "\",\"_event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"_collected_time\":\"";
            report += GetGraylogFormat();
			
            report +=  "\",\"_dns_type\":\"";
            report +=  rec.dns.type;
			
            report +=  "\",\"_iface\":\"";
            report +=  rec.iface;
            
            report +=  "\",\"_flow_id\":";
            report +=  std::to_string(rec.flow_id);
			
            report +=  ",\"_srcip\":\"";
            report +=  rec.src_ip;
			
            report +=  "\",\"_dstip\":\"";
            report +=  rec.dst_ip;
            
            report +=  "\",\"_ids\":\"";
            report +=  rec.ids;
			
            report += "\",\"_srcip_host\":\"";
            report += rec.src_agent;
			
            report += "\",\"_dstip_host\":\"";
            report += rec.dst_agent;
			
            report +=  "\",\"_srcport\":";
            report +=  std::to_string(rec.src_port);
			
            report +=  ",\"_dstport\":";
            report +=  std::to_string(rec.dst_port);
			
            report +=  ",\"_id\":";
            report +=  std::to_string(rec.dns.id);
			
            report +=  ",\"_rrname\":\"";
            report +=  rec.dns.rrname;
			
            report +=  "\",\"_rrtype\":\"";
            report +=  rec.dns.rrtype;
			
            if (!rec.dns.type.compare("answer")) {
			
                report +=  "\",\"_rcode\":\"";
                report +=  rec.dns.rcode;
				
                report +=  "\",\"_rdata\":\"";
                report +=  rec.dns.rdata;
				
                report +=  "\",\"_ttl\":";
                report +=  std::to_string(rec.dns.ttl);
            }
            else {
                report +=  "\",\"_tx_id\":";
                report +=  std::to_string(rec.dns.tx_id);
            }
            report +=  "}";
            
            // SysLog((char*) report.c_str());
            
            break;
            
        case 3: // ssh record
			
            report = "{\"version\": \"1.1\",\"host\":\"";
            report += node_id;
            report += "\",\"short_message\":\"ssh-nids\"";
            report += ",\"full_message\":\"SSH event from Suricata NIDS\"";
            report += ",\"level\":";
            report += std::to_string(7);
            report += ",\"_type\":\"NET\"";
            report += ",\"_source\":\"Suricata\"";
		
            report +=  ",\"_project_id\":\"";
            report +=  fs.filter.ref_id;
			
            report +=  "\",\"_event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"_collected_time\":\"";
            report += GetGraylogFormat();
			
            report +=  "\",\"_iface\":\"";
            report +=  rec.iface;
            
            report +=  "\",\"_flow_id\":";
            report +=  std::to_string(rec.flow_id);
			
            report +=  ",\"_srcip\":\"";
            report +=  rec.src_ip;
			
            report +=  "\",\"_dstip\":\"";
            report +=  rec.dst_ip;
            
            report +=  "\",\"_ids\":\"";
            report +=  rec.ids;
			
            report += "\",\"_srcip_host\":\"";
            report += rec.src_agent;
			
            report += "\",\"_dstip_host\":\"";
            report += rec.dst_agent;
			
            report +=  "\",\"_srcport\":";
            report +=  std::to_string(rec.src_port);
			
            report +=  ",\"_dstport\":";
            report +=  std::to_string(rec.dst_port);
			
            report +=  ",\"_client_proto_ver\":\"";
            report +=  rec.ssh.client_proto;
			
            report +=  "\",\"_client_sw_ver\":\"";
            report +=  rec.ssh.client_sw;
			
            report +=  "\",\"_server_proto_ver\":\"";
            report +=  rec.ssh.server_proto;
			
            report +=  "\",\"_server_sw_ver\":\"";
            report +=  rec.ssh.server_sw;
            report +=  "\"}";
            
            break;
            
        case 4: // flow record
		
            report = "{\"version\": \"1.1\",\"host\":\"";
            report += node_id;
            report += "\",\"short_message\":\"netflow-nids\"";
            report += ",\"full_message\":\"Netflow event from Suricata NIDS\"";
            report += ",\"level\":";
            report += std::to_string(7);
            report += ",\"_type\":\"NET\"";
            report += ",\"_source\":\"Suricata\"";
			
            report +=  ",\"_project_id\":\"";
            report +=  fs.filter.ref_id;
			
            report +=  "\",\"_event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"_collected_time\":\"";
            report += GetGraylogFormat();
			
            report += "\",\"_protocol\":\"";
            report += rec.protocol;
			
            report += "\",\"_app_proto\":\"";
            report += rec.netflow.app_proto;
			
            report +=  "\",\"_iface\":\"";
            report +=  rec.iface;
            
            report +=  "\",\"_flow_id\":";
            report +=  std::to_string(rec.flow_id);
			
            report += ",\"_srcip\":\"";
            report += rec.src_ip;
			
            report += "\",\"_dstip\":\"";
            report += rec.dst_ip;
            
            report +=  "\",\"_ids\":\"";
            report +=  rec.ids;
			
            report += "\",\"_srcip_host\":\"";
            report += rec.src_agent;
			
            report += "\",\"_dstip_host\":\"";
            report += rec.dst_agent;
			
            report += "\",\"_srcport\":";
            report += std::to_string(rec.src_port);
			
            report += ",\"_dstport\":";
            report += std::to_string(rec.dst_port);
			
            report += ",\"_bytes\":";
            report += std::to_string(rec.netflow.bytes);
			
            report += ",\"_pkts\":";
            report += std::to_string(rec.netflow.pkts);
			
            report += ",\"_age\":";
            report += std::to_string(rec.netflow.age);
			
            report += ",\"_start\":\"";
            report += rec.netflow.start;
			
            report += "\",\"_end\":\"";
            report += rec.netflow.end;
			
            report += "\"}";
            break;
            
        case 5: // file record
		
            report = "{\"version\": \"1.1\",\"host\":\"";
            report += node_id;
            report += "\",\"short_message\":\"file-nids\"";
            report += ",\"full_message\":\"File event from Suricata NIDS\"";
            report += ",\"level\":";
            report += std::to_string(7);
            report += ",\"_type\":\"NET\"";
            report += ",\"_source\":\"Suricata\"";
			
            report +=  ",\"_project_id\":\"";
            report +=  fs.filter.ref_id;
			
            report +=  "\",\"_event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"_collected_time\":\"";
            report += GetGraylogFormat();
			
            report += "\",\"_protocol\":\"";
            report += rec.protocol;
			
            report += "\",\"_app_proto\":\"";
            report += rec.file.app_proto;
			
            report +=  "\",\"_iface\":\"";
            report +=  rec.iface;
            
            report +=  "\",\"_flow_id\":";
            report +=  std::to_string(rec.flow_id);
			
            report += ",\"_srcip\":\"";
            report += rec.src_ip;
			
            report += "\",\"_dstip\":\"";
            report += rec.dst_ip;
            
            report +=  "\",\"_ids\":\"";
            report +=  rec.ids;
			
            report += "\",\"_srcip_host\":\"";
            report += rec.src_agent;
			
            report += "\",\"_dstip_host\":\"";
            report += rec.dst_agent;
			
            report += "\",\"_srcport\":";
            report += std::to_string(rec.src_port);
			
            report += ",\"_dstport\":";
            report += std::to_string(rec.dst_port);
			
            report += ",\"_filename\":\"";
            report += rec.file.name;
			
            report += "\",\"_size\":";
            report += std::to_string(rec.file.size);
			
            report += ",\"_state\":\"";
            report += rec.file.state;
			
            report += "\",\"_md5\":\"";
            report += rec.file.md5;
			
            report += "\"}";
            break;
    }
    
    q_logs_nids.push(report);
    report.clear();
}

void Nids::SendAlert(int s, GrayList* gl) {
    
    sk.alert.ref_id = fs.filter.ref_id;
    
    sk.alert.type = "NET";
    sk.alert.source = "Suricata";
    
    sk.alert.list_cats.push_back(rec.alert.category);
        
    sk.alert.severity = s; 
    sk.alert.score = rec.alert.severity;
    sk.alert.event = std::to_string(rec.alert.signature_id);
    sk.alert.action = "indef";
    sk.alert.description = rec.alert.signature;
        
    sk.alert.status = "processed_new";
    
    sk.alert.srcip = rec.src_ip;
    sk.alert.dstip = rec.dst_ip;
    
    sk.alert.srcport = rec.src_port;
    sk.alert.dstport = rec.dst_port;
    
    sk.alert.srcagent = rec.src_agent;
    sk.alert.dstagent = rec.dst_agent;
    sk.alert.user = "indef";
            
    if (gl != NULL) {
            
        if (gl->rsp.profile.compare("indef") != 0) {
            sk.alert.action = gl->rsp.profile;
            sk.alert.status = "modified_new";
        } 
        
        if (gl->rsp.new_event.compare("") != 0) {
            sk.alert.event = gl->rsp.new_event;
            sk.alert.status = "modified_new";
        }    
            
        if (gl->rsp.new_severity != 0) {
            sk.alert.severity = gl->rsp.new_severity;
            sk.alert.status = "modified_new";
        }   
            
        if (gl->rsp.new_category.compare("") != 0) {
            sk.alert.list_cats.push_back(gl->rsp.new_category);
            sk.alert.status = "modified_new";
        }   
                
        if (gl->rsp.new_description.compare("") != 0) {
            sk.alert.description = gl->rsp.new_description;
            sk.alert.status = "modified_new";
        }   
        
    }
        
    sk.alert.sensor = rec.ids;
    sk.alert.agent = "";
    sk.alert.process = "";
    sk.alert.container = "";
    sk.alert.sensor = rec.ids;
    sk.alert.location = std::to_string(rec.flow_id);
    sk.alert.filter = fs.filter.desc;
    sk.alert.event_time = rec.time_stamp;
              
    sk.alert.info = "\"artifacts\": [";
    
    sk.alert.info += " {\"dataType\": \"ip\",\"data\":\"";
    sk.alert.info += rec.src_ip;
    sk.alert.info += "\",\"message\":\"src ip\" }, ";
        
    sk.alert.info += " {\"dataType\": \"ip\",\"data\":\"";
    sk.alert.info += rec.dst_ip;
    sk.alert.info += "\",\"message\":\"dst ip\" } ";
        
    sk.alert.info += "]";
        
    sk.alert.event_json = jsonPayload;
    
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
    
    ids_rec.agent = rec.src_agent;
    ids_rec.ids = rec.ids;
    ids_rec.location = rec.dst_agent;
                            
    if (gl != NULL) {
        
        if (gl->agr.reproduced > 0) {
            
            ids_rec.agr.in_period = gl->agr.in_period;
            ids_rec.agr.reproduced = gl->agr.reproduced;
            
            ids_rec.rsp.profile = gl->rsp.profile;
            ids_rec.rsp.new_category = gl->rsp.new_category;
            ids_rec.rsp.new_description = gl->rsp.new_description;
            ids_rec.rsp.new_event = gl->rsp.new_event;
            ids_rec.rsp.new_severity = gl->rsp.new_severity;
            
        }
    }
                                    
    q_nids.push(ids_rec);
    
    return ids_rec.severity;
}

void Nids::PushFlowsRecord() {
    
    FlowsRecord flows_rec;
    
    switch (rec.event_type) {
        
        case 0:
            break;
        
        case 1:
            break;
        
        case 2: // dns record
            break;
            
        case 3: // ssh record
                        
            flows_rec.ref_id = fs.filter.ref_id;
            flows_rec.flows_type = 3;
            
            flows_rec.src_ip = rec.src_ip;
            flows_rec.dst_ip = rec.dst_ip;
            
            flows_rec.src_agent = rec.src_agent;
            flows_rec.dst_agent = rec.dst_agent;
            
            flows_rec.ids = rec.ids;
                
            flows_rec.info1 = rec.ssh.client_sw;
            flows_rec.info2 = rec.ssh.server_sw;
    
            flows_rec.bytes = 0;
    
            q_flows.push(flows_rec);
            break;
            
        case 4: // flows record
            break;
            
        case 5: // file record
            break;
        
        default:
            break;
    }
}
