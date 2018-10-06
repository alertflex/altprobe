/* 
 * File:   nids.cpp
 * Author: Oleg Zharkov
 *
 * Created on May 26, 2014, 10:43 AM
 */

#include "nids.h"


boost::lockfree::spsc_queue<string> q_logs_nids{LOG_QUEUE_SIZE};

int Nids::Go(void) {
    
    // boost::shared_lock<boost::shared_mutex> lock(fs.filters_update_lock);
    
    BwList* bwl;
    int severity;
    int res = 0;
    
    ClearRecords();
    
    if (status) {
        
        // read Suricata data 
        reply = (redisReply *) redisCommand( c, (const char *) redis_key.c_str());
        
        
        if (!reply) {
            SysLog("failed reading suricata events from redis");
            freeReplyObject(reply);
            return 1;
        }
        
        if (reply->type == REDIS_REPLY_STRING) {
            res = ParsJson(reply->str);
        } else {
            freeReplyObject(reply);
            usleep(GetGosleepTimer()*60);
            
            alerts_counter = 0;
            return 1;
        }
        
        if (res != 0) {
            
            boost::shared_lock<boost::shared_mutex> lock(fs.filters_update);
        
            if (fs.filter.nids.log) CreateLogPayload(res);
                
            if (res == 1 && alerts_counter <= sk.alerts_threshold) {
                    
                bwl = CheckBwList();
                
                severity = PushIdsRecord(bwl);
                    
                if (bwl != NULL) {
                    if (bwl->rsp.profile.compare("suppress") != 0) {
                        SendAlert(severity, bwl);
                    }
                } else {
                    if (fs.filter.nids.severity <= severity) SendAlert(severity, NULL);
                }
                    
                if (sk.alerts_threshold != 0) {
            
                    if (alerts_counter < sk.alerts_threshold) alerts_counter++;
                    else {
                        SendAlertMultiple(3);
                        alerts_counter++;
                    }
                }
            } else {
                PushFlowsRecord();
            }
        } 
            
        freeReplyObject(reply);
    } 
    else {
        usleep(GetGosleepTimer()*60);
    }
        
    return 1;
}


BwList* Nids::CheckBwList() {
    
    if (fs.filter.nids.bwl.size() != 0) {
        
        std::vector<BwList*>::iterator i, end;
        
        for (i = fs.filter.nids.bwl.begin(), end = fs.filter.nids.bwl.end(); i != end; ++i) {
            int event_id = (*i)->event;
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


int Nids::ParsJson (char* redis_payload) {
    
    jsonPayload.assign(reply->str, GetBufferSize(reply->str));
    
    try {
        ss << redis_payload;
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
        
        rec.flow_id = pt.get<int>("flow_id",0);
        
        rec.src_ip = pt.get<string>("src_ip","");
        rec.src_type = IsHomeNetwork(rec.src_ip);
        if (rec.src_type == 0) rec.src_agent = "ext_net";
        else rec.src_agent = fs.GetAgentNameByIP(rec.src_ip);
        rec.src_port = pt.get<int>("src_port",0);
        
        rec.dst_ip = pt.get<string>("dest_ip","");
        rec.dst_type = IsHomeNetwork(rec.dst_ip);
        if (rec.dst_type == 0) rec.dst_agent = "ext_net";
        else rec.dst_agent = fs.GetAgentNameByIP(rec.dst_ip);
        rec.dst_port = pt.get<int>("dest_port",0);
        
        rec.ids = pt.get<string>("host","");
        rec.protocol = pt.get<string>("proto","");
                
        // alert record
        rec.alert.action = pt.get<string>("alert.action","");
                
        rec.alert.gid = pt.get<int>("alert.gid",0); 
        rec.alert.signature_id = pt.get<int>("alert.signature_id",0); 
                
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
        
        rec.flow_id = pt.get<int>("flow_id",0);
        
        rec.src_ip = pt.get<string>("src_ip","");
        rec.src_type = IsHomeNetwork(rec.src_ip);
        if (rec.src_type == 0) rec.src_agent = "ext_net";
        else rec.src_agent = fs.GetAgentNameByIP(rec.src_ip);
        rec.src_port = pt.get<int>("src_port",0);
        
        rec.dst_ip = pt.get<string>("dest_ip","");
        rec.dst_type = IsHomeNetwork(rec.dst_ip);
        if (rec.dst_type == 0) rec.dst_agent = "ext_net";
        else rec.dst_agent = fs.GetAgentNameByIP(rec.dst_ip);
        rec.dst_port = pt.get<int>("dest_port",0);
        
        rec.ids = pt.get<string>("host","");
        
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
        
        rec.flow_id = pt.get<long>("flow_id",0);
        
        rec.src_ip = pt.get<string>("src_ip","");
        rec.src_type = IsHomeNetwork(rec.src_ip);
        if (rec.src_type == 0) rec.src_agent = "ext_net";
        else rec.src_agent = fs.GetAgentNameByIP(rec.src_ip);
        rec.src_port = pt.get<int>("src_port",0);
        
        rec.dst_ip = pt.get<string>("dest_ip","");
        rec.dst_type = IsHomeNetwork(rec.dst_ip);
        if (rec.dst_type == 0) rec.dst_agent = "ext_net";
        else rec.dst_agent = fs.GetAgentNameByIP(rec.dst_ip);
        rec.dst_port = pt.get<int>("dest_port",0);
        
        rec.ids = pt.get<string>("host","");
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
        
        rec.flow_id = pt.get<long>("flow_id",0);
        
        rec.src_ip = pt.get<string>("src_ip","");
        rec.src_type = IsHomeNetwork(rec.src_ip);
        if (rec.src_type == 0) rec.src_agent = "ext_net";
        else rec.src_agent = fs.GetAgentNameByIP(rec.src_ip);
        rec.src_port = pt.get<int>("src_port",0);
        
        rec.dst_ip = pt.get<string>("dest_ip","");
        rec.dst_type = IsHomeNetwork(rec.dst_ip);
        if (rec.dst_type == 0) rec.dst_agent = "ext_net";
        else rec.dst_agent = fs.GetAgentNameByIP(rec.dst_ip);
        rec.dst_port = pt.get<int>("dest_port",0);
        
        rec.ids = pt.get<string>("host","");
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
    
    rec.event_type = 0;
    
    if (event_type.compare("stats") == 0) {
        
        net_stat.ids = pt.get<string>("host","");
        
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
			
            report +=  ",\"_event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"_collected_time\":\"";
            report += GetGraylogFormat();
			
            report += "\",\"_severity\":";
            report += std::to_string(rec.alert.severity);
			
            report +=  ",\"_category\":\"";
            report +=  rec.alert.category;
			
            report +=  "\",\"_signature\":\"";
            report +=  rec.alert.signature;
			
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
		
            report +=  ",\"_event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"_collected_time\":\"";
            report += GetGraylogFormat();
			
            report +=  "\",\"_dns_type\":\"";
            report +=  rec.dns.type;
			
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
		
            report +=  ",\"_event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"_collected_time\":\"";
            report += GetGraylogFormat();
			
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
            
            //SysLog((char*) report.str().c_str());
            
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
			
            report +=  ",\"_event_time\":\"";
            report +=  rec.time_stamp;
            
            report += "\",\"_collected_time\":\"";
            report += GetGraylogFormat();
			
            report += "\",\"_protocol\":\"";
            report += rec.protocol;
			
            report += "\",\"_app_proto\":\"";
            report += rec.netflow.app_proto;
			
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
    }
    
    q_logs_nids.push(report);
    report.clear();
}

void Nids::SendAlert(int s, BwList* bwl) {
    
    sk.alert.ref_id = fs.filter.ref_id;
    
    sk.alert.type = "NET";
    sk.alert.source = "Suricata";
    
    sk.alert.list_cats.push_back(rec.alert.category);
        
    sk.alert.severity = s; 
    sk.alert.event = rec.alert.signature_id;
    sk.alert.action = "none";
    sk.alert.description = rec.alert.signature;
        
    sk.alert.status = "processed_new";
    
    sk.alert.srcip = rec.src_ip;
    sk.alert.dstip = rec.dst_ip;
            
    if (bwl != NULL) {
            
        if (bwl->rsp.profile.compare("none") != 0) {
            sk.alert.action = bwl->rsp.profile;
            sk.alert.status = "modified_new";
        } 
        
        if (bwl->rsp.new_event != 0) {
            sk.alert.event = bwl->rsp.new_event;
            sk.alert.status = "modified_new";
        }    
            
        if (bwl->rsp.new_severity != 0) {
            sk.alert.severity = bwl->rsp.new_severity;
            sk.alert.status = "modified_new";
        }   
            
        if (bwl->rsp.new_category.compare("") != 0) {
            sk.alert.list_cats.push_back(bwl->rsp.new_category);
            sk.alert.status = "modified_new";
        }   
                
        if (bwl->rsp.new_description.compare("") != 0) {
            sk.alert.description = bwl->rsp.new_description;
            sk.alert.status = "modified_new";
        }   
        
        if (bwl->rsp.ipblock_type.compare("none") != 0) {
            
            if (bwl->rsp.ipblock_type.compare("src") == 0 && sk.alert.srcip.compare("") != 0) {
                
                if (!IsHomeNetwork(rec.src_ip)) {
                    ExecCmd(rec.src_ip, "src");
                    sk.alert.severity = 3;
                    sk.alert.list_cats.push_back("srcip_blocked");
                }
                
            } else {
                if (bwl->rsp.ipblock_type.compare("dst") == 0 && sk.alert.dstip.compare("") != 0) {
                    
                    if (!IsHomeNetwork(rec.dst_ip)) {
                        ExecCmd(rec.dst_ip, "dst");
                        sk.alert.severity = 3;
                        sk.alert.list_cats.push_back("dstip_blocked");
                    }
                    
                }
            }
        }
    }
        
    if (rec.dst_agent.compare("ext_net") != 0) sk.alert.agent = rec.dst_agent;
    else {
        if (rec.src_agent.compare("ext_net") != 0) sk.alert.agent = rec.src_agent;
        else sk.alert.agent = "ext_net";
    }
    
    sk.alert.hostname = rec.ids;
    sk.alert.location = rec.dst_agent;
              
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

int Nids::PushIdsRecord(BwList* bwl) {
    // create new ids record
    IdsRecord ids_rec;
                
    ids_rec.ids_type = 3;
                
    ids_rec.ref_id = fs.filter.ref_id;
                
    ids_rec.list_cats.push_back(rec.alert.category);
                
    ids_rec.event = rec.alert.signature_id;
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
                            
    if (bwl != NULL) {
        
        if (bwl->agr.reproduced > 0) {
            
            ids_rec.agr.in_period = bwl->agr.in_period;
            ids_rec.agr.reproduced = bwl->agr.reproduced;
            
            ids_rec.rsp.profile = bwl->rsp.profile;
            ids_rec.rsp.ipblock_type = bwl->rsp.ipblock_type;
            ids_rec.rsp.new_category = bwl->rsp.new_category;
            ids_rec.rsp.new_description = bwl->rsp.new_description;
            ids_rec.rsp.new_event = bwl->rsp.new_event;
            ids_rec.rsp.new_severity = bwl->rsp.new_severity;
            
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
            
            flows_rec.ref_id = fs.filter.ref_id;
            flows_rec.flows_type = 2;
            
            flows_rec.src_ip = rec.src_ip;
            flows_rec.dst_ip = rec.dst_ip;
            
            flows_rec.src_agent = rec.src_agent;
            flows_rec.dst_agent = rec.dst_agent;
            
            flows_rec.ids = rec.ids;
            
            flows_rec.info1 = rec.dns.rrname;
            flows_rec.info2 = rec.dns.rdata;
    
            flows_rec.bytes = rec.netflow.bytes;
    
            q_flows.push(flows_rec);
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
                        
            flows_rec.ref_id = fs.filter.ref_id;
            flows_rec.flows_type = 1;
            
            flows_rec.src_ip = rec.src_ip;
            flows_rec.dst_ip = rec.dst_ip;
            flows_rec.dst_port = rec.dst_port;
            
            flows_rec.src_agent = rec.src_agent;
            flows_rec.dst_agent = rec.dst_agent;
            
    
    
            flows_rec.ids = rec.ids;
    
            flows_rec.info1 = rec.netflow.app_proto;
    
            flows_rec.bytes = rec.netflow.bytes;
    
            flows_rec.dst_country = CountryByIp(rec.dst_ip);
            flows_rec.src_country = CountryByIp(rec.src_ip);
    
            q_flows.push(flows_rec);
            break;
        
        default:
            break;
    }
}

string Nids::CountryByIp(string ip) {
    
    GeoIPRecord *gir;
    char **ret;
    
    if (maxmind_state != 0) {
    
        gir = GeoIP_record_by_name(gi, (const char *) ip.c_str());

        if (gir != NULL) {
            country_code = string(gir->country_code);
            GeoIPRecord_delete(gir);
            return country_code;
        }
    }

    return "";
}


