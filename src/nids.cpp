/* 
 * File:   nids.cpp
 * Author: Oleg Zharkov
 *
 * Created on May 26, 2014, 10:43 AM
 */

#include "nids.h"


namespace bpt = boost::property_tree;


char Nids::host[OS_HEADER_SIZE];
long Nids::port;
char Nids::maxmind_path[OS_BUFFER_SIZE];

int Nids::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    //Read filter config
    if(!fs.GetFiltersConfig()) return 0;
    
    ConfigYaml* cy = new ConfigYaml( "nids");
    
    cy->addKey("redis");
    cy->addKey("port");
        
    cy->ParsConfig();
    
    strncpy(host, (char*) cy->getParameter("redis").c_str(), sizeof(host));
        
    if (!strcmp (host, "none")) { 
            nids_status = 0;
            SysLog("config file notification: suricata redis interface is disabled - redis param error");
            return 1;
    }
    else nids_status = 1;
    
    port = stoi(cy->getParameter("port"));
        
    if (port == 0) { 
        nids_status = 0;
        SysLog("config file notification: suricata redis interface is disabled - port param error");
    }
        
    cy = new ConfigYaml( "collector");
    
    cy->addKey("geodb");
    
    cy->ParsConfig();
    
    strncpy(maxmind_path, (char*) cy->getParameter("geodb").c_str(), sizeof(maxmind_path));

    return 1;
}

   
    
int Nids::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (nids_status == 1) {
        c = redisConnect(host, port);
    
        if (c != NULL && c->err) {
            // handle error
            sprintf(level, "failed open redis server: %s\n", c->errstr);
            SysLog(level);
            return 0;
        }
    }
    
    if (!strcmp (maxmind_path, "none")) maxmind_state = 0;
    else {
        gi = GeoIP_open(maxmind_path, GEOIP_INDEX_CACHE);

        if (gi == NULL) {
            SysLog("error opening maxmind database\n");
            maxmind_state = 0;
        }
        else maxmind_state = 1;
    }
    
    return 1;
    
}


void Nids::Close() {
    
    sk.Close();
    
    if (nids_status == 1) redisFree(c);
    
    if (maxmind_state != 0) GeoIP_delete(gi);
}


int Nids::Go(void) {
    
    BwList* bwl;
    int severity;
    int res = 0;
    
    ClearRecords();
    
    if (nids_status) {
        
        // read Suricata data 
        reply = (redisReply *) redisCommand( c, (const char *) "rpop suricata");
        
        if (!reply) {
            SysLog("failed reading suricata events from redis");
            freeReplyObject(reply);
            return 1;
        }
        
        if (reply->type == REDIS_REPLY_STRING) {
            res = ParsJson(reply->str);
            
        } else {
            freeReplyObject(reply);
            usleep(GetGosleepTimer());
            return 1;
        }
        
        if (fs.filter.nids.log) {
                    
            CreateLogPayload(res);
                    
            if (sk.GetStateCtrl()) q_log.push(logPayload);
            else {
                if (sk.GetStatePersist()) {
                    //string log = "{\"suricata\":" + logPayload + "}";
                    int rsm = Sinks::persist.WriteLog(logPayload);
                    if(rsm == 0) sk.SetStatePersist(0);
                }
            }
        
        }
        
        if (sk.GetStateCtrl()) {
        
            if (res == 1) {
            
                bwl = CheckBwList();
                
                severity = PushIdsRecord(bwl);
                
                if (bwl != NULL) {
                    if (!bwl->action.compare("supress")) SendAlert(severity, bwl);
                } else {
                    if (fs.filter.nids.severity <= severity) SendAlert(severity, NULL);
                }
            } else {
                if (res == 4) {
                    if (CheckTraffic()) PushFlowRecord();
                }
            }
        }
        
        freeReplyObject(reply);
    }
    else usleep(GetGosleepTimer()*120);
    
    return 1;
}

bool Nids::CheckTraffic() {
    
    if (fs.filter.home_nets.size() != 0) {
        
        std::vector<Network*>::iterator i, end;
        
        for (i = fs.filter.home_nets.begin(), end = fs.filter.home_nets.end(); i != end; ++i) {
            
            string net = (*i)->network;
            string mask = (*i)->netmask;
            
            bool res = IsIPInRange(rec.dst_ip, net, mask);
            if(res) return true;
            
            res = IsIPInRange(rec.src_ip, net, mask);
            if(res) return true;
        }
    }
    
    return false;
}

bool Nids::CheckHomeNetwork() {
    
    if (fs.filter.home_nets.size() != 0) {
        
        std::vector<Network*>::iterator i, end;
        
        for (i = fs.filter.home_nets.begin(), end = fs.filter.home_nets.end(); i != end; ++i) {
            
            string net = (*i)->network;
            string mask = (*i)->netmask;
            
            bool res = IsIPInRange(rec.dst_ip, net, mask);
            if(res) return true;
            
            res = IsIPInRange(rec.src_ip, net, mask);
            if(res) return true;
        }
    }
    
    return false;
}


BwList* Nids::CheckBwList() {
    if (fs.filter.nids.bwl.size() != 0) {
        
        std::vector<BwList*>::iterator i, end;
        
        for (i = fs.filter.nids.bwl.begin(), end = fs.filter.nids.bwl.end(); i != end; ++i) {
            int event_id = (*i)->event;
            if (event_id == rec.alert.signature_id) {
                string ip = (*i)->ip;
                if (ip.compare("all") == 0) return (*i);
                if (ip.compare(rec.src_ip) == 0) return (*i);
                if (ip.compare(rec.dst_ip) == 0) return (*i);
            }
        }
    }
    
    return NULL;
}


int Nids::ParsJson (char* redis_payload) {
    
    stringstream ss(redis_payload);
    bpt::ptree pt;
    bpt::read_json(ss, pt);
        
    boost::optional< bpt::ptree& > alert = pt.get_child_optional( "alert" );
    
    if (alert) {
        
        IncrementEventsCounter();
        
        rec.time_stamp = pt.get<string>("timestamp","");
        
        rec.flow_id = pt.get<int>("flow_id",0);
        
        rec.in_iface = pt.get<string>("in_iface","");
        
        rec.event_type = pt.get<string>("event_type","");
        
        rec.src_ip = pt.get<string>("src_ip","");
        
        rec.src_port = pt.get<int>("src_port",0);
        
        rec.dst_ip = pt.get<string>("dest_ip","");
        
        rec.dst_port = pt.get<int>("dest_port",0);
        
        rec.protocol = pt.get<string>("proto","");
        
        rec.hostname = pt.get<string>("host","");
        
        rec.payload_printable = pt.get<string>("payload_printable","");
        
        for (int i=0; i < rec.payload_printable.size(); i++)
            if (rec.payload_printable[i] == '\'' || rec.payload_printable[i] == '\"' || rec.payload_printable[i] == '\\') rec.payload_printable[i] = ' ';
        
        rec.stream = pt.get<int>("stream",0); 
        
        // alert record
        rec.alert.action = pt.get<string>("alert.action","");
                
        rec.alert.gid = pt.get<int>("alert.gid",0); 
        rec.alert.signature_id = pt.get<int>("alert.signature_id",0); 
        rec.alert.rev = pt.get<int>("alert.rev",0);
        
        rec.alert.signature = pt.get<string>("alert.signature","");
        
        rec.alert.category = pt.get<std::string>("alert.category","");
        
        rec.alert.severity = pt.get<int>("alert.severity",0);
        
        pt.clear();
        return 1;
    }
    
    boost::optional< bpt::ptree& > dns = pt.get_child_optional( "dns" );
    
    if (dns) {
        
        IncrementNetEventsCounter();
            
        rec.time_stamp = pt.get<string>("timestamp","");
        
        rec.flow_id = pt.get<int>("flow_id",0);
        
        rec.in_iface = pt.get<string>("in_iface","");
        
        rec.event_type = pt.get<string>("event_type","");
        
        rec.src_ip = pt.get<string>("src_ip","");
        
        rec.src_port = pt.get<int>("src_port",0);
        
        rec.dst_ip = pt.get<string>("dest_ip","");
        
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
            
            pt.clear();
            return 2;
        }
        else {
            if (!rec.dns.type.compare("query")) {
                rec.dns.tx_id =  pt.get<int>("dns.tx_id",0); 
                
                pt.clear();
                return 3;
            }
        }
    }
    
    boost::optional< bpt::ptree& > netflow = pt.get_child_optional( "netflow" );
    
    if (netflow) {
        
        IncrementNetEventsCounter();
        
        rec.time_stamp = pt.get<string>("timestamp","");
        
        rec.flow_id = pt.get<long>("flow_id",0);
        
        rec.event_type = pt.get<string>("event_type","");
        
        rec.src_ip = pt.get<string>("src_ip","");
        
        rec.src_port = pt.get<int>("src_port",0);
        
        rec.dst_ip = pt.get<string>("dest_ip","");
        
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
        
        
        pt.clear();
        return 4;
    } 
    
    
    pt.clear();
    return 0;
}

void Nids::CreateLogPayload(int r) {
    stringstream ss;
    
    switch (r) {
            
        case 1: // alert record
    
            ss <<  "{\"version\": \"1.1\",\"host\":\"";
            ss <<  node_id;
            ss << "\",\"short_message\":\"nids\"";
            ss << ",\"full_message\":\"Alert from Suricata NIDS\"";
            ss << ",\"level\":";
            
            int level; 
            
            switch (rec.alert.severity) {
                case 1 :
                    level = 3; 
                    break;
                case 2 :
                    level = 2; 
                    break;
                case 3 :
                    level = 1; 
                    break;
                default :
                    level = 0; 
                    break;
            }
            
            ss <<  level;
            
            ss <<  ",\"_event_type\":\"suricata\"";
            ss << ",\"_severity\":";
            ss << rec.alert.severity;
            ss <<  ",\"_time_of_process\":\"";
            ss <<  GetGraylogFormat();
            ss <<  "\",\"_time_stamp\":\"";
            ss <<  rec.time_stamp;
            ss <<  "\",\"_category\":\"";
            ss <<  rec.alert.category;
            ss <<  "\",\"_signature\":\"";
            ss <<  rec.alert.signature;
            ss <<  "\",\"_flow_id\":";
            ss <<  rec.flow_id;
            ss <<  ",\"_stream\":";
            ss <<  rec.stream;
            ss <<  ",\"_in_iface\":\"";
            ss <<  rec.in_iface;
            ss <<  "\",\"_srcip\":\"";
            ss <<  rec.src_ip;
            ss <<  "\",\"_dstip\":\"";
            ss <<  rec.dst_ip;
            ss <<  "\",\"_srcport\":";
            ss <<  rec.src_port;
            ss <<  ",\"_dstport\":";
            ss <<  rec.dst_port;
            ss <<  ",\"_gid\":";
            ss <<  rec.alert.gid;
            ss <<  ",\"_signature_id\":";
            ss <<  rec.alert.signature_id;
            ss <<  ",\"_rev\":";
            ss <<  rec.alert.rev;
            ss <<  ",\"_action\":\"";
            ss <<  rec.alert.action;
            ss <<  "\",\"_payload_printable\":\"";
            ss <<  rec.payload_printable;
            ss <<  "\"}";
            break;
        case 2: // dns record
        case 3:    
            ss <<  "{\"version\": \"1.1\",\"host\":\"";
            ss <<  node_id;
            ss <<  "\",\"short_message\":\"dns\"";
            ss <<  ",\"full_message\":\"DNS message from Suricata NIDS\"";
            ss <<  ",\"level\":";
            ss <<  0;
            ss <<  ",\"_event_type\":\"suricata\"";
            ss <<  ",\"_time_of_process\":\"";
            ss <<  GetGraylogFormat();
            ss <<  "\",\"_time_stamp\":\"";
            ss <<  rec.time_stamp;
            ss <<  "\",\"_dns_type\":\"";
            ss <<  rec.dns.type;
            ss <<  "\",\"_flow_id\":";
            ss <<  rec.flow_id;
            ss <<  ",\"_in_iface\":\"";
            ss <<  rec.in_iface;
            ss <<  "\",\"_srcip\":\"";
            ss <<  rec.src_ip;
            ss <<  "\",\"_dstip\":\"";
            ss <<  rec.dst_ip;
            ss <<  "\",\"_srcport\":";
            ss <<  rec.src_port;
            ss <<  ",\"_dstport\":";
            ss <<  rec.dst_port;
            ss <<  ",\"_id\":";
            ss <<  rec.dns.id;
            ss <<  ",\"_rrname\":\"";
            ss <<  rec.dns.rrname;
            ss <<  "\",\"_rrtype\":\"";
            ss <<  rec.dns.rrtype;
            if (!rec.dns.type.compare("answer")) {
                ss <<  "\",\"_rcode\":\"";
                ss <<  rec.dns.rcode;
                ss <<  "\",\"_rdata\":\"";
                ss <<  rec.dns.rdata;
                ss <<  "\",\"_ttl\":";
                ss <<  rec.dns.ttl;
            }
            else {
                ss <<  "\",\"_tx_id\":";
                ss <<  rec.dns.tx_id;
            }
            ss <<  "}";
            break;
        case 4: // flow record
            ss << "{\"version\": \"1.1\",\"host\":\"";
            ss << node_id;
            ss << "\",\"short_message\":\"netflow\"";
            ss << ",\"full_message\":\"Netflow message from Suricata NIDS\"";
            ss << ",\"level\":";
            ss << 0;
            ss << ",\"_event_type\":\"suricata\"";
            ss << ",\"_time_of_process\":\"";
            ss << GetGraylogFormat();
            ss <<  "\",\"_time_stamp\":\"";
            ss <<  rec.time_stamp;
            ss << "\",\"_protocol\":\"";
            ss << rec.protocol;
            ss << "\",\"_app_proto\":\"";
            ss << rec.netflow.app_proto;
            ss << "\",\"_srcip\":\"";
            ss << rec.src_ip;
            ss << "\",\"_dstip\":\"";
            ss << rec.dst_ip;
            ss << "\",\"_srcport\":";
            ss << rec.src_port;
            ss << ",\"_dstport\":";
            ss << rec.dst_port;
            ss << ",\"_bytes\":";
            ss << rec.netflow.bytes;
            ss << ",\"_pkts\":";
            ss << rec.netflow.pkts;
            ss << ",\"_age\":";
            ss << rec.netflow.age;
            ss << ",\"_start\":\"";
            ss << rec.netflow.start;
            ss << "\",\"_end\":\"";
            ss << rec.netflow.end;
            ss << "\"}";
            break;
    }
    
    logPayload = ss.str();
}

void Nids::SendAlert(int s, BwList* bwl) {
    
    if (sk.GetStateCtrl()) {
    
        sk.alert.ref_id = fs.filter.ref_id;
    
        sk.alert.source = "NIDS";
        sk.alert.type = "Suricata";
    
        sk.alert.list_cats.push_back(rec.alert.category);
        
        sk.alert.severity = s; 
        sk.alert.event = rec.alert.signature_id;
        sk.alert.action = rec.alert.action;
        sk.alert.description = rec.alert.signature;
        
        sk.alert.status = "processed_new";
            
        if (bwl != NULL) {
            
            if (bwl->action.compare("none") != 0) {
                sk.alert.action = bwl->action;
                sk.alert.status = "modified_new";
            }  
        
            if (bwl->agr.new_event != 0) {
                sk.alert.event = bwl->agr.new_event;
                sk.alert.status = "modified_new";
            }    
            
            if (bwl->agr.new_severity != 0) {
                sk.alert.severity = bwl->agr.new_severity;
                sk.alert.status = "modified_new";
            }   
            
            if (bwl->agr.new_category.compare("") != 0) {
                sk.alert.list_cats.push_back(bwl->agr.new_category);
                sk.alert.status = "modified_new";
            }   
                
            if (bwl->agr.new_description.compare("") != 0) {
                sk.alert.description = bwl->agr.new_description;
                sk.alert.status = "modified_new";
            }   
        }
        
        sk.alert.srcip = rec.src_ip;
        sk.alert.dstip = rec.dst_ip;
        sk.alert.hostname = rec.hostname;
        sk.alert.location = rec.in_iface;
        
        stringstream ss;
        
        ss << "\"artifacts\": [";
    
        ss << " {\"dataType\": \"ip\",\"data\":\"";
        ss << rec.src_ip;
        ss << "\",\"message\":\"src ip\" }, ";
        
        ss << " {\"dataType\": \"ip\",\"data\":\"";
        ss << rec.dst_ip;
        ss << "\",\"message\":\"dst ip\" } ";
        
        ss << "]";
        
        sk.alert.info = ss.str();
        
        sk.alert.event_json.assign(reply->str, GetBufferSize(reply->str));
        
        sk.SendAlert();
    }
}

int Nids::PushIdsRecord(BwList* bwl) {
    // create new ids record
    IdsRecord ids_rec;
                
    ids_rec.ids_type = 1;
                
    ids_rec.ref_id = fs.filter.ref_id;
                
    ids_rec.list_cats.push_back(rec.alert.category);
                
    ids_rec.event = rec.alert.signature_id;
    ids_rec.action = rec.alert.action;
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
    ids_rec.location = rec.in_iface;
                        
    if (bwl != NULL) {
        if (bwl->agr.reproduced > 0) {
            ids_rec.action = bwl->action;
            ids_rec.agr.new_category = bwl->agr.new_category;
            ids_rec.agr.new_description = bwl->agr.new_description;
            ids_rec.agr.new_event = bwl->agr.new_event;
            ids_rec.agr.new_severity = bwl->agr.new_severity;
            ids_rec.agr.in_period = bwl->agr.in_period;
            ids_rec.agr.reproduced = bwl->agr.reproduced;
        }
    }
                                
    q_ids.push(ids_rec);
    
    return ids_rec.severity;
}

void Nids::PushFlowRecord() {
    
    NetflowRecord flow_rec;
    
    flow_rec.ref_id = fs.filter.ref_id;
    
    flow_rec.src_ip = rec.src_ip;
    flow_rec.dst_ip = rec.dst_ip;
    
    flow_rec.proto = rec.protocol;
    flow_rec.app_proto = rec.netflow.app_proto;
    
    flow_rec.bytes = rec.netflow.bytes;
    
    flow_rec.dst_country = CountryByIp(rec.dst_ip);
    flow_rec.src_country = CountryByIp(rec.src_ip);
    
    q_netflow.push(flow_rec);
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


