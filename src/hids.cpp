/* 
 * File:   hids.cpp
 * Author: Oleg Zharkov
 *
 * Created on May 26, 2014, 10:43 AM
 */
 
#include "hids.h"

namespace bpt = boost::property_tree;


int Hids::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    //Read filter config
    if(!fs.GetFiltersConfig()) return 0;
    
    ConfigYaml* cy = new ConfigYaml( "hids");
    
    cy->addKey("zmq");
        
    cy->ParsConfig();
    
    if (!cy->getParameter("zmq").compare("none")) {
        hids_status = 0;
        SysLog("config file notification: OSSEC interface is disabled");
    }
    else {
        strncpy(url, (char*) cy->getParameter("zmq").c_str(), sizeof(url));
        hids_status = 1;
    }
    
    return 1;
}

int Hids::OpenZmq(void) {
    char t[OS_HEADER_SIZE];
     
    context = zmq_ctx_new();
    subscriber = zmq_socket(context, ZMQ_SUB);
    
    rc = zmq_connect(subscriber, url);

    if (rc != 0) return 0;
    
    sprintf(t, "ossec.alerts"); 
    rc = zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, t, strlen(t));
    
    if (rc != 0) return 0;
    
    return 1;
}
 
int Hids::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (hids_status == 1) {
        if (!OpenZmq()) {
            SysLog("failed to connect to OSSEC server over ZMQ");
            return 0;
        }
    }
        
    return 1;
}

void Hids::Close() {
    
    sk.Close();
    
    if (!rc) {
        zmq_close(subscriber);
        zmq_ctx_destroy(context);
    }
}


int Hids::Go(void) {
    
    BwList* bwl;
    
    ClearRecords();
        
    // read OSSEC data from port
    if (ReceiveEvent()) {
        
        ParsJson();
        
	IncrementEventsCounter();
        
        if (fs.filter.hids.log) {
            
            CreateLogPayload();
            
            if (sk.GetStateCtrl()) q_log.push(logPayload);
            else {
                if (sk.GetStatePersist()) {
                    //string log = "{\"ossec\":" + logPayload + "}";
                    int rsm = Sinks::persist.WriteLog(logPayload);
                    if(rsm == 0) sk.SetStatePersist(0);
                }
            }
        }
        
        if (sk.GetStateCtrl()) {
            
            bwl = CheckBwList();
            
            int severity = PushIdsRecord(bwl);
                
            if (bwl != NULL) {
                if (!bwl->action.compare("supress")) SendAlert(severity, bwl);
            } else {
                if (fs.filter.hids.severity <= severity) SendAlert(severity, NULL);
            } 
        }
    }
        
    return 1;
}

BwList* Hids::CheckBwList() {
    //char log_message 
    if (fs.filter.hids.bwl.size() != 0) {
        
        std::vector<BwList*>::iterator i, end;
        
        for (i = fs.filter.hids.bwl.begin(), end = fs.filter.hids.bwl.end(); i != end; ++i) {
            int event_id = (*i)->event;
            if (event_id == rec.rule.sidid) {
                string ip = (*i)->ip;
                if (ip.compare("all") == 0) return (*i);
                if (ip.compare(rec.srcip) == 0) return (*i);
            }
        }
    }
    
    return NULL;
}

int Hids::ReceiveEvent(void) 
{
    struct zmq_msg_hdr h;
    int ret;
    
    ret = zmq_recv(subscriber, &h, sizeof(h), 0); 
    if (ret == -1) {
        SysLog("failed reading event (phase 1) from ZMQ for OSSEC.");
        return 0;
    }
    ret = zmq_recv(subscriber, payload, OS_PAYLOAD_SIZE, 0); 
    if (ret == -1) {
        SysLog("failed reading event (phase 2) from ZMQ for OSSEC.");
        return 0;
    }
    
    return 1;
}

void Hids::ParsJson() {
    
    stringstream ss(payload);
    bpt::ptree pt;
    bpt::read_json(ss, pt);
    
    // rule
    rec.rule.sidid = pt.get<int>("rule.id",0);
    
    rec.rule.level = pt.get<int>("rule.level",0);
    
    rec.rule.comment = pt.get<string>("rule.description","");
    
    rec.rule.cve = pt.get<string>("rule.cve","");
    
    rec.rule.info = pt.get<string>("rule.info","");
    
    try {
    
        bpt::ptree groups_cats = pt.get_child("rule.groups");
    
        BOOST_FOREACH(bpt::ptree::value_type &v, groups_cats) {
            assert(v.first.empty()); // array elements have no names
            rec.rule.list_cats.push_back(v.second.data());
        }
    } catch (bpt::ptree_bad_path& e) {}
    
    try {
    
        bpt::ptree pcidss_cats = pt.get_child("rule.pci_dss");
        BOOST_FOREACH(bpt::ptree::value_type &v, pcidss_cats) {
            assert(v.first.empty()); // array elements have no names
            string pcidss = "pci_dss_" + v.second.data();
            rec.rule.list_cats.push_back(pcidss);
        }  
    
    } catch (bpt::ptree_bad_path& e) {}
    
    // root
    rec.action = pt.get<string>("action","");
        
    rec.protocol = pt.get<string>("protocol","");
        
    rec.hostname = pt.get<string>("hostname","");
        
    rec.location = pt.get<string>("location","");
    
    rec.srcip = pt.get<string>("srcip","");
        
    string srcport = pt.get<string>("srcport","0");
    rec.srcport = stoi( srcport );
    
    rec.srcuser = pt.get<string>("srcuser","");
    
    rec.dstip = pt.get<string>("dstip","");
        
    string dstport = pt.get<string>("dstport","0");
    rec.dstport = stoi( dstport );
    
    rec.dstuser = pt.get<string>("dstuser","");
    
    // file
    
    rec.file.filename = pt.get<string>("syscheck.path","");
    
    rec.file.md5_before = pt.get<string>("syscheck.md5_before","");
    
    rec.file.md5_after = pt.get<string>("syscheck.md5_after","");
    
    rec.file.sha1_before = pt.get<string>("syscheck.sha1_before","");
    
    rec.file.sha1_after = pt.get<string>("syscheck.sha1_after","");
    
    rec.file.owner_before = pt.get<string>("syscheck.owner_before","");
        
    rec.file.owner_after = pt.get<string>("syscheck.owner_after","");
           
    rec.file.gowner_before = pt.get<string>("syscheck.gowner_before","");
    
    rec.file.gowner_after = pt.get<string>("syscheck.gowner_after","");
    
    pt.clear();
}

void Hids::CreateLogPayload() {
    stringstream ss;
    
    ss << "{\"version\": \"1.1\",\"host\":\"";
    ss << node_id;
    if (rec.file.filename.compare("") != 0) {
        ss << "\",\"short_message\":\"fim\"";
        ss << ",\"full_message\":\"Alert from OSSEC FIM\"";
    } else {
        ss << "\",\"short_message\":\"hids\"";
        ss << ",\"full_message\":\"Alert from OSSEC HIDS\"";
    }
    ss << ",\"level\":";
    
    int level;
    
    if (rec.rule.level < 2) {
        level = 4;
    } else {
        if (rec.rule.level < 4) {
            level = 3;
        } else {
            if (rec.rule.level < 10) {
                level = 2;
            } else {
                level = 1;
            }
        }
    }    
    ss << level;
    ss << ",\"event_type\":\"ossec\"";
    ss << ",\"ossec-level\":";
    ss << rec.rule.level;
    ss << ",\"_time_of_event\":\"";
    ss << GetGraylogFormat();
    ss << "\",\"_comment\":\"";
    ss << rec.rule.comment;
    ss << "\",\"_sidid\":";
    ss << rec.rule.sidid;
    ss << ",\"_group_name\":\"";
    
    int j = 0;
    for (string i : rec.rule.list_cats) {
        if (j != 0 && j < rec.rule.list_cats.size()) ss << ", ";
        ss << i;
            
        j++;    
    }
    
    ss << "\",\"_cve\":\"";
    ss << rec.rule.cve;
    ss << "\",\"_info\":\"";
    ss << rec.rule.info;
    ss << "\",\"_hostname\":\"";
    ss << rec.hostname;
    ss << "\",\"_location\":\"";
    ss << rec.location;
    ss << "\",\"_srcip\":\"";
    ss << rec.srcip;
    ss << "\",\"_dstip\":\"";
    ss << rec.dstip;
    ss << "\",\"_srcport\":";
    ss << rec.srcport;
    ss << ",\"_dstport\":";
    ss << rec.dstport;
    ss << ",\"_action\":\"";
    ss << rec.action;
    ss << "\",\"_srcuser\":\"";
    ss << rec.srcuser;
    ss << "\",\"_dstuser\":\"";
    ss << rec.dstuser;
    if (rec.file.filename.compare("") != 0) {
        ss << "\",\"_filename\":\"";
        ss << rec.file.filename;
        ss << "\",\"_md5_before\":\"";
        ss << rec.file.md5_before;
        ss << "\",\"_md5_after\":\"";
        ss << rec.file.md5_after;
        ss << "\",\"_sha1_before\":\"";
        ss << rec.file.sha1_before;
        ss << "\",\"_sha1_after\":\"";
        ss << rec.file.sha1_after;
        ss << "\",\"_owner_before\":\"";
        ss << rec.file.owner_before;
        ss << "\",\"_owner_after\":\"";
        ss << rec.file.owner_after;
        ss << "\",\"_gowner_before\":\"";
        ss << rec.file.gowner_before;
        ss << "\",\"_gowner_after\":\"";
        ss << rec.file.gowner_after;
    }
    ss << "\"}";
    
    logPayload = ss.str();
}



int Hids::PushIdsRecord(BwList* bwl) {
    // create new IDS record
    IdsRecord ids_rec;
            
    ids_rec.ref_id = fs.filter.ref_id;
    
    ids_rec.event = rec.rule.sidid;
            
    copy(rec.rule.list_cats.begin(),rec.rule.list_cats.end(),back_inserter(ids_rec.list_cats));
    
    if (rec.rule.level < 2) {
        ids_rec.severity = 0;
    } else {
        if (rec.rule.level < 4) {
            ids_rec.severity = 1;
        } else {
            if (rec.rule.level < 10) {
                ids_rec.severity = 2;
            } else {
                ids_rec.severity = 3;
            }
        }
    }    
            
    ids_rec.action = rec.action;
    ids_rec.desc = rec.rule.comment;
                
    ids_rec.src_ip = rec.srcip;
    ids_rec.dst_ip = rec.dstip;
    ids_rec.hostname = rec.hostname;
            
    if (rec.file.filename.compare("") == 0) {
        ids_rec.location = rec.location;
        ids_rec.ids_type = 2;
    }  else {
        ids_rec.location = rec.file.filename;
        ids_rec.ids_type = 3;
    }
        
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

void Hids::SendAlert(int s, BwList*  bwl) {
        
    if (sk.GetStateCtrl()) {
    
        sk.alert.ref_id =  fs.filter.ref_id;
    
        copy(rec.rule.list_cats.begin(),rec.rule.list_cats.end(),back_inserter(sk.alert.list_cats));
        
        sk.alert.severity = s;
        sk.alert.event = rec.rule.sidid;
        sk.alert.action = rec.action;
        sk.alert.description = rec.rule.comment;
        
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
        
        sk.alert.srcip = rec.srcip;
        sk.alert.dstip = rec.dstip;
        
        sk.alert.type = "OSSEC";
        
        stringstream ss;
                    
        if (rec.file.filename.compare("") == 0) {
            
            sk.alert.source = "HIDS";
            
            sk.alert.hostname = rec.hostname;
        
            sk.alert.location = rec.location;
        
            // CVE Info srcfqdn dstfqdn srcuser dstuser
            sk.alert.info = rec.rule.info;
        }
        else {
            
            sk.alert.source = "FIM";
            
            sk.alert.hostname = rec.hostname;
        
            sk.alert.location = rec.file.filename;
        
            // md5_before md5_after sha1_before sha1_after owner_before owner_after gowner_before gowner_after    
            
            ss << "\"artifacts\": [";
            ss << "{ \"dataType\": \"md5\",\"data\":\"";
            ss << rec.file.md5_before;
            ss << "\",\"message\":\"message digest before\" }, ";
            
            ss << "{ \"dataType\": \"md5\",\"data\":\"";
            ss << rec.file.md5_after;
            ss << "\",\"message\":\"Message digest after\" }, ";
        
            ss << "{ \"dataType\": \"sha1\",\"data\":\"";
            ss << rec.file.sha1_before;
            ss << "\",\"message\":\"Secure hash before\" }, ";
            
            ss << "{ \"dataType\": \"sha1\",\"data\":\"";
            ss << rec.file.sha1_after;
            ss << "\",\"message\":\"Secure hash after\" } ";
            
            ss << "]";
            
            sk.alert.info = ss.str();
        }
        
        sk.alert.event_json.assign(payload, GetBufferSize(payload));
        
        sk.SendAlert();
    }
}

    
