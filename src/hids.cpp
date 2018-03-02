/* 
 * File:   hids.cpp
 * Author: Oleg Zharkov
 *
 * Created on May 26, 2014, 10:43 AM
 */
 
#include "hids.h"

#include <boost/algorithm/string.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

namespace bpt = boost::property_tree;

boost::lockfree::spsc_queue<string> q_logs_hids{LOG_QUEUE_SIZE};
boost::lockfree::spsc_queue<string> q_compliance{LOG_QUEUE_SIZE};

int Hids::Go(void) {
    
    BwList* bwl;
    int res = 0;
    
    ClearRecords();
        
    if (status) {
        
        // read data 
        reply = (redisReply *) redisCommand( c, (const char *) redis_key.c_str());
        
        if (!reply) {
            SysLog("failed reading ossec events from redis");
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
        
        IncrementEventsCounter();
        
        boost::shared_lock<boost::shared_mutex> lock(fs.filters_update);
        
        if (res != 0 ) {      
            if (fs.filter.hids.log ) CreateLog();
            
            if (alerts_counter <= sk.alerts_threshold) {
            
                bwl = CheckBwList();
            
                int severity = PushRecord(bwl);
                
                if (bwl != NULL) {
                    if (!bwl->action.compare("supress")) SendAlert(severity, bwl);
                } else {
                    if (fs.filter.hids.severity <= severity) {
                        SendAlert(severity, NULL);
                    }
                } 
                
                if (sk.alerts_threshold != 0) {
            
                    if (alerts_counter < sk.alerts_threshold) alerts_counter++;
                    else {
                        sendAlertMultiple(1);
                        alerts_counter++;
                    }
                }
            }
        } 
        freeReplyObject(reply);
    } 
    else {
        usleep(GetGosleepTimer()*60);
    }
            
    return 1;
}

BwList* Hids::CheckBwList() {
    
    if (fs.filter.hids.bwl.size() != 0) {
        
        std::vector<BwList*>::iterator i, end;
        
        for (i = fs.filter.hids.bwl.begin(), end = fs.filter.hids.bwl.end(); i != end; ++i) {
            
            int event_id = (*i)->event;
            if (event_id == rec.rule.id) {
                
                string agent = (*i)->host;
                
                if (agent.compare("none") || agent.compare(rec.hostname) == 0) {
                
                    return (*i);
                }
            }
        }
    }
    
    return NULL;
}


int Hids::ParsJson(char* redis_payload) {
    
    bpt::ptree pt, pt1;
    string message;
    
    jsonPayload.assign(reply->str, GetBufferSize(reply->str));
    
    try {
    
        stringstream ss1(redis_payload);
        bpt::read_json(ss1, pt1);
    
        message = pt1.get<string>("message","");
        
        if ((message.compare("") == 0)) {
            pt1.clear();
            return 0;
        }
    
        stringstream ss(message);
        bpt::read_json(ss, pt);
    
    } catch (const std::exception & ex) {
        pt.clear();
        pt1.clear();
        SysLog((char*) ex.what());
        return 0;
    } 
    
    string loc = pt.get<string>("location","");
    
    if (loc.compare("Wazuh-VULS") == 0 ) {
        
        stringstream report;
        
        report << "{ \"type\": \"report_vuls\", \"data\": ";
        
        report << "{ \"ref_id\": \"";
        report << fs.filter.ref_id;
            
        report << "\", \"agent_name\": \"";
        report << pt.get<string>("agent.name","");
        
        report << "\", \"event_id\": \"";
        report << pt.get<int>("rule.id",0);
        
        report << "\", \"severity\": ";
        
        int level = pt.get<int>("rule.level",0);
        string severity;
    
        if (level < 2) {
            severity = "0";
        } else {
            if (level < 4) {
                severity = "1";
            } else {
                if (level < 10) {
                    severity = "2";
                } else {
                    severity = "3";
                }
            }
        }  
        
        report << severity;
        
        report << ", \"description\": \"";
        report << pt.get<string>("rule.description","");
        
        report << "\", \"affected_packages\": \"";
        report << pt.get<string>("data.vuls.affected_packages","");
        
        report << "\", \"assurance\": \"";
        report << pt.get<string>("data.vuls.assurance","");
        
        report << "\", \"kernel_version\": \"";
        report << pt.get<string>("data.vuls.kernel_version","");
        
        report << "\", \"last_modified\": \"";
        report << pt.get<string>("data.vuls.last_modified","");
        
        report << "\", \"link\": \"";
        report << pt.get<string>("data.vuls.link","");
        
        report << "\", \"os_version\": \"";
        report << pt.get<string>("data.vuls.os_version","");
        
        report << "\", \"score\": \"";
        report << pt.get<string>("data.vuls.score","");
        
        report << "\", \"scanned_cve\": \"";
        report << pt.get<string>("data.vuls.scanned_cve","");
        
        report << "\", \"source\": \"";
        report << pt.get<string>("data.vuls.source","");
        
        report << "\", \"time_of_survey\": \"";
        report << GetNodeTime();
        report << "\" } }";
        
       
        q_compliance.push(report.str());
        
        pt.clear();
        pt1.clear();
        return 0;
    }
    
    string mon_con = pt.get<string>("data.audit.key","");
    
    if (mon_con.compare("monitor-connections") == 0) {
        
        stringstream report;
        
        report << "{\"version\": \"1.1\",\"host\":\"";
        report << node_id;
        
        report << "\",\"short_message\":\"auditd\"";
        report << ",\"full_message\":\"Network activity of process from Auditd\"";
        report << ",\"level\":";
        report << 1;
        report << ",\"_event_type\":\"monitor-connections\"";
        report << ",\"_time_of_event\":\"";
        report << GetGraylogFormat();
    
        report << "\",\"_description\":\"";
        report << pt.get<string>("rule.description","");
                
        report << "\",\"_agentname\":\"";
        report << pt.get<string>("agent.name","");
        
        report << "\",\"_full_log\":\"";
        string full_log = pt.get<string>("full_log","");
        ReplaceAll(full_log, "\"", "");
        report << full_log;
        
        report << "\",\"_pid\":\"";
        report << pt.get<string>("data.audit.pid","");
        
        report << "\",\"_command\":\"";
        report <<  pt.get<string>("data.audit.command","");
        
        report << "\",\"_exe\":\"";
        report <<  pt.get<string>("data.audit.exe","");
        
        report << "\"}";
    
        q_logs_hids.push(report.str());
        
        pt.clear();
        pt1.clear();
        return 0;
    }
    
    string desc = pt.get<string>("rule.description","");
    
    
    if (loc.compare("WinEvtLog") == 0 && desc.compare("Sysmon - Event 3") == 0) {
        
        stringstream report;
        
        report << "{\"version\": \"1.1\",\"host\":\"";
        report << node_id;
        
        report << "\",\"short_message\":\"sysmon\"";
        report << ",\"full_message\":\"Network activity of process from SysMon\"";
        report << ",\"level\":";
        report << 1;
        report << ",\"_event_type\":\"monitor-connections\"";
        report << ",\"_time_of_event\":\"";
        report << GetGraylogFormat();
    
        report << "\",\"_description\":\"";
        report << desc;
        
        report << "\",\"_agentname\":\"";
        report << pt.get<string>("agent.name","");
        
        report << "\",\"_id\":\"";
        report << pt.get<string>("data.id","");
        
        report << "\",\"_protocol\":\"";
        report << pt.get<string>("data.protocol","");
        
        report << "\",\"_srcip\":\"";
        report << pt.get<string>("data.srcip","");
        
        report << "\",\"_srcport\":\"";
        report << pt.get<string>("data.srcport","");
        
        report << "\",\"_srcuser\":\"";
        string srcuser = pt.get<string>("data.srcuser","");
        ReplaceAll(srcuser, "\\", "\\\\\\\\");
        report << srcuser;
        
        report << "\",\"_dstip\":\"";
        report << pt.get<string>("data.dstip","");
        
        report << "\",\"_dstport\":\"";
        report << pt.get<string>("data.dstport","");
        
        report << "\",\"_processGuid\":\"";
        report << pt.get<string>("data.sysmon.processGuid","");
        
        report << "\",\"_processId\":\"";
        report << pt.get<string>("data.sysmon.processId","");
        
        report << "\",\"_image\":\"";
        string image = pt.get<string>("data.sysmon.image","");
        ReplaceAll(image, "\\", "\\\\\\\\");
        report << image;
        
        report << "\",\"_initiated\":\"";
        report << pt.get<string>("data.sysmon.initiated","");
        
        report << "\",\"_sourceIsIpv6\":\"";
        report << pt.get<string>("data.sysmon.sourceIsIpv6","");
        
        report << "\",\"_sourceHostname\":\"";
        report << pt.get<string>("data.sysmon.sourceHostname","");
        
        report << "\",\"_destinationIsIpv6\":\"";
        report << pt.get<string>("data.sysmon.destinationIsIpv6","");
        
        report << "\",\"_destinationHostname\":\"";
        report << pt.get<string>("data.sysmon.destinationHostname","");
        
        report << "\"}";
    
        q_logs_hids.push(report.str());
        
        pt.clear();
        pt1.clear();
        return 0;
    }
    
    rec.rule.id = pt.get<int>("rule.id",0);
    
    rec.rule.level = pt.get<int>("rule.level",0);
    
    rec.rule.desc = desc;
    ReplaceAll(rec.rule.desc, "\"", "");
    ReplaceAll(rec.rule.desc, "\\", "\\\\\\\\");
    
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
    
    rec.hostname = pt.get<string>("agent.name","");
    
    rec.location = loc;
    ReplaceAll(rec.location, "\"", "");
    ReplaceAll(rec.location, "\\", "\\\\\\\\");
        
    rec.srcip = pt.get<string>("data.srcip","");
        
    rec.dstip = pt.get<string>("data.dstip","");
        
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
    pt1.clear();
    return 1;
}

void Hids::CreateLog() {
    
    stringstream ss;
    
    ss << "{\"version\": \"1.1\",\"host\":\"";
    ss << node_id;
    if (rec.file.filename.compare("") != 0) {
        ss << "\",\"short_message\":\"fim\"";
        ss << ",\"full_message\":\"Alert from OSSEC FIM\"";
    } else {
        ss << "\",\"short_message\":\"hids\"";
        ss << ",\"full_message\":\"Alert from OSSEC IDS\"";
    }
    ss << ",\"level\":";
    
    int level;
    
    if (rec.rule.level < 2) {
        level = 0;
    } else {
        if (rec.rule.level < 4) {
            level = 1;
        } else {
            if (rec.rule.level < 10) {
                level = 2;
            } else {
                level = 3;
            }
        }
    }    
    ss << level;
    ss << ",\"_event_type\":\"ossec\"";
    ss << ",\"_ossec-level\":";
    ss << rec.rule.level;
    ss << ",\"_time_of_event\":\"";
    ss << GetGraylogFormat();
    ss << "\",\"_description\":\"";
    ss << rec.rule.desc;
    ss << "\",\"_sidid\":";
    ss << rec.rule.id;
    ss << ",\"_group_name\":\"";
    
    int j = 0;
    for (string i : rec.rule.list_cats) {
        if (j != 0 && j < rec.rule.list_cats.size()) ss << ", ";
        ss << i;
            
        j++;    
    }
    
    ss << "\",\"_info\":\"";
    ss << rec.rule.info;
    ss << "\",\"_agentname\":\"";
    ss << rec.hostname;
    ss << "\",\"_location\":\"";
    ss << rec.location;
    ss << "\",\"_srcip\":\"";
    ss << rec.srcip;
    ss << "\",\"_dstip\":\"";
    ss << rec.dstip;
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
    q_logs_hids.push(ss.str());
    
}



int Hids::PushRecord(BwList* bwl) {
    // create new IDS record
    IdsRecord ids_rec;
            
    ids_rec.ref_id = fs.filter.ref_id;
    
    ids_rec.event = rec.rule.id;
            
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
            
    ids_rec.desc = rec.rule.desc;
                
    ids_rec.src_ip = rec.srcip;
    ids_rec.dst_ip = rec.dstip;
    ids_rec.hostname = rec.hostname;
    ids_rec.action = "none";
                
    if (rec.file.filename.compare("") == 0) {
        ids_rec.location = rec.location;
        ids_rec.ids_type = 2;
    }  else {
        ids_rec.location = rec.file.filename;
        ids_rec.ids_type = 1;
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
            
    q_hids.push(ids_rec);
    
    return ids_rec.severity;
}

void Hids::SendAlert(int s, BwList*  bwl) {
    
    sk.alert.ref_id =  fs.filter.ref_id;
    
    copy(rec.rule.list_cats.begin(),rec.rule.list_cats.end(),back_inserter(sk.alert.list_cats));
        
    sk.alert.severity = s;
    sk.alert.event = rec.rule.id;
    sk.alert.action = "none";
    sk.alert.description = rec.rule.desc;
        
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
        
    sk.alert.source = "OSSEC";
        
    stringstream ss;
                    
    if (rec.file.filename.compare("") == 0) {
            
        sk.alert.type = "HIDS";
            
        sk.alert.hostname = rec.hostname;
        sk.alert.location = rec.location;
        
        sk.alert.info = rec.rule.info;
    }
    else {
            
        sk.alert.type = "FIM";
            
        sk.alert.hostname = rec.hostname;
        
        sk.alert.location = rec.file.filename;
        
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
        
    sk.alert.event_json.assign(reply->str, GetBufferSize(reply->str));
        
    sk.SendAlert();
        
}

    
