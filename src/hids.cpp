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
    
    string message;
    
    jsonPayload.assign(reply->str, GetBufferSize(reply->str));
    
    try {
    
        ss1 << redis_payload;
        bpt::read_json(ss1, pt1);
    
        message = pt1.get<string>("message","");
        
        if ((message.compare("") == 0)) {
            ResetStreams();
            return 0;
        }
    
        ss << message;
        bpt::read_json(ss, pt);
    
    } catch (const std::exception & ex) {
        ResetStreams();
        SysLog((char*) ex.what());
        return 0;
    } 
    
    string loc = pt.get<string>("location","");
    
    
    if (loc.compare("Wazuh-VULS") == 0 ) {
        
        report = "{ \"type\": \"report_vuls\", \"data\": ";
        
        report += "{ \"ref_id\": \"";
        report += fs.filter.ref_id;
            
        report += "\", \"agent_name\": \"";
        report += pt.get<string>("agent.name","");
        
        report += "\", \"event_id\": \"";
        report += std::to_string(pt.get<int>("rule.id",0));
        
        report += "\", \"severity\": ";
        
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
        
        report += severity;
        
        report +=  ", \"event_time\":\"";
        report += pt.get<string>("timestamp","");
        
        report += "\", \"description\": \"";
        report += pt.get<string>("rule.description","");
        
        report += "\", \"affected_packages\": \"";
        report += pt.get<string>("data.vuls.affected_packages","");
        
        report += "\", \"assurance\": \"";
        report += pt.get<string>("data.vuls.assurance","");
        
        report += "\", \"kernel_version\": \"";
        report += pt.get<string>("data.vuls.kernel_version","");
        
        report += "\", \"last_modified\": \"";
        report += pt.get<string>("data.vuls.last_modified","");
        
        report += "\", \"link\": \"";
        report += pt.get<string>("data.vuls.link","");
        
        report += "\", \"os_version\": \"";
        report += pt.get<string>("data.vuls.os_version","");
        
        report += "\", \"score\": \"";
        report += pt.get<string>("data.vuls.score","");
        
        report += "\", \"scanned_cve\": \"";
        report += pt.get<string>("data.vuls.scanned_cve","");
        
        report += "\", \"source\": \"";
        report += pt.get<string>("data.vuls.source","");
        
        report += "\", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } }";
        
       
        q_compliance.push(report);
        
        report.clear();
        ResetStreams();
        return 0;
    }
    
    string mon_con = pt.get<string>("data.audit.key","");
    
    if (mon_con.compare("linux-connects") == 0) {
        
        report = "{\"version\": \"1.1\",\"host\":\"";
        report += node_id;
        report += "\",\"short_message\":\"process-linux\"";
        report += ",\"full_message\":\"Network activity of linux process from Auditd\"";
	report += ",\"level\":";
        report += std::to_string(7);
        report += ",\"_type\":\"auditd\"";
        report += ",\"_source\":\"ossec\"";
        
	report += ",\"_agentname\":\"";
        report += pt.get<string>("agent.name","");
        
        report +=  "\", \"_event_time\":\"";
        report += pt.get<string>("timestamp","");
        
        report += "\",\"_collected_time\":\"";
        report += GetGraylogFormat();
		
	report += "\",\"_description\":\"";
        report += pt.get<string>("rule.description","");
        
	report += "\",\"_full_log\":\"";
        string full_log = pt.get<string>("full_log","");
        ReplaceAll(full_log, "\"", "");
        report += full_log;
        
        report += "\",\"_pid\":\"";
        report += pt.get<string>("data.audit.pid","");
        
        report += "\",\"_command\":\"";
        report +=  pt.get<string>("data.audit.command","");
        
        report += "\",\"_exe\":\"";
        report +=  pt.get<string>("data.audit.exe","");
        
        report += "\"}";
        
        // SysLog((char*) report.str().c_str());
    
        q_logs_hids.push(report);
        
        report.clear();
        ResetStreams();
        return 0;
    }
    
    string desc = pt.get<string>("rule.description","");
    
    if (loc.compare("WinEvtLog") == 0 && desc.compare("Sysmon - Event 3") == 0) {
        
        report = "{\"version\": \"1.1\",\"host\":\"";
        report += node_id;
        report += "\",\"short_message\":\"process-win\"";
        report += ",\"full_message\":\"Network activity of windows process from Sysmon\"";
        report += ",\"level\":";
        report += std::to_string(7);
		
	report += ",\"_type\":\"sysmon\"";
        report += ",\"_source\":\"hids\"";
        
	report += ",\"_agentname\":\"";
        report += pt.get<string>("agent.name","");
        
        report += "\", \"_event_time\":\"";
        report += pt.get<string>("timestamp","");
        
        report += "\",\"_collected_time\":\"";
        report += GetGraylogFormat();
		
	report += "\",\"_description\":\"";
        report += desc;
        
        report += "\",\"_id\":\"";
        report += pt.get<string>("data.id","");
        
        report += "\",\"_protocol\":\"";
        report += pt.get<string>("data.protocol","");
        
        report += "\",\"_srcip\":\"";
        report += pt.get<string>("data.srcip","");
        
        report += "\",\"_srcport\":\"";
        report += pt.get<string>("data.srcport","");
        
        report += "\",\"_srcuser\":\"";
        string srcuser = pt.get<string>("data.srcuser","");
        ReplaceAll(srcuser, "\\", "\\\\\\\\");
        report += srcuser;
        
        report += "\",\"_dstip\":\"";
        report += pt.get<string>("data.dstip","");
        
        report += "\",\"_dstport\":\"";
        report += pt.get<string>("data.dstport","");
        
        report += "\",\"_processGuid\":\"";
        report += pt.get<string>("data.sysmon.processGuid","");
        
        report += "\",\"_processId\":\"";
        report += pt.get<string>("data.sysmon.processId","");
        
        report += "\",\"_image\":\"";
        string image = pt.get<string>("data.sysmon.image","");
        ReplaceAll(image, "\\", "\\\\\\\\");
        report += image;
        
        report += "\",\"_initiated\":\"";
        report += pt.get<string>("data.sysmon.initiated","");
        
        report += "\",\"_sourceIsIpv6\":\"";
        report += pt.get<string>("data.sysmon.sourceIsIpv6","");
        
        report += "\",\"_sourceHostname\":\"";
        report += pt.get<string>("data.sysmon.sourceHostname","");
        
        report += "\",\"_destinationIsIpv6\":\"";
        report += pt.get<string>("data.sysmon.destinationIsIpv6","");
        
        report += "\",\"_destinationHostname\":\"";
        report += pt.get<string>("data.sysmon.destinationHostname","");
        
        report += "\"}";
    
        q_logs_hids.push(report);
        
        report.clear();
        ResetStreams();
        return 0;
    }
    
    rec.rule.id = pt.get<int>("rule.id",0);
    
    rec.rule.level = pt.get<int>("rule.level",0);
    
    rec.rule.desc = desc;
    ReplaceAll(rec.rule.desc, "\"", "");
    ReplaceAll(rec.rule.desc, "\\", "\\\\\\\\");
    
    rec.rule.info = pt.get<string>("rule.info","");
    
    try {
    
        groups_cats = pt.get_child("rule.groups");
        
        BOOST_FOREACH(bpt::ptree::value_type &v, groups_cats) {
            assert(v.first.empty()); // array elements have no names
            rec.rule.list_cats.push_back(v.second.data());
        }
    } catch (bpt::ptree_bad_path& e) {}
    
    try {
    
        pcidss_cats = pt.get_child("rule.pci_dss");
        BOOST_FOREACH(bpt::ptree::value_type &v, pcidss_cats) {
            assert(v.first.empty()); // array elements have no names
            string pcidss = "pci_dss_" + v.second.data();
            rec.rule.list_cats.push_back(pcidss);
        }  
    
    } catch (bpt::ptree_bad_path& e) {}
    
    rec.hostname = pt.get<string>("agent.name","");
    
    rec.datetime = pt.get<string>("timestamp","");
    
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
        
    ResetStreams();
    return 1;
}

void Hids::CreateLog() {
    
    report = "{\"version\": \"1.1\",\"host\":\"";
    report += node_id;
    report += "\",\"short_message\":\"event-hids\"";
    report += ",\"full_message\":\"IDS/FIM event from OSSEC/Wazuh\"";
    report += ",\"level\":";
    report += std::to_string(7);
    if (rec.file.filename.compare("") != 0) {
        report += ",\"_type\":\"fim\"";
    } else {
        report += ",\"_type\":\"ids\"";
    }
    report += ",\"_source\":\"ossec\"";
        
    report += ",\"_agentname\":\"";
    report += rec.hostname;
    
    report += "\", \"_event_time\":\"";
    report += rec.datetime;
    
    report += "\",\"_collected_time\":\"";
    report += GetGraylogFormat();
		
    report += "\",\"_description\":\"";
    report += rec.rule.desc;
    
    report += "\",\"_ossec-level\":";
    report += std::to_string(rec.rule.level);
    
    report += ",\"_sidid\":";
    report += std::to_string(rec.rule.id);
	
    report += ",\"_group_name\":\"";
    
    int j = 0;
    for (string i : rec.rule.list_cats) {
        if (j != 0 && j < rec.rule.list_cats.size()) report += ", ";
        report += i;
            
        j++;    
    }
    
    report += "\",\"_info\":\"";
    report += rec.rule.info;
    report += "\",\"_location\":\"";
    report += rec.location;
    report += "\",\"_srcip\":\"";
    report += rec.srcip;
    report += "\",\"_dstip\":\"";
    report += rec.dstip;
    if (rec.file.filename.compare("") != 0) {
        report += "\",\"_filename\":\"";
        report += rec.file.filename;
        report += "\",\"_md5_before\":\"";
        report += rec.file.md5_before;
        report += "\",\"_md5_after\":\"";
        report += rec.file.md5_after;
        report += "\",\"_sha1_before\":\"";
        report += rec.file.sha1_before;
        report += "\",\"_sha1_after\":\"";
        report += rec.file.sha1_after;
        report += "\",\"_owner_before\":\"";
        report += rec.file.owner_before;
        report += "\",\"_owner_after\":\"";
        report += rec.file.owner_after;
        report += "\",\"_gowner_before\":\"";
        report += rec.file.gowner_before;
        report += "\",\"_gowner_after\":\"";
        report += rec.file.gowner_after;
    }
    report += "\"}";
    
    //SysLog((char*) report.str().c_str());
    
    q_logs_hids.push(report);
    
    report.clear();
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
        
        sk.alert.info = "\"artifacts\": [";
        sk.alert.info += "{ \"dataType\": \"md5\",\"data\":\"";
        sk.alert.info += rec.file.md5_before;
        sk.alert.info += "\",\"message\":\"message digest before\" }, ";
            
        sk.alert.info += "{ \"dataType\": \"md5\",\"data\":\"";
        sk.alert.info += rec.file.md5_after;
        sk.alert.info += "\",\"message\":\"Message digest after\" }, ";
        
        sk.alert.info += "{ \"dataType\": \"sha1\",\"data\":\"";
        sk.alert.info += rec.file.sha1_before;
        sk.alert.info += "\",\"message\":\"Secure hash before\" }, ";
            
        sk.alert.info += "{ \"dataType\": \"sha1\",\"data\":\"";
        sk.alert.info += rec.file.sha1_after;
        sk.alert.info += "\",\"message\":\"Secure hash after\" } ";
            
        sk.alert.info += "]";
            
    }
    
    sk.alert.event_json.assign(reply->str, GetBufferSize(reply->str));
        
    sk.SendAlert();
        
}

    
