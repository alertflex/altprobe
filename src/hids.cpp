/* 
 * File:   hids.cpp
 * Author: Oleg Zharkov
 *
 * Created on May 26, 2014, 10:43 AM
 */
#include <stdio.h>
#include <stdlib.h>
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
        
        boost::shared_lock<boost::shared_mutex> lock(fs.filters_update);
        
        IncrementEventsCounter();
        
        if (res != 0 ) {  
            
            if (mr.mod_rec) {
                
                if (fs.filter.waf.log ) CreateWafLog();
            
                if (alerts_counter <= sk.alerts_threshold) {
            
                    bwl = CheckWafBwList();
            
                    int severity = PushWafRecord(bwl);
                
                    if (bwl != NULL) {
                        if (!bwl->action.compare("supress")) SendWafAlert(severity, bwl);
                    } else {
                        if (fs.filter.waf.severity <= severity) {
                            
                            SendWafAlert(severity, NULL);
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
                
            } else {
            
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
                
                if (agent.compare("none") || agent.compare(rec.agent) == 0) {
                
                    return (*i);
                }
            }
        }
    }
    
    return NULL;
}

BwList* Hids::CheckWafBwList() {
    
    if (fs.filter.waf.bwl.size() != 0) {
        
        std::vector<BwList*>::iterator i, end;
        
        for (i = fs.filter.waf.bwl.begin(), end = fs.filter.waf.bwl.end(); i != end; ++i) {
            
            int event_id = (*i)->event;
            if (event_id == rec.rule.id) {
                
                string agent = (*i)->host;
                
                if (agent.compare("none") || agent.compare(rec.agent) == 0) {
                
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
    string full_log = pt.get<string>("full_log","indef");
    ReplaceAll(full_log, "\"", "");
    ReplaceAll(full_log, "\\", "\\\\\\\\");
    
    if (loc.compare("wodle_open-scap") == 0 ) {
    
        report = "{ \"type\": \"compliance\", \"data\": ";
        
        report += "{ \"ref_id\": \"";
        report += fs.filter.ref_id;
            
        report += "\", \"agent\": \"";
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
        
        report += ", \"description\": \"";
        report += pt.get<string>("rule.description","indef");
        
        report += "\", \"benchmark\": \"";
        report += pt.get<string>("data.oscap.scan.benchmark.id","indef");
        
        report += "\", \"profile_id\": \"";
        report += pt.get<string>("data.oscap.scan.profile.id","indef");
        
        report += "\", \"profile_title\": \"";
        report += pt.get<string>("data.oscap.scan.profile.title","indef");
        
        report += "\", \"check_id\": \"";
        report += pt.get<string>("data.oscap.check.id","indef");
        
        report += "\", \"check_title\": \"";
        report += pt.get<string>("data.oscap.check.title","indef");
        
        report += "\", \"check_result\": \"";
        report += pt.get<string>("data.oscap.check.result","indef");
        
        report += "\", \"check_severity\": \"";
        report += pt.get<string>("data.oscap.check.severity","indef");
        
        report += "\", \"check_description\": \"";
        report += pt.get<string>("data.oscap.check.description","indef");
        
        report += "\", \"check_rationale\": \"";
        report += pt.get<string>("data.oscap.check.rationale","indef");
        
        report += "\", \"check_references\": \"";
        report += pt.get<string>("data.oscap.check.references","indef");
        
        report += "\", \"check_identifiers\": \"";
        report += pt.get<string>("data.oscap.check.identifiers","indef");
        
        report += "\", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } }";
        
       
        q_compliance.push(report);
                        
        report.clear();
        ResetStreams();
        return 0;
    }
    
       
    if (loc.compare("vulnerability-detector") == 0 ) {
    
        report = "{ \"type\": \"vulnerability\", \"data\": ";
        
        report += "{ \"ref_id\": \"";
        report += fs.filter.ref_id;
            
        report += "\", \"agent\": \"";
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
        
        report += ", \"description\": \"";
        report += pt.get<string>("rule.description","indef");
        
        report += "\", \"cve\": \"";
        report += pt.get<string>("data.vulnerability.cve","indef");
        
        report += "\", \"cve_state\": \"";
        report += pt.get<string>("data.vulnerability.state","indef");
        
        report += "\", \"cve_severity\": \"";
        report += pt.get<string>("data.vulnerability.severity","indef");
        
        report += "\", \"reference\": \"";
        report += pt.get<string>("data.vulnerability.reference","indef");
        
        report += "\", \"cve_published\": \"";
        report += pt.get<string>("data.vulnerability.published","indef");
        
        report += "\", \"cve_updated\": \"";
        report += pt.get<string>("data.vulnerability.updated","indef");
        
        report += "\", \"package_name\": \"";
        report += pt.get<string>("data.vulnerability.package.name","indef");
        
        report += "\", \"package_version\": \"";
        report += pt.get<string>("data.vulnerability.package.version","indef");
        
        report += "\", \"package_condition\": \"";
        report += pt.get<string>("data.vulnerability.package.condition","indef");
        
        report += "\", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } }";
        
       
        q_compliance.push(report);
        
        report.clear();
        ResetStreams();
        return 0;
    }
    
    string data_title = pt.get<string>("data.title","indef");
        
    string data_file = pt.get<string>("data.file","indef");
    
    if (loc.compare("rootcheck") == 0 && data_title.compare("indef") != 0 ) {
        
        report = "{ \"type\": \"rootcheck\", \"data\": ";
        
        report += "{ \"ref_id\": \"";
        report += fs.filter.ref_id;
            
        report += "\", \"agent\": \"";
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
        
        report += ", \"description\": \"";
        report += pt.get<string>("rule.description","indef");
        
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
        
        report += "\",\"category\":\"";
    
        int j = 0;
        for (string i : rec.rule.list_cats) {
            if (j != 0 && j < rec.rule.list_cats.size()) report += ", ";
            report += i;
            
            j++;    
        }
        
        report += "\", \"full_log\": \"";
        report += full_log;
        
        report += "\", \"title\": \"";
        report += data_title;
        
        report += "\", \"file\": \"";
        report += data_file;
        
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
        
	report += ",\"_agent\":\"";
        report += pt.get<string>("agent.name","");
        
        report += ",\"_manager\":\"";
        report += pt.get<string>("manager.name","");
        
        report +=  "\", \"_event_time\":\"";
        report += pt.get<string>("timestamp","");
        
        report += "\",\"_collected_time\":\"";
        report += GetGraylogFormat();
		
	report += "\",\"_description\":\"";
        report += pt.get<string>("rule.description","indef");
        
	report += "\",\"_full_log\":\"";
        report += full_log;
        
        report += "\",\"_pid\":\"";
        report += pt.get<string>("data.audit.pid","indef");
        
        report += "\",\"_command\":\"";
        report +=  pt.get<string>("data.audit.command","indef");
        
        report += "\",\"_exe\":\"";
        report +=  pt.get<string>("data.audit.exe","indef");
        
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
        
	report += ",\"_agent\":\"";
        report += pt.get<string>("agent.name","");
        
        report += ",\"_manager\":\"";
        report += pt.get<string>("manager.name","");
        
        report += "\", \"_event_time\":\"";
        report += pt.get<string>("timestamp","");
        
        report += "\",\"_collected_time\":\"";
        report += GetGraylogFormat();
		
	report += "\",\"_description\":\"";
        report += desc;
        
        report += "\",\"_id\":\"";
        report += pt.get<string>("data.id","indef");
        
        report += "\",\"_protocol\":\"";
        report += pt.get<string>("data.protocol","indef");
        
        report += "\",\"_srcip\":\"";
        report += pt.get<string>("data.srcip","indef");
        
        report += "\",\"_srcport\":\"";
        report += pt.get<string>("data.srcport","indef");
        
        report += "\",\"_srcuser\":\"";
        string srcuser = pt.get<string>("data.srcuser","indef");
        ReplaceAll(srcuser, "\\", "\\\\\\\\");
        report += srcuser;
        
        report += "\",\"_dstip\":\"";
        report += pt.get<string>("data.dstip","indef");
        
        report += "\",\"_dstport\":\"";
        report += pt.get<string>("data.dstport","indef");
        
        report += "\",\"_processGuid\":\"";
        report += pt.get<string>("data.sysmon.processGuid","indef");
        
        report += "\",\"_processId\":\"";
        report += pt.get<string>("data.sysmon.processId","indef");
        
        report += "\",\"_image\":\"";
        string image = pt.get<string>("data.sysmon.image","indef");
        ReplaceAll(image, "\\", "\\\\\\\\");
        report += image;
        
        report += "\",\"_initiated\":\"";
        report += pt.get<string>("data.sysmon.initiated","indef");
        
        report += "\",\"_sourceIsIpv6\":\"";
        report += pt.get<string>("data.sysmon.sourceIsIpv6","indef");
        
        report += "\",\"_sourceHostname\":\"";
        report += pt.get<string>("data.sysmon.sourceHostname","indef");
        
        report += "\",\"_destinationIsIpv6\":\"";
        report += pt.get<string>("data.sysmon.destinationIsIpv6","indef");
        
        report += "\",\"_destinationHostname\":\"";
        report += pt.get<string>("data.sysmon.destinationHostname","indef");
        
        report += "\"}";
    
        q_logs_hids.push(report);
        
        report.clear();
        ResetStreams();
        return 0;
    }
    
    rec.agent = pt.get<string>("agent.name","");
    
    rec.hostname = pt.get<string>("manager.name","");
    
    rec.datetime = pt.get<string>("timestamp","");
    
    rec.dstip = pt.get<string>("data.dstip","");
    
    string dec_name = pt.get<string>("decoder.name","");
        
    
    if (dec_name.compare("nginx-errorlog") == 0 && mr.IsModsec(full_log)) {
        
        mr.ParsRecord(full_log);
        
        rec.rule.id = mr.ma.id;
        
        rec.rule.level = mr.ma.severity;
        
        rec.rule.desc = mr.ma.msg;
        rec.rule.info = mr.ma.file;
        rec.location = mr.ma.uri;
        rec.srcip = mr.ma.hostname;
        
        std::vector<string>::iterator it, end;
        int i = 0;
        for (vector<string>::const_iterator it = mr.ma.list_tags.begin(); it != mr.ma.list_tags.end(); ++it, i++) {
        
            rec.rule.list_cats.push_back(*it);
        }
        
    } else {
        
        rec.srcip = pt.get<string>("data.srcip","");
        
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
    
        rec.location = loc;
        ReplaceAll(rec.location, "\"", "");
        ReplaceAll(rec.location, "\\", "\\\\\\\\");
        
        rec.file.filename = pt.get<string>("syscheck.path","");
        ReplaceAll(rec.file.filename, "\"", "");
        ReplaceAll(rec.file.filename, "\\", "\\\\\\\\");
    
        rec.file.md5_before = pt.get<string>("syscheck.md5_before","");
    
        rec.file.md5_after = pt.get<string>("syscheck.md5_after","");
    
        rec.file.sha1_before = pt.get<string>("syscheck.sha1_before","");
    
        rec.file.sha1_after = pt.get<string>("syscheck.sha1_after","");
    
        rec.file.owner_before = pt.get<string>("syscheck.owner_before","");
        
        rec.file.owner_after = pt.get<string>("syscheck.owner_after","");
           
        rec.file.gowner_before = pt.get<string>("syscheck.gowner_before","");
    
        rec.file.gowner_after = pt.get<string>("syscheck.gowner_after","");
        
        
        string user = pt.get<string>("data.srcuser","");
        
        if (user.compare("") == 0) {
            
            user = pt.get<string>("data.dstuser","");
        
        }
        
        rec.user = user;
    }
    
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
        
    report += ",\"_agent\":\"";
    report += rec.agent;
    
    report += "\", \"_manager\":\"";
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
	report += "\",\"_user\":\"";
    report += rec.user;
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

void Hids::CreateWafLog() {
    
    report = "{\"version\": \"1.1\",\"host\":\"";
    report += node_id;
    report += "\",\"short_message\":\"event-waf\"";
    report += ",\"full_message\":\"WAF event from ModSecurity\"";
    report += ",\"level\":";
    report += std::to_string(7);
    report += ",\"_type\":\"waf\"";
    report += ",\"_source\":\"modsecurity\"";
        
    report += ",\"_agent\":\"";
    report += rec.agent;
    
    report += "\", \"_manager\":\"";
    report += rec.hostname;
    
    report += "\", \"_event_time\":\"";
    report += rec.datetime;
    
    report += "\",\"_collected_time\":\"";
    report += GetGraylogFormat();
		
    report += "\",\"_description\":\"";
    report += rec.rule.desc;
    
    report += "\",\"_severity\":";
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
    report += "\",\"_target\":\"";
    report += rec.location;
    report += "\",\"_srcip\":\"";
    report += rec.srcip;
    report += "\",\"_dstip\":\"";
    report += rec.dstip;
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
    
    ids_rec.agent = rec.agent;
    ids_rec.user = rec.user;
    ids_rec.ids = rec.hostname;
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

int Hids::PushWafRecord(BwList* bwl) {
    // create new IDS record
    IdsRecord ids_rec;
            
    ids_rec.ref_id = fs.filter.ref_id;
    
    ids_rec.event = rec.rule.id;
            
    copy(rec.rule.list_cats.begin(),rec.rule.list_cats.end(),back_inserter(ids_rec.list_cats));
    
    if (rec.rule.level < 3) {
        ids_rec.severity = 3;
    } else {
        if (rec.rule.level < 4) {
            ids_rec.severity = 2;
        } else {
            if (rec.rule.level < 5) {
                ids_rec.severity = 1;
            } else {
                ids_rec.severity = 0;
            }
        }
    }
    
    ids_rec.desc = rec.rule.desc;
                
    ids_rec.src_ip = rec.srcip;
    ids_rec.dst_ip = rec.dstip;
    
    ids_rec.agent = rec.agent;
    ids_rec.ids = rec.hostname;
    ids_rec.action = "none";
                
    ids_rec.location = rec.location;
    ids_rec.ids_type = 4;
    
        
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
    
    if (!rec.rule.list_cats.empty())
        copy(rec.rule.list_cats.begin(),rec.rule.list_cats.end(),back_inserter(sk.alert.list_cats));
    else 
        sk.alert.list_cats.push_back("wazuh");
        
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
        
    sk.alert.source = "Wazuh";
    
    sk.alert.agent = rec.agent;
	sk.alert.user = rec.user;
    sk.alert.hostname = rec.hostname;
        
    if (rec.file.filename.compare("") == 0) {
            
        sk.alert.type = "HOST";
            
        sk.alert.location = rec.location;
        
        sk.alert.info = rec.rule.info;
    }
    else {
            
        sk.alert.type = "FILE";
            
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

void Hids::SendWafAlert(int s, BwList*  bwl) {
    
    sk.alert.ref_id =  fs.filter.ref_id;
    
    if (!mr.ma.list_tags.empty())
        copy(mr.ma.list_tags.begin(),mr.ma.list_tags.end(),back_inserter(sk.alert.list_cats));
    else 
        sk.alert.list_cats.push_back("waf");
    
    //std::string sev = "send alert waf severity is  " + std::to_string(s);
    //SysLog((char*) sev.c_str());
    
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
        
    sk.alert.source = "Modsecurity";
    sk.alert.type = "NET";
    
    sk.alert.agent = rec.agent;
    sk.alert.hostname = rec.hostname;
        
    sk.alert.location = rec.location;
        
    sk.alert.info = rec.rule.info;
    
    sk.alert.event_json.assign(reply->str, GetBufferSize(reply->str));
        
    sk.SendAlert();
        
}

    
