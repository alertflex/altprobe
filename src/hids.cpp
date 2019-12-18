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

int Hids::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (status == 1) {
        
        if (wazuhlog_status == 2) {
            
            fp = fopen(wazuh_log, "r");
            if(fp == NULL) {
                SysLog("failed open wazuh log file");
                return 0;
            }
            
            fseek(fp,0,SEEK_END);
            stat(wazuh_log, &buf);    
            file_size = (unsigned long) buf.st_size;
      
        } else {
        
            if (wazuhlog_status == 1) {
            
                c = redisConnect(sk.redis_host, sk.redis_port);
    
                if (c != NULL && c->err) {
                    // handle error
                    sprintf(level, "failed open redis server interface: %s\n", c->errstr);
                    SysLog(level);
                    return 0;
                }
            } else return 0;
        }
    }
    
    return 1;
}

void Hids::Close() {
    
    sk.Close();
    
    if (status == 1) {
        
        if (wazuhlog_status) {
            if (fp != NULL) fclose(fp);
        } else redisFree(c);
    }
}

void Hids::IsFileModified() {
    
    int ret = stat(wazuh_log, &buf);
    if (ret == 0) {
                
        unsigned long current_size = (unsigned long) buf.st_size;
        
        if (current_size < file_size) {
            
            if (fp != NULL) fclose(fp);
            fp = fopen(wazuh_log, "r");
                        
            if (fp == NULL) return;
            else {
                
                fseek(fp,0,SEEK_SET);
                int ret = stat(wazuh_log, &buf);
                
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

int Hids::ReadFile() {
    
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

int Hids::Go(void) {
    
    GrayList* gl;
    int res = 0;
    
    ClearRecords();
        
    if (status) {
        
        if (wazuhlog_status) {
            
            res = ReadFile();
            
            if (res == -1) {
                SysLog("failed reading wazuh events from log");
                return 1;
            }
        
            if (res == 0) {
                
                usleep(GetGosleepTimer()*60);
                alerts_counter = 0;
                return 1;
                
            } else res = ParsJson();
        
        
        } else {
        
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
        }
        
        IncrementEventsCounter();
        
        if (res != 0 ) {  
            
            boost::shared_lock<boost::shared_mutex> lock(fs.filters_update);
            
            if (fs.filter.hids.log ) CreateLog();
            
            if (alerts_counter <= sk.alerts_threshold) {
            
                gl = CheckGrayList();
            
                int severity = PushRecord(gl);
                
                if (gl != NULL) {
                    
                    if (gl->rsp.profile.compare("suppress") != 0) SendAlert(severity, gl);
                        
                } else {
                        
                    if (fs.filter.hids.severity.threshold <= severity) {
                            
                        SendAlert(severity, NULL);
                    
                    }
                } 
                
                    if (sk.alerts_threshold != 0) {
            
                    if (alerts_counter < sk.alerts_threshold) alerts_counter++;
                    else {
                        SendAlertMultiple(1);
                        alerts_counter++;
                    }
                }
            }
        }
        
        if (!wazuhlog_status) freeReplyObject(reply);
    } 
    else {
        usleep(GetGosleepTimer()*60);
    }
            
    return 1;
}

GrayList* Hids::CheckGrayList() {
    
    if (fs.filter.hids.gl.size() != 0) {
        
        std::vector<GrayList*>::iterator i, end;
        
        for (i = fs.filter.hids.gl.begin(), end = fs.filter.hids.gl.end(); i != end; ++i) {
            
            int event_id = std::stoi((*i)->event);
            if (event_id == rec.rule.id) {
                
                string agent = (*i)->host;
                
                if (agent.compare("all") == 0 || agent.compare(rec.agent) == 0) {
                
                    return (*i);
                }
            }
        }
    }
    
    return NULL;
}

int Hids::ParsJson() {
    
    string message;
    
    try {
    
        if (!wazuhlog_status) {
            
            jsonPayload.assign(reply->str, GetBufferSize(reply->str));
            ss1 << jsonPayload;
            
            bpt::read_json(ss1, pt1);
    
            message = pt1.get<string>("message","");
        
            if ((message.compare("") == 0)) {
                ResetStreams();
                return 0;
            }
            ss << message;
        
        }  else {
            jsonPayload.assign(file_payload, GetBufferSize(file_payload));
            ss << jsonPayload;
        }
        
        
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
    
        report = "{ \"type\": \"openscap\", \"data\": ";
        
        report += "{ \"ref_id\": \"";
        report += fs.filter.ref_id;
            
        report += "\", \"agent\": \"";
        report += pt.get<string>("agent.name","");
        
        report += "\", \"event_id\": \"";
        report += std::to_string(pt.get<int>("rule.id",0));
        
        report += "\", \"severity\": ";
        
        int level = pt.get<int>("rule.level",0);
        string severity;
    
        if (level < fs.filter.hids.severity.level0) {
            severity = "0";
        } else {
            if (level < fs.filter.hids.severity.level1) {
                severity = "1";
            } else {
                if (level < fs.filter.hids.severity.level2) {
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
    
        if (level < fs.filter.hids.severity.level0) {
            severity = "0";
        } else {
            if (level < fs.filter.hids.severity.level1) {
                severity = "1";
            } else {
                if (level < fs.filter.hids.severity.level2) {
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
    
        if (level < fs.filter.hids.severity.level0) {
            severity = "0";
        } else {
            if (level < fs.filter.hids.severity.level1) {
                severity = "1";
            } else {
                if (level < fs.filter.hids.severity.level2) {
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
        
        try {
    
            hipaa_cats = pt.get_child("rule.hipaa");
            
            BOOST_FOREACH(bpt::ptree::value_type &v, hipaa_cats) {
                assert(v.first.empty()); // array elements have no names
                string hipaa = "hipaa_" + v.second.data();
                rec.rule.list_cats.push_back(hipaa);
            }  
    
        } catch (bpt::ptree_bad_path& e) {}
        
        
        try {
    
            gdpr_cats = pt.get_child("rule.gdpr");
            
            BOOST_FOREACH(bpt::ptree::value_type &v, gdpr_cats) {
                assert(v.first.empty()); // array elements have no names
                string gdpr = "gdpr_" + v.second.data();
                rec.rule.list_cats.push_back(gdpr);
            }  
    
        } catch (bpt::ptree_bad_path& e) {}
        
        try {
    
            nist_cats = pt.get_child("rule.nist_800_53");
            
            BOOST_FOREACH(bpt::ptree::value_type &v, nist_cats) {
                assert(v.first.empty()); // array elements have no names
                string nist = "nist_800_53_" + v.second.data();
                rec.rule.list_cats.push_back(nist);
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
        report += ",\"_type\":\"NET\"";
        report += ",\"_source\":\"Wazuh\"";
        
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
		
	report += ",\"_type\":\"HOST\"";
        report += ",\"_source\":\"Wazuh\"";
        
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
    
    rec.timestamp = pt.get<string>("timestamp","");
    
    rec.dstip = pt.get<string>("data.dstip","");
    
    string dec_name = pt.get<string>("decoder.name","");
        
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
    
    try {
    
        hipaa_cats = pt.get_child("rule.hipaa");
            
        BOOST_FOREACH(bpt::ptree::value_type &v, hipaa_cats) {
            assert(v.first.empty()); // array elements have no names
            string hipaa = "hipaa_" + v.second.data();
            rec.rule.list_cats.push_back(hipaa);
        }  
    
    } catch (bpt::ptree_bad_path& e) {}
        
        
    try {
    
        gdpr_cats = pt.get_child("rule.gdpr");
            
        BOOST_FOREACH(bpt::ptree::value_type &v, gdpr_cats) {
            assert(v.first.empty()); // array elements have no names
            string gdpr = "gdpr_" + v.second.data();
            rec.rule.list_cats.push_back(gdpr);
        }  
    
    } catch (bpt::ptree_bad_path& e) {}
        
    try {
    
        nist_cats = pt.get_child("rule.nist_800_53");
            
        BOOST_FOREACH(bpt::ptree::value_type &v, nist_cats) {
            assert(v.first.empty()); // array elements have no names
            string nist = "nist_800_53_" + v.second.data();
            rec.rule.list_cats.push_back(nist);
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
    
    ResetStreams();
    
    if(SuppressAlert(rec.srcip)) return 0;
    if(SuppressAlert(rec.dstip)) return 0;
    
    return 1;
}

void Hids::CreateLog() {
    
    report = "{\"version\": \"1.1\",\"host\":\"";
    report += node_id;
    
    if (rec.file.filename.compare("") != 0) {
        report += "\",\"short_message\":\"alert-fim\"";
        report += ",\"full_message\":\"Alert from OSSEC/Wazuh FIM\"";
        report += ",\"level\":";
        report += std::to_string(7);
        report += ",\"_type\":\"FILE\"";
    } else {
        report += "\",\"short_message\":\"alert-hids\"";
        report += ",\"full_message\":\"Alert from OSSEC/Wazuh HIDS\"";
        report += ",\"level\":";
        report += std::to_string(7);
        report += ",\"_type\":\"HOST\"";
    }
    report += ",\"_source\":\"Wazuh\"";
        
    report += ",\"_agent\":\"";
    report += rec.agent;
    
    report += "\", \"_manager\":\"";
    report += rec.hostname;
    
    report +=  "\",\"_project_id\":\"";
    report +=  fs.filter.ref_id;
			
    report +=  "\",\"_event_time\":\"";
    report +=  rec.timestamp;
    
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
    
    q_logs_hids.push(report);
    
    report.clear();
}

int Hids::PushRecord(GrayList* gl) {
    
    // create new IDS record
    IdsRecord ids_rec;
            
    ids_rec.ref_id = fs.filter.ref_id;
    
    ids_rec.event = std::to_string(rec.rule.id);
            
    copy(rec.rule.list_cats.begin(),rec.rule.list_cats.end(),back_inserter(ids_rec.list_cats));
    
    if (rec.rule.level < fs.filter.hids.severity.level0) {
        ids_rec.severity = 0;
    } else {
        if (rec.rule.level < fs.filter.hids.severity.level1) {
            ids_rec.severity = 1;
        } else {
            if (rec.rule.level < fs.filter.hids.severity.level2) {
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
    ids_rec.ids = sensor;
    ids_rec.action = "indef";
                
    if (rec.file.filename.compare("") == 0) {
        ids_rec.location = rec.location;
        ids_rec.ids_type = 2;
    }  else {
        ids_rec.file = rec.file.filename;
        ids_rec.ids_type = 1;
    }
        
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
            
    q_hids.push(ids_rec);
    
    return ids_rec.severity;
}

void Hids::SendAlert(int s, GrayList*  gl) {
    
    sk.alert.ref_id =  fs.filter.ref_id;
    
    if (!rec.rule.list_cats.empty())
        copy(rec.rule.list_cats.begin(),rec.rule.list_cats.end(),back_inserter(sk.alert.list_cats));
    else 
        sk.alert.list_cats.push_back("wazuh");
        
    sk.alert.severity = s;
    sk.alert.score = rec.rule.level;
    sk.alert.event = std::to_string(rec.rule.id);
    sk.alert.action = "indef";
    sk.alert.description = rec.rule.desc;
        
    sk.alert.status = "processed_new";
            
    sk.alert.srcip = rec.srcip;
    sk.alert.dstip = rec.dstip;
    
    sk.alert.srcagent = "indef";
    sk.alert.dstagent = "indef";
    sk.alert.agent = rec.agent;
    
    sk.alert.srcport = 0;
    sk.alert.dstport = 0;
        
    sk.alert.source = "Wazuh";
    
    sk.alert.user = rec.user;
    sk.alert.sensor = sensor;
    sk.alert.filter = fs.filter.desc;
    sk.alert.event_time = rec.timestamp;
    
    sk.alert.container = "indef";
    sk.alert.process = "indef";
        
    if (rec.file.filename.compare("") == 0) {
            
        sk.alert.type = "HOST";
            
        sk.alert.location = rec.location;
        sk.alert.file = "indef";
        
        sk.alert.info = rec.rule.info;
    }
    else {
            
        sk.alert.type = "FILE";
            
        sk.alert.file = rec.file.filename;
        sk.alert.location = "indef";
        
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
    
    sk.alert.event_json = jsonPayload;
    
    sk.SendAlert();
    
}

    
