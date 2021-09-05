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
#include "hids.h"

#include <boost/algorithm/string.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

boost::lockfree::spsc_queue<string> q_logs_hids{LOG_QUEUE_SIZE};
boost::lockfree::spsc_queue<string> q_reports{LOG_QUEUE_SIZE};

int Hids::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (wazuhlog_status == 1) {
            
        fp = fopen(wazuh_log, "r");
        if(fp == NULL) {
            SysLog("failed open wazuh log file");
            return status = 0;
        }
            
        fseek(fp,0,SEEK_END);
        stat(wazuh_log, &buf);    
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
        } else status = 0;
    }
    
    return status;
}

void Hids::Close() {
    
    sk.Close();
    
    if (status == 1) {
        
        if (wazuhlog_status == 1) {
            if (fp != NULL) fclose(fp);
        } else {
            if (redis_status == 1) redisFree(c);
        }
        
        status = 0;
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
        
        if (wazuhlog_status == 1) {
            
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
        
            // read data from redis
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
        
        if (redis_status == 1) freeReplyObject(reply);
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
                
                if (agent.compare("indef") == 0 || agent.compare(rec.agent) == 0) {
                    
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

int Hids::ParsJson() {
    
    string message;
    
    IncrementEventsCounter();
    
    try {
    
        if (wazuhlog_status == 1) {
            
            jsonPayload.assign(file_payload, GetBufferSize(file_payload));
            ss << jsonPayload;
        
        }  else {
            
            jsonPayload.assign(reply->str, GetBufferSize(reply->str));
            ss1 << jsonPayload;
            
            bpt::read_json(ss1, pt1);
    
            message = pt1.get<string>("message","");
        
            if ((message.compare("") == 0)) {
                ResetStreams();
                return 0;
            }
            ss << message;
        }
        
        
        bpt::read_json(ss, pt);
    
    } catch (const std::exception & ex) {
        ResetStreams();
        // SysLog((char*) ex.what());
        return 0;
    } 
    
    rec.sensor = probe_id + ".hids";
    
    string loc = pt.get<string>("location","");
    
    if (loc.compare("vulnerability-detector") == 0 ) {
    
        report = "{ \"type\": \"vulnerability\", \"data\": ";
        
        report += "{ \"ref_id\": \"";
        report += fs.filter.ref_id;
            
        report += "\", \"agent\": \"";
        report += pt.get<string>("agent.id","");
        
        report += "\", \"cve\": \"";
        report += pt.get<string>("data.vulnerability.cve","indef");
        
        report += "\", \"severity\": \"";
        report += pt.get<string>("data.vulnerability.severity","indef");
        
        report += "\", \"reference\": \"";
        
        try {
            
            vul_ref = pt.get_child("data.vulnerability.references");
        
            BOOST_FOREACH(bpt::ptree::value_type &v, vul_ref) {
                assert(v.first.empty()); // array elements have no names
                report += " ";
                report += v.second.data();
            }
        } catch (bpt::ptree_bad_path& e) {
            
        }
        
        report += "\", \"pkg_name\": \"";
        report += pt.get<string>("data.vulnerability.package.name","indef");
        
        report += "\", \"pkg_version\": \"";
        report += pt.get<string>("data.vulnerability.package.version","indef");
        
        report += "\", \"title\": \"";
        report += pt.get<string>("data.vulnerability.title","indef");
        
        report += "\", \"description\": \"";
        
        string rationale = pt.get<string>("data.vulnerability.rationale","indef");
        ReplaceAll(rationale, "\"", "");
                
        report += rationale;
        
        report += "\", \"time_of_survey\": \"";
        report += GetNodeTime();
        report += "\" } }";
        
        q_reports.push(report);
        
        report.clear();
        ResetStreams();
        return 0;
    }
    
    rec.agent = pt.get<string>("agent.name","indef");
    
    rec.timestamp = pt.get<string>("timestamp","indef");
    
    rec.dstip = pt.get<string>("data.dstip","indef");
    
    rec.dstport = pt.get<int>("data.dstport",0);
    
    rec.srcip = pt.get<string>("data.srcip","indef");
    
    rec.srcport = pt.get<int>("data.srcport",0);
        
    rec.rule.id = pt.get<int>("rule.id",0);
    
    rec.rule.level = pt.get<int>("rule.level",0);
    
    rec.location = loc;
    ReplaceAll(rec.location, "\"", "");
    ReplaceAll(rec.location, "\'", "");
    ReplaceAll(rec.location, "\r", " ");
    ReplaceAll(rec.location, "\n", " ");
    ReplaceAll(rec.location, "\\", "\\\\");
    
    rec.file.file_path = pt.get<string>("syscheck.path","indef");
    ReplaceAll(rec.file.file_path, "\"", "");
    ReplaceAll(rec.file.file_path, "\'", "");
    ReplaceAll(rec.file.file_path, "\r", " ");
    ReplaceAll(rec.file.file_path, "\n", " ");
    ReplaceAll(rec.file.file_path, "\\", "\\\\");
    
    rec.file.reg_value = pt.get<string>("syscheck.value_name","indef");
    ReplaceAll(rec.file.reg_value, "\"", "");
    ReplaceAll(rec.file.reg_value, "\'", "");
    ReplaceAll(rec.file.reg_value, "\r", " ");
    ReplaceAll(rec.file.reg_value, "\n", " ");
    ReplaceAll(rec.file.reg_value, "\\", "\\\\");
    
    rec.rule.desc = pt.get<string>("rule.description","indef");
    ReplaceAll(rec.rule.desc, "\"", "");
    ReplaceAll(rec.rule.desc, "\'", "");
    ReplaceAll(rec.rule.desc, "\r", " ");
    ReplaceAll(rec.rule.desc, "\n", " ");
    ReplaceAll(rec.rule.desc, "\\", "\\\\");
    
    rec.rule.info = pt.get<string>("full_log","indef");
    ReplaceAll(rec.rule.info, "\"", "");
    ReplaceAll(rec.rule.info, "\'", "");
    ReplaceAll(rec.rule.info, "\r", " ");
    ReplaceAll(rec.rule.info, "\n", " ");
    ReplaceAll(rec.rule.info, "\\", "\\\\");
    
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
    
    try {
    
        mitre_cats = pt.get_child("rule.mitre.id");
            
        BOOST_FOREACH(bpt::ptree::value_type &v, mitre_cats) {
            assert(v.first.empty()); // array elements have no names
            string mitre = "mitre_" + v.second.data();
            rec.rule.list_cats.push_back(mitre);
        }  
    
    } catch (bpt::ptree_bad_path& e) {}
    
    rec.file.md5 = pt.get<string>("syscheck.md5_after","");
    
    rec.file.sha1 = pt.get<string>("syscheck.sha1_after","");
    
    rec.file.sha256 = pt.get<string>("syscheck.sha256_after","");
    
    rec.process_id = pt.get<int>("syscheck.audit.process.id", 0);
        
    rec.process_name = pt.get<string>("syscheck.audit.process.name","indef");
    
    string user = pt.get<string>("syscheck.audit.user.name","indef");
        
    if (user.compare("indef") == 0) {   
        user = pt.get<string>("data.srcuser","indef");
    }
        
    if (user.compare("indef") == 0) {
        user = pt.get<string>("data.dstuser","indef");
    }
        
    rec.user = user;
    
    ResetStreams();
    
    if(SuppressAlert(rec.srcip)) return 0;
    if(SuppressAlert(rec.dstip)) return 0;
    
    return 1;
}

void Hids::CreateLog() {
    
    
       
    
    report = "{\"version\": \"1.1\",\"node\":\"";
    report += node_id;
    
    if (rec.file.file_path.compare("indef") != 0) {
        report += "\",\"short_message\":\"alert-fim\"";
        report += ",\"full_message\":\"Alert from OSSEC/Wazuh FIM\"";
        report += ",\"level\":";
        report += std::to_string(7);
        report += ",\"source_type\":\"FILE\"";
    } else {
        report += "\",\"short_message\":\"alert-hids\"";
        report += ",\"full_message\":\"Alert from OSSEC/Wazuh HIDS\"";
        report += ",\"level\":";
        report += std::to_string(7);
        report += ",\"source_type\":\"HOST\"";
    }
    report += ",\"source_name\":\"Wazuh\"";
        
    report += ",\"agent\":\"";
    report += rec.agent;
    
    report += "\", \"sensor\":\"";
    report += rec.sensor;
    
    report +=  "\",\"project_id\":\"";
    report +=  fs.filter.ref_id;
			
    report +=  "\",\"event_time\":\"";
    report +=  rec.timestamp;
    
    report += "\",\"collected_time\":\"";
    report += GetGraylogFormat();
		
    report += "\",\"description\":\"";
    report += rec.rule.desc;
    
    report += "\",\"ossec-level\":";
    report += std::to_string(rec.rule.level);
    
    report += ",\"sidid\":";
    report += std::to_string(rec.rule.id);
	
    report += ",\"group_name\":\"";
    
    int j = 0;
    for (string i : rec.rule.list_cats) {
        if (j != 0 && j < rec.rule.list_cats.size()) report += ", ";
        report += i;
            
        j++;    
    }
    
    report += "\",\"info\":\"";
    report += rec.rule.info;
    report += "\",\"location\":\"";
    report += rec.location;
    report += "\",\"srcip\":\"";
    report += rec.srcip;
    report += "\",\"dstip\":\"";
    report += rec.dstip;
    report += "\",\"process\":\"";
    report += rec.process_name;
    report += "\",\"user\":\"";
    report += rec.user;
    
    if (rec.file.file_path.compare("indef") != 0) {
        report += "\",\"filename\":\"";
        report += rec.file.file_path;
        report += "\",\"md5\":\"";
        report += rec.file.md5;
        report += "\",\"sha1\":\"";
        report += rec.file.sha1;
        report += "\",\"sha256\":\"";
        report += rec.file.sha256;
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
    ids_rec.process = rec.process_name;
    ids_rec.user = rec.user;
    ids_rec.ids = rec.sensor;
    ids_rec.action = "indef";
                
    if (rec.file.file_path.compare("") == 0) {
        ids_rec.location = rec.location;
    }  else {
        ids_rec.file = rec.file.file_path;
    }
        
    if (gl != NULL) {
        
        ids_rec.filter = true;
        
        if (gl->agr.reproduced > 0) {
            
            ids_rec.host = "indef";
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
    
    q_hids.push(ids_rec);
            
    return ids_rec.severity;
}

void Hids::SendAlert(int s, GrayList*  gl) {
    
    sk.alert.ref_id =  fs.filter.ref_id;
    sk.alert.sensor_id = rec.sensor;
    
    sk.alert.alert_severity = s;
    sk.alert.alert_source = "Wazuh";
    sk.alert.alert_type = "HOST";
    sk.alert.event_severity = rec.rule.level;
    sk.alert.event_id = std::to_string(rec.rule.id);
    sk.alert.description = rec.rule.desc;
    sk.alert.action = "indef";     
    sk.alert.location = rec.location;
    sk.alert.info = rec.rule.info;
    sk.alert.status = "processed";
    sk.alert.user_name = rec.user;
    sk.alert.agent_name = rec.agent;
    sk.alert.filter = fs.filter.name;
    
    if (!rec.rule.list_cats.empty())
        copy(rec.rule.list_cats.begin(),rec.rule.list_cats.end(),back_inserter(sk.alert.list_cats));
    else 
        sk.alert.list_cats.push_back("wazuh");
    
    sk.alert.event_time = rec.timestamp;
        
    sk.alert.src_ip = rec.srcip;
    sk.alert.dst_ip = rec.dstip;
    sk.alert.src_hostname = "indef";
    sk.alert.dst_hostname = "indef";
    sk.alert.src_port = rec.srcport;
    sk.alert.dst_port = rec.dstport;
        
    sk.alert.reg_value = "indef";
    sk.alert.file_name = "indef";
	
    sk.alert.hash_md5 = "indef";
    sk.alert.hash_sha1 = "indef";
    sk.alert.hash_sha256 = "indef";
	
    sk.alert.process_id = rec.process_id;
    sk.alert.process_name = rec.process_name;
    sk.alert.process_cmdline = "indef";
    sk.alert.process_path = "indef";
    
    sk.alert.url_hostname = "indef";
    sk.alert.url_path = "indef";
    
    sk.alert.container_id = "indef";
    sk.alert.container_name = "indef";
    
    sk.alert.cloud_instance = "indef";
        
    if (rec.file.file_path.compare("indef") != 0) {
            
        sk.alert.alert_type = "FILE";
            
        sk.alert.reg_value = rec.file.reg_value;
        sk.alert.file_name = rec.file.file_path;
        
        sk.alert.hash_md5 = rec.file.md5;
        sk.alert.hash_sha1 = rec.file.sha1;
        sk.alert.hash_sha256 = rec.file.sha256;
    }
    
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
    
    sk.SendAlert();
    
}

    
