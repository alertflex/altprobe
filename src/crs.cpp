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
#include "crs.h"

#include <boost/algorithm/string.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

boost::lockfree::spsc_queue<string> q_logs_crs{LOG_QUEUE_SIZE};

int Crs::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (falcolog_status == 1) {
            
        fp = fopen(falco_log, "r");
        if(fp == NULL) {
            SysLog("failed open falco log file");
            return status = 0;
        }
        
        fseek(fp,0,SEEK_END);
        stat(falco_log, &buf);    
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

void Crs::Close() {
    
    sk.Close();
    
    if (status == 1) {
        
        if (falcolog_status == 1) {
            if (fp != NULL) fclose(fp);
        } else {
            if (redis_status == 1) redisFree(c);
        }
        
        status = 0;
    }
}

void Crs::IsFileModified() {
    
    int ret = stat(falco_log, &buf);
    if (ret == 0) {
                
        unsigned long current_size = (unsigned long) buf.st_size;
        
        if (current_size < file_size) {
            
            if (fp != NULL) fclose(fp);
            fp = fopen(falco_log, "r");
                        
            if (fp == NULL) return;
            else {
                
                fseek(fp,0,SEEK_SET);
                int ret = stat(falco_log, &buf);
                
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

int Crs::ReadFile() {
    
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

int Crs::Go(void) {
    
    GrayList* gl;
    int res = 0;
    
    ClearRecords();
        
    if (status) {
        
        if (falcolog_status == 1) {
            
            res = ReadFile();
            
            if (res == -1) {
                SysLog("failed reading falco events from log");
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
            
            if (fs.filter.crs.log ) CreateLog();
            
            if (alerts_counter <= sk.alerts_threshold) {
            
                gl = CheckGrayList();
            
                int severity = PushRecord(gl);
                
                if (gl != NULL) {
                    
                    if (gl->rsp.profile.compare("suppress") != 0) SendAlert(severity, gl);
                        
                } else {
                        
                    if (fs.filter.crs.severity.threshold <= severity) {
                            
                        SendAlert(severity, NULL);
                    
                    }
                } 
                
                if (sk.alerts_threshold != 0) {
            
                    if (alerts_counter < sk.alerts_threshold) alerts_counter++;
                    else {
                        SendAlertMultiple(0);
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

GrayList* Crs::CheckGrayList() {
    
    if (fs.filter.crs.gl.size() != 0) {
        
        std::vector<GrayList*>::iterator i, end;
        
        for (i = fs.filter.crs.gl.begin(), end = fs.filter.crs.gl.end(); i != end; ++i) {
            
            string event = (*i)->event;
            if (event.compare(rec.rule) == 0) {
                
                string container = (*i)->host;
                
                if (container.compare("indef") == 0 || container.compare(rec.fields.container_id) == 0 || container.compare(rec.fields.container_name) == 0) {
                
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

int Crs::ParsJson() {
    
    string message;
    
    IncrementEventsCounter();
    
    try {
    
        if (falcolog_status == 1) {
            
            jsonPayload.assign(file_payload, GetBufferSize(file_payload));
            ss << jsonPayload;
            
            rec.sensor = probe_id + ".crs";
        
        }  else {
            
            jsonPayload.assign(reply->str, GetBufferSize(reply->str));
            ss1 << jsonPayload;
            
            bpt::read_json(ss1, pt1);
    
            message = pt1.get<string>("message","");
            rec.sensor = pt1.get<string>("beat.name");
        
            if ((message.compare("") == 0)) {
                ResetStreams();
                return 0;
            }
            ss << message;
        }
        
        
        bpt::read_json(ss, pt);
    
    } catch (const std::exception & ex) {
        ResetStreams();
        SysLog((char*) ex.what());
        return 0;
    } 
    
    
    string output = pt.get<string>("output","");
    ReplaceAll(output, "\"", "");
    // ReplaceAll(output, "\\", "\\\\\\\\");
    rec.output = output;
    
    rec.priority = pt.get<string>("priority","");
    
    if (rec.priority.compare("Emergency") == 0) rec.level = 7;
    if (rec.priority.compare("Alert") == 0) rec.level = 6;
    if (rec.priority.compare("Critical") == 0) rec.level = 5;
    if (rec.priority.compare("Error") == 0) rec.level = 4;
    if (rec.priority.compare("Warning") == 0) rec.level = 3;
    if (rec.priority.compare("Notice") == 0) rec.level = 2;
    if (rec.priority.compare("Info") == 0) rec.level = 1;
    if (rec.priority.compare("Debug") == 0) rec.level = 0;
    
    rec.timestamp = pt.get<string>("time","");
    
    rec.rule = pt.get<string>("rule","");
    
    boost::optional< bpt::ptree& > child = pt.get_child_optional( "output_fields" );
    
    if( child ) {
        
        bpt::ptree output_fields = pt.get_child("output_fields");
    
        rec.fields.fd_cip = output_fields.get<string>(bpt::ptree::path_type("fd.cip", '/'),"indef");
        rec.fields.fd_sip = output_fields.get<string>(bpt::ptree::path_type("fd.sip", '/'),"indef");
        rec.fields.fd_cport = output_fields.get<int>(bpt::ptree::path_type("fd.cport", '/'),0);
        rec.fields.fd_sport = output_fields.get<int>(bpt::ptree::path_type("fd.sport", '/'),0);
        rec.fields.fd_cip_name = output_fields.get<string>(bpt::ptree::path_type("fd.cip.name", '/'),"indef");
        rec.fields.fd_sip_name = output_fields.get<string>(bpt::ptree::path_type("fd.sip.name", '/'),"indef");
        
        rec.fields.fd_path = output_fields.get<string>(bpt::ptree::path_type("fd.name", '/'),"indef");
                
        rec.fields.proc_pid = output_fields.get<int>(bpt::ptree::path_type("proc.pid", '/'),0);
        rec.fields.proc_cmdline = output_fields.get<string>(bpt::ptree::path_type("proc.cmdline", '/'),"indef");
        rec.fields.proc_name = output_fields.get<string>(bpt::ptree::path_type("proc.name", '/'),"indef");
        rec.fields.proc_cwd = output_fields.get<string>(bpt::ptree::path_type("proc.cwd", '/'),"indef");  
    
        rec.fields.container_id = output_fields.get<string>(bpt::ptree::path_type("container.id", '/'),"indef");
        
        rec.fields.container_name = output_fields.get<string>(bpt::ptree::path_type("container.name", '/'),"indef");
    
        rec.fields.user_name = output_fields.get<string>(bpt::ptree::path_type("user.name", '/'),"indef");
        
        string cloudInstance = rec.fields.fd_cip_name = output_fields.get<string>(bpt::ptree::path_type("ka.req.pod.containers.image", '/'),"indef");
        
        if (cloudInstance.compare("indef") == 0) {
           cloudInstance = rec.fields.fd_cip_name = output_fields.get<string>(bpt::ptree::path_type("ka.target.resource", '/'),"indef"); 
        }
        
        rec.fields.cloud_instance = cloudInstance;
    }
        
    ResetStreams();
    
    return 1;
}

void Crs::CreateLog() {
    
    report = "{\"version\": \"1.1\",\"node\":\"";
    report += node_id;
    report += "\",\"short_message\":\"alert-crs\"";
    report += ",\"full_message\":\"Alert from Falco\"";
    report += ",\"level\":";
    report += std::to_string(7);
    report += ",\"source_type\":\"HOST\"";
    report += ",\"source_name\":\"Falco\"";
        
    report +=  ",\"project_id\":\"";
    report +=  fs.filter.ref_id;
			
    report +=  "\",\"event_time\":\"";
    report +=  rec.timestamp;
    
    report += "\",\"collected_time\":\"";
    report += GetGraylogFormat();
    
    report += "\",\"priority\":\"";
    report += rec.priority;
    
    report += "\",\"rule\":\"";
    report += rec.rule;
		
    report += "\",\"description\":\"";
    report += rec.output;
    
    report += "\", \"sensor\":\"";
    report += rec.sensor;
    
    report += "\",\"user_name\":\"";
    report += rec.fields.user_name;
    
    report += "\",\"client_ip\":\"";
    report += rec.fields.fd_cip;
    
    report += "\",\"server_ip\":\"";
    report += rec.fields.fd_sip;
    
    report += "\",\"client_port\":";
    report += std::to_string(rec.fields.fd_cport);
    
    report += ",\"server_port\":";
    report += std::to_string(rec.fields.fd_sport);
    
    report += ",\"client_hostname\":\"";
    report += rec.fields.fd_cip_name;
    
    report += "\",\"server_hostname\":\"";
    report += rec.fields.fd_sip_name;
    
    report += "\",\"file_path\":\"";
    report += rec.fields.fd_path;
    
    report += "\",\"process_pid\":";
    report += std::to_string(rec.fields.proc_pid);
    
    report += ",\"process_cmdline\":\"";
    report += rec.fields.proc_cmdline;
    
    report += "\",\"process_name\":\"";
    report += rec.fields.proc_name;
    
    report += "\",\"process_dir\":\"";
    report += rec.fields.proc_cwd;
    
    report += "\",\"container_name\":\"";
    report += rec.fields.container_name;
    
    report += "\",\"container_id\":\"";
    report += rec.fields.container_id;
    
    report += "\"}";
    
    q_logs_crs.push(report);
    
    report.clear();
}

int Crs::PushRecord(GrayList* gl) {
    
    // create new IDS record
    IdsRecord ids_rec;
            
    ids_rec.ref_id = fs.filter.ref_id;
    
    ids_rec.event = rec.rule;
            
    if (rec.level < fs.filter.hids.severity.level0) {
        ids_rec.severity = 0;
    } else {
        if (rec.level < fs.filter.hids.severity.level1) {
            ids_rec.severity = 1;
        } else {
            if (rec.level < fs.filter.hids.severity.level2) {
                ids_rec.severity = 2;
            } else {
                ids_rec.severity = 3;
            }
        }
    }    
    
    ids_rec.list_cats.push_back("falco");
    ids_rec.user = rec.fields.user_name;
    ids_rec.process = rec.fields.proc_name;
    ids_rec.container = rec.fields.container_id;
    ids_rec.ids = rec.sensor;
    ids_rec.action = "indef";
                    
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
    
    q_crs.push(ids_rec);
                
    return ids_rec.severity;
}

void Crs::SendAlert(int s, GrayList*  gl) {
    
    sk.alert.ref_id =  fs.filter.ref_id;
    sk.alert.sensor_id = rec.sensor;
    
    sk.alert.alert_severity = s;
    sk.alert.alert_source = "Falco";
    sk.alert.alert_type = "HOST";
    sk.alert.event_severity = rec.level;
    sk.alert.event_id = rec.rule;
    sk.alert.description = rec.output;
    sk.alert.action = "indef";     
    sk.alert.location = "indef";
    sk.alert.info = "indef";
    sk.alert.status = "processed";
    sk.alert.user_name = rec.fields.user_name;
    sk.alert.agent_name = probe_id;
    sk.alert.filter = fs.filter.name;
    
    sk.alert.list_cats.push_back("falco");
    
    sk.alert.event_time = rec.timestamp;
            
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
    
    sk.alert.src_ip = rec.fields.fd_cip;
    sk.alert.dst_ip = rec.fields.fd_sip;
    sk.alert.src_hostname = GetHostname(rec.fields.fd_cip);
    sk.alert.dst_hostname = GetHostname(rec.fields.fd_sip);
    sk.alert.src_port = rec.fields.fd_cport;
    sk.alert.dst_port = rec.fields.fd_sport;
    
    sk.alert.reg_value = "indef";
    sk.alert.file_name = rec.fields.fd_path;
	
    sk.alert.hash_md5 = "indef";
    sk.alert.hash_sha1 = "indef";
    sk.alert.hash_sha256 = "indef";
	
    sk.alert.process_id = rec.fields.proc_pid;
    sk.alert.process_name = rec.fields.proc_name;
    sk.alert.process_cmdline = rec.fields.proc_cmdline;
    sk.alert.process_path = rec.fields.proc_cwd;
    
    sk.alert.url_hostname = "indef";
    sk.alert.url_path = "indef";
    
    sk.alert.container_id = rec.fields.container_id;
    sk.alert.container_name = rec.fields.container_name;
    
    sk.alert.cloud_instance = rec.fields.cloud_instance;
    
    sk.SendAlert();
    
}

    
