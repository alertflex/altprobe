/* 
 * File:   waf.cpp
 * Author: Oleg Zharkov
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "waf.h"

#include <boost/algorithm/string.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>

boost::lockfree::spsc_queue<string> q_logs_waf{LOG_QUEUE_SIZE};


void ModsecRecord::GetAuditHeader(const string str) {
    
    int pointer = str.find("[file");
    
    parameters = str.substr(pointer);
}

void ModsecRecord::GetClient(const string str) {
    
    int i;
    char rest_str[15];
    
    size_t pointer = str.find(", client: ");
    
    if (pointer != string::npos) {
        
        string check = str.substr(pointer);
        
        if (check.length() > 25) {
            string client = str.substr(pointer + 10, 15);
            strcpy(rest_str, client.c_str());
        
            for (i = 0; i < 15; i++) {
                if (rest_str[i] == ',') break;
            }
        
            ma.client =  client.substr(0, i);
            return;
        }
    }
    
    ma.client = "";
}

void ModsecRecord::RemoveAuditParametersName(const string field, const string str) {
    
    int b = field.length();
    int l = str.length() - b - 2;
    
    buffer = str.substr(b, l);
    
    buffer.erase(0, 2);
    buffer.erase(buffer.size() - 1);   
}

void ModsecRecord::CheckAuditFields(const string str) {
    
    
    
    if(str.find("file") == 0) {
        
        try {
        
            RemoveAuditParametersName("file", str);
            ma.file = buffer;
        
        } catch (const std::exception & ex) {
            ma.file = "";
        }
        
        return;
    }
    
    if(str.find("id") == 0) {
        
        try {
            
            RemoveAuditParametersName("id", str);
            ma.id = std::stoi(buffer);

        } catch (const std::exception & ex) {
            ma.id = 0;
        }
        
        return;
    }
    
    if(str.find("severity") == 0) {
        
        
        try {
           
            RemoveAuditParametersName("severity", str);
            ma.severity = std::stoi(buffer);

        } catch (const std::exception & ex) {
            ma.severity = 0;
        }
        
        return;
    }
    
    if(str.find("tag") == 0) {
            
        try {
            
            RemoveAuditParametersName("tag", str);
            ma.list_tags.push_back(buffer);
        
        } catch (const std::exception & ex) {
        }
        
        return;
    }
    
    if(str.find("msg") == 0) {
        
        try {
        
            RemoveAuditParametersName("msg", str);
            ma.msg = buffer;
        
        } catch (const std::exception & ex) {
            ma.msg = "";
        }
        
        return;
    }
    
    if(str.find("hostname") == 0) {
        
        try {
        
            RemoveAuditParametersName("hostname", str);
            ma.hostname = buffer;
        
        } catch (const std::exception & ex) {
            ma.hostname = "";
        }
        
        return;
    }
    
    if(str.find("uri") == 0) {
        
        try {
        
            RemoveAuditParametersName("uri", str);
            ma.uri = buffer;
        
        } catch (const std::exception & ex) {
            ma.uri = "";
        }
        
        return;
    }
    
}

int ModsecRecord::ParsRecord(const string rec) {
    
    GetAuditHeader(rec);
    
    boost::split(strs,parameters,boost::is_any_of("["));
    
    std::vector<string>::iterator i, end;
    
    for (vector<string>::const_iterator it = strs.begin(); it != strs.end(); ++it) {
        
        CheckAuditFields(*it);
    }
    
    GetClient(rec);
    
    return 1;
}

int Waf::Open() {
    
    char level[OS_HEADER_SIZE];
    
    if (!sk.Open()) return 0;
    
    if (status == 1) {
        
        if (modseclog_status == 2) {
            
            fp = fopen(modsec_log, "r");
            if(fp == NULL) {
                SysLog("failed open nginx error log file");
                return 0;
            }
            
            fseek(fp,0,SEEK_END);
            stat(modsec_log, &buf);    
            file_size = (unsigned long) buf.st_size;
    
        } else {
        
            if (modseclog_status == 1) {
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

void Waf::Close() {
    
    sk.Close();
    
    if (status == 1) {
        
        if (modseclog_status == 2) {
            if (fp != NULL) fclose(fp);
        } else redisFree(c);
    }
}

void Waf::IsFileModified() {
    
    int ret = stat(modsec_log, &buf);
    if (ret == 0) {
                
        unsigned long current_size = (unsigned long) buf.st_size;
        
        if (current_size < file_size) {
            
            if (fp != NULL) fclose(fp);
            fp = fopen(modsec_log, "r");
                        
            if (fp == NULL) return;
            else {
                
                fseek(fp,0,SEEK_SET);
                int ret = stat(modsec_log, &buf);
                
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

int Waf::ReadFile() {
    
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

int Waf::Go(void) {
    
    GrayList* gl;
    int res = 0;
    
    ClearRecords();
        
    if (status) {
        
        if (modseclog_status == 2) {
            
            res = ReadFile();
            
            if (res == -1) {
                SysLog("failed reading modsec events from log");
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
            
            if (rec.mod_rec) {
                
                if (fs.filter.waf.log ) CreateLog();
            
                if (alerts_counter <= sk.alerts_threshold) {
            
                    gl = CheckGrayList();
            
                    int severity = PushRecord(gl);
                
                    if (gl != NULL) {
                        if (gl->rsp.profile.compare("suppress") != 0) SendAlert(severity, gl);
                    } else {
                        if (fs.filter.waf.severity.threshold <= severity) {
                            
                            SendAlert(severity, NULL);
                        }
                    } 
                
                    if (sk.alerts_threshold != 0) {
            
                        if (alerts_counter < sk.alerts_threshold) alerts_counter++;
                        else {
                            SendAlertMultiple(3);
                            alerts_counter++;
                        }
                    }
                }
            } 
        } 
        if (modseclog_status == 1) freeReplyObject(reply);
    } 
    else {
        usleep(GetGosleepTimer()*60);
    }
            
    return 1;
}

GrayList* Waf::CheckGrayList() {
    
    if (fs.filter.waf.gl.size() != 0) {
        
        std::vector<GrayList*>::iterator i, end;
        
        for (i = fs.filter.waf.gl.begin(), end = fs.filter.waf.gl.end(); i != end; ++i) {
            
            int event_id = std::stoi((*i)->event);
            if (event_id == rec.ma.id) {
                
                string host = (*i)->host;
                
                if (host.compare("indef") == 0 || host.compare(rec.ma.client) == 0 || host.compare(rec.ma.hostname) == 0) {
                
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



int Waf::ParsJson() {
    
    try {
        
        if (modseclog_status == 1) jsonPayload.assign(reply->str, GetBufferSize(reply->str));
        else jsonPayload.assign(file_payload, GetBufferSize(file_payload));
        
	if ((jsonPayload.compare("") == 0)) {
            ResetStreams();
            return 0;
        }
    
	if (modseclog_status == 1) {
            ss << jsonPayload;
            bpt::read_json(ss, pt);
            jsonPayload = pt.get<string>("message","");
            event_time = pt.get<string>("@timestamp","");
        } else {
            event_time = GetGraylogFormat();
        }       
        
        if (rec.IsModsec(jsonPayload)) {
            rec.ParsRecord(jsonPayload);
            ResetStreams();
            if(SuppressAlert(rec.ma.hostname)) return 0;
                        
            return 1;
        }
    
           
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    ResetStreams();
    return 0;
}

void Waf::CreateLog() {
    
    report = "{\"version\": \"1.1\",\"host\":\"";
    report += node_id;
    report += "\",\"short_message\":\"alert-waf\"";
    report += ",\"full_message\":\"Alert from ModSecurity/NGINX\"";
    report += ",\"level\":";
    report += std::to_string(7);
    report += ",\"_type\":\"NET\"";
    report += ",\"_source\":\"Modsecurity\"";
        
    report +=  ",\"_project_id\":\"";
    report +=  fs.filter.ref_id;
			
    report +=  "\",\"_event_time\":\"";
    report +=  event_time;
    
    report += "\",\"_collected_time\":\"";
    report += GetGraylogFormat();
		
    report += "\",\"_description\":\"";
    report += rec.ma.msg;
    
    report += "\",\"_severity\":";
    report += std::to_string(rec.ma.severity);
    
    report += ",\"_sidid\":";
    report += std::to_string(rec.ma.id);
	
    report += ",\"_group_name\":\"";
    
    std::vector<string>::iterator it, end;
    int i = 0;
    for (vector<string>::const_iterator it = rec.ma.list_tags.begin(); it != rec.ma.list_tags.end(); ++it) {
        
        if (i != 0 && i < rec.ma.list_tags.size()) report += ", ";
        
        report += (*it);
        i++;
        
    }
    
    report += "\",\"_info\":\"";
    report += rec.ma.file;
    report += "\",\"_target\":\"";
    report += rec.ma.uri;
    report += "\",\"_srcip\":\"";
    report += rec.ma.client;
    report += "\",\"_dstip\":\""; 
    report += rec.ma.hostname;
    report += "\"}";
    
    q_logs_waf.push(report);
    
    report.clear();
}


int Waf::PushRecord(GrayList* gl) {
    // create new IDS record
    IdsRecord ids_rec;
            
    ids_rec.ref_id = fs.filter.ref_id;
    
    ids_rec.event = rec.ma.id;
            
    copy(rec.ma.list_tags.begin(),rec.ma.list_tags.end(),back_inserter(ids_rec.list_cats));
    
    if (rec.ma.severity < fs.filter.waf.severity.level2) {
        ids_rec.severity = 3;
    } else {
        if (rec.ma.severity < fs.filter.waf.severity.level1) {
            ids_rec.severity = 2;
        } else {
            if (rec.ma.severity < fs.filter.waf.severity.level0) {
                ids_rec.severity = 1;
            } else {
                ids_rec.severity = 0;
            }
        }
    }
    
    ids_rec.desc = rec.ma.msg;
                
    ids_rec.src_ip = rec.ma.client;
    ids_rec.dst_ip = rec.ma.hostname;
    
    ids_rec.agent = "indef";
    ids_rec.ids = sensor;
    ids_rec.action = "indef";
                
    ids_rec.location = rec.ma.uri;
    ids_rec.ids_type = 4;
    
        
    if (gl != NULL) {
        
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
            
    q_waf.push(ids_rec);
    
    return ids_rec.severity;
}


void Waf::SendAlert(int s, GrayList*  gl) {
    
    sk.alert.ref_id =  fs.filter.ref_id;
    
    if (!rec.ma.list_tags.empty())
        copy(rec.ma.list_tags.begin(),rec.ma.list_tags.end(),back_inserter(sk.alert.list_cats));
    else 
        sk.alert.list_cats.push_back("waf");
    
    sk.alert.severity = s;
    sk.alert.score = rec.ma.severity;
    sk.alert.event = rec.ma.id;
    sk.alert.action = "indef";
    sk.alert.description = rec.ma.msg;
        
    sk.alert.status = "processed_new";
    
    sk.alert.srcip = rec.ma.client;
    sk.alert.dstip = rec.ma.hostname;
        
    sk.alert.source = "Modsecurity";
    sk.alert.type = "NET";
    
    sk.alert.srcagent = "indef";
    sk.alert.dstagent = "indef";
    
    sk.alert.srcport = 0;
    sk.alert.dstport = 0;
        
    sk.alert.user = " ";
    sk.alert.sensor = sensor;
    sk.alert.filter = fs.filter.desc;
    sk.alert.event_time = event_time;
        
    sk.alert.location = rec.ma.uri;
        
    sk.alert.info = rec.ma.file;
    
    if (gl != NULL) {
            
        if (gl->rsp.profile.compare("indef") != 0) {
            sk.alert.action = gl->rsp.profile;
            sk.alert.status = "modified_new";
        } 
        
        if (gl->rsp.new_type.compare("indef") != 0) {
            sk.alert.type = gl->rsp.new_type;
            sk.alert.status = "modified_new";
        }  
        
        if (gl->rsp.new_source.compare("indef") != 0) {
            sk.alert.source = gl->rsp.new_source;
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





