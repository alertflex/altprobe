/* 
 * File:   hids.cpp
 * Author: Oleg Zharkov
 *
 * Created on May 26, 2014, 10:43 AM
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
    
    if (status == 1) {
        
        if (falcolog_status == 2) {
            
            fp = fopen(falco_log, "r");
            if(fp == NULL) {
                SysLog("failed open falco log file");
                return 0;
            }
            
            fseek(fp,0,SEEK_END);
            stat(falco_log, &buf);    
            file_size = (unsigned long) buf.st_size;
      
        } else {
        
            if (falcolog_status == 1) {
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

void Crs::Close() {
    
    sk.Close();
    
    if (status == 1) {
        
        if (falcolog_status == 2) {
            if (fp != NULL) fclose(fp);
        } else redisFree(c);
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
        
        if (falcolog_status == 2) {
            
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
        
        if (falcolog_status == 1) freeReplyObject(reply);
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
                
                if (container.compare("all") == 0 || container.compare(rec.fields.container_id) == 0 || container.compare(rec.fields.container_name) == 0) {
                
                    return (*i);
                }
            }
        }
    }
    
    return NULL;
}

int Crs::ParsJson() {
    
    string message;
    
    try {
    
        if (falcolog_status == 1) {
            
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
    
    
    rec.output = pt.get<string>("output","");
    
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
    
    rec.fields.fd_name = pt.get<string>("output_fields.fd.name","");
        
    rec.fields.proc_cmdline = pt.get<string>("output_fields.proc.cmdline","");
    
    rec.fields.proc_name = pt.get<string>("output_fields.proc.name","");
    
    rec.fields.user_name = pt.get<string>("output_fields.user.name","");
    
    rec.fields.container_id = pt.get<string>("output_fields.container.id","");
    
    rec.fields.container_name = pt.get<string>("output_fields.container.name","");
    
    ResetStreams();
    
    return 1;
}

void Crs::CreateLog() {
    
    
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
    if (falcolog_status == 1) ids_rec.ids = rec.sensor;
    else ids_rec.ids = sensor;
    ids_rec.action = "indef";
    ids_rec.ids_type = 5;
                
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
                
    q_crs.push(ids_rec);
    
    return ids_rec.severity;
}

void Crs::SendAlert(int s, GrayList*  gl) {
    
    sk.alert.ref_id =  fs.filter.ref_id;
    
    sk.alert.list_cats.push_back("falco");
        
    sk.alert.severity = s;
    sk.alert.score = rec.level;
    sk.alert.event = rec.rule;
    sk.alert.action = "indef";
    sk.alert.description = rec.output;
        
    sk.alert.status = "processed_new";
            
    sk.alert.srcip = "";
    sk.alert.dstip = "";
    
    sk.alert.srcagent = "indef";
    sk.alert.dstagent = "indef";
    
    sk.alert.srcport = 0;
    sk.alert.dstport = 0;
        
    sk.alert.source = "Falco";
    
    sk.alert.user = rec.fields.user_name;
    
    if (falcolog_status == 1) sk.alert.sensor = rec.sensor;
    else sk.alert.sensor = sensor;
    
    sk.alert.filter = fs.filter.desc;
    sk.alert.event_time = rec.timestamp;
        
    sk.alert.type = "HOST";
            
    sk.alert.location = "";
    sk.alert.info = rec.rule;
        
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

    
