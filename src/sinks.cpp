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

#include "sinks.h"


int Sinks::config_flag = 0;

char Sinks::redis_host[OS_HEADER_SIZE];
long Sinks::redis_port;

int Sinks::ctrl_error_counter = 0;

int Sinks::alerts_threshold = 0;

int Sinks::reports_period = 0;

int Sinks::update_period = 0;

LocLog Sinks::persist;

int Sinks::GetConfig() {
    
    char logtype[PORT_SIZE];
    
    if (config_flag == 0) {
        config_flag = 1; 
        
        if (!CollectorObject::GetConfig()) return 0; 
        
        int ctrl_state = ctrl.GetConfig();
        if(ctrl_state == 0) return 0;
    
        ConfigYaml* cy = new ConfigYaml( "collector");
    
        cy->addKey("timer_report");
        cy->addKey("timer_update");
        cy->addKey("alerts_threshold");
        cy->addKey("redis_host");
        cy->addKey("redis_port");
                
        cy->ParsConfig();
        
        reports_period = stoi(cy->getParameter("timer_report"));
        if (!reports_period) {
            SysLog("config file: sending reports to controller disabled");
        }
        
        update_period = stoi(cy->getParameter("timer_update"));
        if (!update_period) {
            SysLog("config file: update tasks are disabled");
        }
        
        alerts_threshold = stoi(cy->getParameter("alerts_threshold"));
        
        strncpy(redis_host, (char*) cy->getParameter("redis_host").c_str(), sizeof(redis_host));
        
        redis_port = stoi(cy->getParameter("redis_port"));
    }
        
    return 1;
}


int Sinks::Open() {
    
    if(!ctrl.Open()) return 0;
    
    return 1;
}


void Sinks::Close() {
    
    persist.Close();
    ctrl.Close();
}


int Sinks::SendMessage(Event* e) { 
    
    if (!ctrl.SendMessage(e)) {
       return 0;
    }
    return 1;
}

void Sinks::SendAlert(void) {
    
    alert.CreateAlertUUID();
    
    if (!SendMessage(&alert)) {
        
        stringstream al;
    
        al << "{\"alert\": {";
        
        al << "\"time_of_event\":";
        al << GetNodeTime();
        
        al << "\",\"agent\": \"";
        al << alert.agent_name;
        
        al << "\",\"source\": \"";
        al << alert.alert_source;
        
        al << "\",\"type\": \"";
        al << alert.alert_type;
        
        al << "\",\"event\": ";
        al << alert.event_id;
        
        al << ",\"severity\": ";
        al << alert.alert_severity;
        
        al << ",\"description\": \"";
        al << alert.description;
        
        al << "\",\"category\": \"";
        char cat_string[OS_STRING_SIZE];
        int j = 0;
        for (string i : alert.list_cats) {
            if ( j < alert.list_cats.size() - 1) i = i + ", ";
            if (j == 0) strncpy (cat_string, i.c_str(), i.size() + 1);
            else strncat (cat_string, i.c_str(), i.size() + 1);
            
            j++;    
        }
        string strEventCat(cat_string);
        al << strEventCat;
        
        al << "\",\"src_ip\": \"";
        al << alert.src_ip;
        
        al << "\",\"dst_ip\": \"";
        al << alert.dst_ip;
        
        al << "\",\"location\": \"";
        al << alert.location;
                
        al << "\",\"action\": \"";
        al << alert.action;
        
        al << "\",\"status\": \"";
        al << alert.status;
        
        al << "\",\"info\": \"";
        al << alert.info;
        
        al << "\"}}";
        
        persist.WriteLog(al.str());    
        
    }
        
    alert.Reset();
}







