/* 
 * File:   sinks.h
 * Author: Oleg Zharkov
 *
 */

#include "sinks.h"


int Sinks::config_flag = 0;

char Sinks::redis_host[OS_HEADER_SIZE];
long Sinks::redis_port;

int Sinks::ctrl_error_counter = 0;

int Sinks::alerts_threshold = 0;

int Sinks::reports_period = 0;

LocLog Sinks::persist;

int Sinks::GetConfig() {
    
    char logtype[PORT_SIZE];
    
    if (config_flag == 0) {
        config_flag = 1; 
        
        if (!CollectorObject::GetConfig()) return 0; 
        
        int ctrl_state = ctrl.GetConfig();
        if(ctrl_state == 0) return 0;
    
        ConfigYaml* cy = new ConfigYaml( "collector");
    
        cy->addKey("report_timer");
        cy->addKey("alerts_threshold");
        cy->addKey("redis_host");
        cy->addKey("redis_port");
                
        cy->ParsConfig();
        
        reports_period = stoi(cy->getParameter("report_timer"));
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
    bool res = true;
    
    if (ctrl_error_counter > 0) res = ctrl.Reset();
    
    if (res) {
        if (!ctrl.SendMessage(e)) {
            if (ctrl_error_counter == 0) SysLog("Error of sending alert to controller");
            ctrl_error_counter++;
            return 0;
        } else ctrl_error_counter = 0;
        
        return 1;
    }
    
    return 0;
}

void Sinks::SendAlert(void) {
    
    alert.CreateAlertUUID();
    
    if (!SendMessage(&alert)) {
        
        stringstream al;
    
        al << "{\"alert\": {";
        
        al << "\"time_of_event\":";
        al << GetNodeTime();
        
        al << "\",\"agent\": \"";
        al << alert.hostname;
        
        al << "\",\"source\": \"";
        al << alert.source;
        
        al << "\",\"type\": \"";
        al << alert.type;
        
        al << "\",\"event\": ";
        al << alert.event;
        
        al << ",\"severity\": ";
        al << alert.severity;
        
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
        
        al << "\",\"srcip\": \"";
        al << alert.srcip;
        
        al << "\",\"dstip\": \"";
        al << alert.dstip;
        
        al << "\",\"location\": \"";
        al << alert.location;
                
        al << "\",\"action\": \"";
        al << alert.action;
        
        al << "\",\"status\": \"";
        al << alert.status;
        
        al << "\",\"info\": \"";
        al << alert.info;
        
        al << "\",\"event_json\": \"";
        al << alert.event_json;
        
        al << "\"}}";
        
        
        persist.WriteLog(al.str());    
        
    }
        
    alert.Reset();
}







