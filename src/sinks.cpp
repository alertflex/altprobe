/* 
 * File:   sinks.h
 * Author: Oleg Zharkov
 *
 */

#include "sinks.h"

int Sinks::config_flag = 0;

int Sinks::ctrl_state = 1;
int Sinks::ctrl_error_counter = 0;

int Sinks::persist_state = 0;
int Sinks::persist_threshold = 0;

int Sinks::reports_period = 0;

FileLog Sinks::persist;

std::mutex persist_lock;

int Sinks::GetConfig() {
    
    if (config_flag == 0) {
        config_flag = 1; 
        
        if (!CollectorObject::GetConfig()) return 0; 
        
        ctrl_state = ctrl.GetConfig();
        if(ctrl_state == 0) return 0;
    
        ConfigYaml* cy = new ConfigYaml( "collector");
    
        cy->addKey("report_timer");
        cy->addKey("persist_threshold");
        
        cy->ParsConfig();
        
        reports_period = stoi(cy->getParameter("report_timer"));
        
        persist_threshold = stoi(cy->getParameter("persist_threshold"));
        
     }
        
    return 1;
}


int Sinks::Open() {
    if(GetStateCtrl() == 1) 
        if(!ctrl.Open()) return 0;
    
    return 1;
}


void Sinks::Close() {
    
    if(persist_state == 1) {
        persist.Close();
    }
    
    ctrl.Close();
}


void Sinks::SendMessage(Event* e) { 
        
    if (!ctrl.SendMessage(e)) CtrlErrorCounter();
}

void Sinks::SendAlert(void) {
    
    alert.CreateAlertUUID();
    
    int res = ctrl.SendMessage(&alert);
        
    if (!res) CtrlErrorCounter();
        
    alert.Reset();
}


void Sinks::CtrlErrorCounter(void) {
    
    std::lock_guard<std::mutex> lock(persist_lock);
    
    if (ctrl_state != 0) {
    
        if ((persist_threshold > 0) && (ctrl_error_counter > persist_threshold)) {
            SysLog("Connection to controller is closed, because error counter limit has been reached");
            ctrl_state = 0;
            if(persist.Open()) {
                persist_state = 1;
                SysLog("Collector starts to persist logs to local file");
            }
            else SysLog("Collector error, cannot open a local file for persisting of logs");
        }
        else {
            SysLog("Communication error of sending data to controller");
            ctrl_error_counter++; 
        }
    }
}


