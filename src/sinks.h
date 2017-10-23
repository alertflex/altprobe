/* 
 * File:   sinks.h
 * Author: Oleg Zharkov
 *
 */

#ifndef SINKS_H
#define	SINKS_H

#include "filelog.h"
#include "controller.h"
#include "config.h"


class Sinks : public CollectorObject {
public:
    static int config_flag;
    
    static int persist_state;
    static int ctrl_state;
    
    static int reports_period;
    
    static int persist_threshold;
    static int ctrl_error_counter;
    
    // Local log operations
    static FileLog persist;
    
    // Controller operations
    Controller ctrl;
    
    Alert alert;
    
    void Init() {
        alert.SetEventType(et_alert);
        alert.Reset();
    }
    
    int Open();
    void Close();
    
    virtual int GetConfig();
    
    int GetStateCtrl() { 
        return ctrl_state;
    }
    
    
    
    int GetReportsPeriod() { 
        if (GetStateCtrl() != 0) return reports_period; 
        return 0;
    };
    
    void SendMessage(Event* e);
    
    //Send Alert to Controller
    void SendAlert(void);
    
    static int GetStatePersist() { 
        return persist_state; 
    }
    
    static void SetStatePersist(int s) { 
        persist_state = s; 
    }
    
    static void CtrlErrorCounter(void);
};

#endif	/* SINKS_H */

