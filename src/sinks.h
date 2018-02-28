/* 
 * File:   sinks.h
 * Author: Oleg Zharkov
 *
 */

#ifndef SINKS_H
#define	SINKS_H

#include "controller.h"
#include "config.h"
#include "loclog.h"

class Sinks : public CollectorObject {
public:
    static int config_flag;
    
    static int reports_period;
    
    static int alerts_threshold;
    
    static int ctrl_error_counter;
    
    // Redis config parameters
    static char redis_host[OS_HEADER_SIZE];
    static long int redis_port;
    
    // Local log operations
    static LocLog persist;
        
    // Controller operations
    Controller ctrl;
    
    Alert alert;
    
    void Init() {
        alert.Reset();
    }
    
    int Open();
    void Close();
    
    virtual int GetConfig();
    
    int GetReportsPeriod() { 
        return reports_period; 
    };
    
    int SendMessage(Event* e);
    
    //Send Alert to Controller
    void SendAlert(void);
    
    static void CtrlErrorCounter(void);
};


#endif	/* SINKS_H */

