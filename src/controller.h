/* 
 * File:  controller.h
 * Author: Oleg Zharkov
 */

#ifndef CONTROLLER_H
#define	CONTROLLER_H

#include <mutex>
#include <activemq/library/ActiveMQCPP.h>
#include <decaf/lang/Thread.h>
#include <decaf/lang/Runnable.h>
#include <decaf/lang/Integer.h>
#include <decaf/lang/Long.h>
#include <decaf/lang/System.h>
#include <activemq/core/ActiveMQConnectionFactory.h>
#include <activemq/util/Config.h>
#include <cms/Connection.h>
#include <cms/Session.h>
#include <cms/TextMessage.h>
#include <cms/BytesMessage.h>
#include <cms/MapMessage.h>
#include <cms/ExceptionListener.h>
#include <cms/MessageListener.h>

#include "cobject.h"

using namespace activemq::core;
using namespace decaf::util::concurrent;
using namespace decaf::util;
using namespace decaf::lang;
using namespace cms;
using namespace std;

class Controller : public CollectorObject {
    
public:
    static int mq_counter;
    static mutex m_controller;
    
    static char url[OS_HEADER_SIZE];
    static char user[OS_HEADER_SIZE];
    static char pwd[OS_HEADER_SIZE];
    static char cert[OS_HEADER_SIZE];
    static char cert_verify[OS_HEADER_SIZE];
    static char key[OS_HEADER_SIZE];
    static char key_pwd[OS_HEADER_SIZE];
            
    static Connection* connection;
    static bool ssl_broker;
    static bool ssl_client;
    static bool ssl_verify;
    static bool user_pwd;
        
    static Session* session;
    static Destination* destAlerts;
    static MessageProducer* producerAlerts;
    static Destination* destInfo;
    static MessageProducer* producerInfo;
    static bool sessionTransacted;
    static int connection_error;
    
    Controller () {
        memset(url, 0, sizeof(url));
        memset(user, 0, sizeof(user));
        memset(pwd, 0, sizeof(pwd));
        memset(cert, 0, sizeof(cert));
        memset(cert_verify, 0, sizeof(cert_verify));
        memset(key, 0, sizeof(key));
        memset(key_pwd, 0, sizeof(key_pwd));
                
        session = NULL;
        destAlerts = NULL;
        producerAlerts = NULL;
        destInfo = NULL;
        producerInfo = NULL;
    }
     
    virtual int Open();
    virtual int GetConfig();
    void CheckStatus();
    int SendMessage(Event* e);
    virtual void Close();
    
};



#endif	/* CONTROLLER_H */

