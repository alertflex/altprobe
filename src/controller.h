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
    static char cert[OS_HEADER_SIZE];
    static char key[OS_HEADER_SIZE];
    static char pwd[OS_HEADER_SIZE];
    static char path[OS_HEADER_SIZE];
    
    static Connection* connection;
    static bool ssl;
    
    Session* session;
    Destination* destination;
    MessageProducer* producer;
    bool sessionTransacted;
    bool connection_status;
    
    Controller () {
        memset(url, 0, sizeof(url));
        memset(cert, 0, sizeof(cert));
        memset(key, 0, sizeof(key));
        memset(pwd, 0, sizeof(pwd));
        memset(path, 0, sizeof(path));
        
        session = NULL;
        destination = NULL;
        producer = NULL;
        sessionTransacted = false;
        connection_status = false;
    }
     
    virtual int Open();
    virtual bool Reset();
    virtual int GetConfig();
    int SendMessage(Event* e);
    virtual void Close();
    
};



#endif	/* CONTROLLER_H */

