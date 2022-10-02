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
    static int altprobe_mode;
    static pid_t p_pid;
    
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
    int SendAgentInfo(string ref, string node, string agent, string json);
    virtual void Close();
    
};



#endif	/* CONTROLLER_H */

