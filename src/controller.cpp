/* 
 * File:  controller.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */
#include <mutex>
#include <activemq-cpp-3.9.5/cms/Message.h>

#include "controller.h"

int Controller::mq_counter = 0;
mutex Controller::m_controller;

char Controller::url[OS_HEADER_SIZE];
char Controller::user[OS_HEADER_SIZE];
char Controller::pwd[OS_HEADER_SIZE];
char Controller::cert[OS_HEADER_SIZE];
char Controller::cert_verify[OS_HEADER_SIZE];
char Controller::key[OS_HEADER_SIZE];
char Controller::key_pwd[OS_HEADER_SIZE];

Connection* Controller::connection = NULL;
bool Controller::ssl_broker = true;
bool Controller::ssl_client = true;
bool Controller::ssl_verify = true;
bool Controller::user_pwd = true;

Session* Controller::session;
Destination* Controller::destAlerts;
MessageProducer* Controller::producerAlerts;
Destination* Controller::destInfo;
MessageProducer* Controller::producerInfo;
bool Controller::sessionTransacted;
bool Controller::connection_status;

int Controller::GetConfig() {
       
    ConfigYaml* cy = new ConfigYaml( "controller");
    
    cy->addKey("url");
    cy->addKey("user");
    cy->addKey("pwd");
    cy->addKey("cert");
    cy->addKey("cert_verify");
    cy->addKey("key");
    cy->addKey("key_pwd");
    
    
    cy->ParsConfig();
    
    strncpy(url, (char*) cy->getParameter("url").c_str(), sizeof(url));
    if (!strcmp (url, "indef")) { 
        SysLog("config file notification: ActiveMQ interface is disabled");
        return 0;
    }
    
    if (!strcmp (url, "")) { 
        SysLog("config file error: parameter controller url");
        return 0;
    }
    
    strncpy(user, (char*) cy->getParameter("user").c_str(), sizeof(user));
    
    if (!strcmp (user, "")) {
        SysLog("config file error: parameter controller user");
        return 0;
    }
    
    if (!strcmp (user, "indef")) {
        user_pwd = false;
    }
    
    strncpy(pwd, (char*) cy->getParameter("pwd").c_str(), sizeof(pwd));
    
    if (!strcmp (pwd, "")) {
        SysLog("config file error: parameter controller pwd");
        return 0;
    }
    
    strncpy(cert, (char*) cy->getParameter("cert").c_str(), sizeof(cert));
    if (!strcmp (cert, "")) {
        SysLog("config file error: parameter controller cert");
        return 0;
    }
    
    if (!strcmp (cert, "indef")) {
        ssl_broker = false;
    }
    
    strncpy(cert_verify, (char*) cy->getParameter("cert_verify").c_str(), sizeof(cert_verify));
    if (!strcmp (cert_verify, "")) {
        SysLog("config file error: parameter controller cert_verify");
        return 0;
    }
    
    if (!strcmp (cert_verify, "false")) {
        ssl_verify = false;
    }
    
    
    strncpy(key, (char*) cy->getParameter("key").c_str(), sizeof(key));
    if (!strcmp (key, "")) {
        SysLog("config file error: parameter controller key");
        return 0;
    }
    
    if (!strcmp (key, "indef")) {
        ssl_client = false;
    }
    
    strncpy(key_pwd, (char*) cy->getParameter("key_pwd").c_str(), sizeof(key_pwd));
    if (!strcmp (key_pwd, "")) {
        SysLog("config file error: parameter controller key_pwd");
        return 0;
    }
    
    if (!strcmp (key_pwd, "indef")) {
        ssl_client = false;
    }
    
       
    return 1;
}

int Controller::Open() {
    
    bool amq_conn = false;
    int conn_attempts = 0;
    
    do {
        try {
            if (connection == NULL) {
                
                activemq::library::ActiveMQCPP::initializeLibrary();
                
                if (ssl_broker) {
                    
                    decaf::lang::System::setProperty( "decaf.net.ssl.trustStore", cert );
                    
                    if (!ssl_verify) {
                        decaf::lang::System::setProperty("decaf.net.ssl.disablePeerVerification", "true");
                    }
                    
                } 
                
                if (ssl_client) {
                    decaf::lang::System::setProperty("decaf.net.ssl.keyStore", key); 
                    decaf::lang::System::setProperty("decaf.net.ssl.keyStorePassword", key_pwd); 
                } 
                
                // Create a ConnectionFactory
                string strUrl(url);
            
                auto_ptr<ConnectionFactory> connectionFactory(
                    ConnectionFactory::createCMSConnectionFactory(strUrl));
            
                // Create a Connection
                if (user_pwd) {
                    connection = connectionFactory->createConnection(user,pwd);
                } else {
                    connection = connectionFactory->createConnection();
                }
                
                connection->start();
                
            }
            
            if (session == NULL) {
        
                // Create a Session
                if (this->sessionTransacted) {
                    session = connection->createSession(Session::SESSION_TRANSACTED);
                } else {
                    session = connection->createSession(Session::AUTO_ACKNOWLEDGE);
                }
            }
            
            if (producerAlerts == NULL) {
            
                // Create the destination for alerts
                string strAlerts("jms/alertflex/alerts");
            
                destAlerts = session->createQueue(strAlerts);
                        
                // Create a MessageProducer from the Session to Queue
                producerAlerts = session->createProducer(destAlerts);
       
                producerAlerts->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
            }
            
            if (producerInfo == NULL) {
            
                // Create the destination for statistics(Queue)
                string strInfo("jms/alertflex/info");
            
                destInfo = session->createQueue(strInfo);
                        
                // Create a MessageProducer from the Session to Queue
                producerInfo = session->createProducer(destInfo);
       
                producerInfo->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
            }
        
            mq_counter++;
        
            amq_conn = true;
                 
        } catch (CMSException& e) {
        
            if (conn_attempts > 10) {
                SysLog("activeMQ operation error");
                string str = e.getMessage();
                const char * c = str.c_str();
                SysLog((char*) c);
                return 0;
            }
            sleep(3);
            conn_attempts++;
        }
        
    } while (!amq_conn);
    
    connection_status = true;
    return 1;
}


int Controller::SendMessage(Event* e) {
    
    int msg_type = e->event_type;
    
    try {
        
        if (msg_type == 0) {
            
            // Create an alert
            string strEventJson(((Alert*) e)->event_json);
            auto_ptr<TextMessage> message(session->createTextMessage(strEventJson));
            
            string strProbeId(node_id);
            message->setStringProperty("node_id", strProbeId);
            
            message->setIntProperty("msg_type", 0);
                
            string strAlertUuid(((Alert*) e)->alert_uuid);
            message->setStringProperty("alert_uuid", strAlertUuid);
                
            string strRefId(((Alert*) e)->ref_id);
            message->setStringProperty("ref_id", strRefId);
                
            string strSource(((Alert*) e)->source);
            message->setStringProperty("source", strSource);
                
            string strType(((Alert*) e)->type);
            message->setStringProperty("type", strType);
            
            string strEvent(((Alert*) e)->event);
            message->setStringProperty("event", strEvent);
                    
            message->setIntProperty("severity", ((Alert*) e)->severity);
            
            message->setIntProperty("score", ((Alert*) e)->score);
                    
            char cat_string[OS_STRING_SIZE];
        
            int j = 0;
            for (string i : ((Alert*) e)->list_cats) {
                if ( j < ((Alert*) e)->list_cats.size() - 1) i = i + ", ";
                if (j == 0) strncpy (cat_string, i.c_str(), i.size() + 1);
                else strncat (cat_string, i.c_str(), i.size() + 1);
            
                j++;    
            }
                
            string strEventCat(cat_string);
            message->setStringProperty("category", strEventCat);
                    
            string strEventDetails(((Alert*) e)->description);
            message->setStringProperty("description", strEventDetails);
                
            string strSrcip(((Alert*) e)->srcip);
            message->setStringProperty("srcip", strSrcip);
                
            string strDstip(((Alert*) e)->dstip);
            message->setStringProperty("dstip", strDstip);
            
            string strSrcagent(((Alert*) e)->srcagent);
            message->setStringProperty("srcagent", strSrcagent);
                
            string strDstagent(((Alert*) e)->dstagent);
            message->setStringProperty("dstagent", strDstagent);
            
            message->setIntProperty("srcport", ((Alert*) e)->srcport);
            
            message->setIntProperty("dstport", ((Alert*) e)->dstport);
			
            string strUser(((Alert*) e)->user);
            message->setStringProperty("user", strUser);
            
            string strAgent(((Alert*) e)->agent);
            message->setStringProperty("agent", strAgent);
            
            string strContainer(((Alert*) e)->container);
            message->setStringProperty("container", strContainer);
            
            string strProcess(((Alert*) e)->process);
            message->setStringProperty("process", strProcess);
            
            string strFile(((Alert*) e)->file);
            message->setStringProperty("file", strFile);
            
            string strSensor(((Alert*) e)->sensor);
            message->setStringProperty("sensor", strSensor);
                
            string strLoc(((Alert*) e)->location);
            message->setStringProperty("location", strLoc);
                
            string strAct(((Alert*) e)->action);
            message->setStringProperty("action", strAct);
                
            string strStatus(((Alert*) e)->status);
            message->setStringProperty("status", strStatus);
            
            string strFilter(((Alert*) e)->filter);
            message->setStringProperty("filter", strFilter);
            
            string strInfo(((Alert*) e)->info);
            message->setStringProperty("info", strInfo);
            
            string strEventTime(((Alert*) e)->event_time);
            message->setStringProperty("event_time", strEventTime);
            
            message->setStringProperty("collr_time", GetNodeTime());
            
            producerAlerts->send(message.get());
            
                    
        }  else {
            
            // Create a stats or logs
            BytesMessage* byte_message = session->createBytesMessage();
                
            string strNodeId(node_id);
            byte_message->setStringProperty("node_id", strNodeId);
            byte_message->setStringProperty("ref_id", e->ref_id);
            byte_message->setIntProperty("msg_type", msg_type);
            
            switch (msg_type) {
                case 4 :
                    byte_message->setStringProperty("sensor", sensor_id + "-crs");
                    break;
                case 5 :
                    byte_message->setStringProperty("sensor", sensor_id + "-hids");
                    break;
                case 6 :
                    byte_message->setStringProperty("sensor", sensor_id + "-nids");
                    break;
                case 7 :
                    byte_message->setStringProperty("sensor", sensor_id + "-waf");
                    break;
                case 8 :
                    byte_message->setStringProperty("sensor", sensor_id + "-crs");
                    byte_message->setStringProperty("rule", ((Rule*) e)->name_rule);
                    break;
                case 9 :
                    byte_message->setStringProperty("sensor", sensor_id + "-hids");
                    byte_message->setStringProperty("rule", ((Rule*) e)->name_rule);
                    break;
                case 10 :
                    byte_message->setStringProperty("sensor", sensor_id + "-nids");
                    byte_message->setStringProperty("rule", ((Rule*) e)->name_rule);
                    break;
                case 11 :
                    byte_message->setStringProperty("sensor", sensor_id + "-waf");
                    byte_message->setStringProperty("rule", ((Rule*) e)->name_rule);
                    break;
                default:
                    break;
            }
            
            vector<unsigned char> vec;
            string msg_comp = ((BinData*) e)->data;
            const char* c = msg_comp.c_str();
            for (int i=0; i < msg_comp.size() + 1; i++) vec.push_back(c[i]);
                
            byte_message->writeBytes(vec);
            
            producerInfo->send(byte_message);
                                    
            delete byte_message;
        }
        
        
    } catch (CMSException& e) {
        SysLog("ActiveMQ CMS Exception occurred.");
        return 0;
    }
        
    return 1;
}

bool Controller::Reset() {
    
    try {
        
        if (connection_status) {
                
            if (connection != NULL) {
                connection->close();
                connection = NULL;
            }
                
            if (destAlerts != NULL) {
                delete destAlerts;
                destAlerts = NULL;
            }
            
            if (destInfo != NULL) {
                delete destInfo;
                destInfo = NULL;
            }
        
            if (producerAlerts != NULL) {
                delete producerAlerts;
                producerAlerts = NULL;
            }
            
            if (producerInfo != NULL) {
                delete producerInfo;
                producerInfo = NULL;
            }
                
            if (session != NULL) {
                delete session;
                session = NULL;
            }
                
            connection_status = false;
        }
            
        if (!connection_status) {
            
            if (connection == NULL) {
                
                // Create a ConnectionFactory
                string strUrl(url);
            
                unique_ptr<ConnectionFactory> connectionFactory(
                    ConnectionFactory::createCMSConnectionFactory(strUrl));
            
                // Create a Connection
                if (user_pwd) {
                    connection = connectionFactory->createConnection(user,pwd);
                } else {
                    connection = connectionFactory->createConnection();
                }
                
                connection->start();
            }
            
            if (session == NULL) {
        
                // Create a Session
                if (this->sessionTransacted) {
                    session = connection->createSession(Session::SESSION_TRANSACTED);
                } else {
                    session = connection->createSession(Session::AUTO_ACKNOWLEDGE);
                }
            }
            
            if (destAlerts == NULL) {
                // Create the destination for alerts
                string strAlerts("jms/alertflex/alerts");
            
                destAlerts = session->createTopic(strAlerts);
            }
            
            if (producerAlerts == NULL) {
                // Create a MessageProducer from the Session to the Queue
                producerAlerts = session->createProducer(destAlerts);
       
                producerAlerts->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
            }
            
            if (destInfo == NULL) {
                // Create the destination for statistics(Queue)
                string strInfo("jms/alertflex/info");
            
                destInfo = session->createQueue(strInfo);
            }
            
            if (producerInfo == NULL) {
                // Create a MessageProducer from the Session to the Queue
                producerInfo = session->createProducer(destInfo);
       
                producerInfo->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
            }
                       
            connection_status = true;
        }
        
    } catch (CMSException& e) {
        SysLog("activeMQ operation error: reset");
        string str = e.getMessage();
        const char * c = str.c_str();
        SysLog((char*) c);
    }
    
    return connection_status;
}

void Controller::Close() {
 
    if (connection != NULL) {
        try {
            connection->close();
            
        } catch (cms::CMSException& ex) {
            SysLog("activeMQ operation error: connection close");
        }
    }
 
    // Destroy resources.
    try {
        delete destAlerts;
        destAlerts = NULL;
        
        if (producerAlerts) {
            delete producerAlerts;
            producerAlerts = NULL;
        }
        
        delete destInfo;
        destInfo = NULL;
        
        if (producerInfo) {
            delete producerInfo;
            producerInfo = NULL;
        }
        
        delete session;
        session = NULL;
        
        m_controller.lock();
        mq_counter--;
        m_controller.unlock();
        
        if (mq_counter == 0) {
            delete connection;
            connection = NULL;
        }
        
    } catch (CMSException& e) {
        SysLog("activeMQ operation error: destroy resources");
    }
}




