/* 
 * File:  controller.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */
#include <mutex>
#include <activemq-cpp-3.10.0/cms/Message.h>

#include "controller.h"

int Controller::mq_counter = 0;
mutex Controller::m_controller;

char Controller::url[OS_HEADER_SIZE];
char Controller::cert[OS_HEADER_SIZE];
char Controller::key[OS_HEADER_SIZE];
char Controller::pwd[OS_HEADER_SIZE];
char Controller::path[OS_HEADER_SIZE];

Connection* Controller::connection = NULL;
bool Controller::ssl = true;

int Controller::GetConfig() {
       
    ConfigYaml* cy = new ConfigYaml( "controller");
    
    cy->addKey("amq");
    cy->addKey("key");
    cy->addKey("cert");
    cy->addKey("pwd");
    cy->addKey("path");
    
    cy->ParsConfig();
    
    strncpy(url, (char*) cy->getParameter("amq").c_str(), sizeof(url));
    if (!strcmp (url, "none")) { 
        SysLog("config file notification: ActiveMQ interface is disabled");
        return 0;
    }
    
    if (!strcmp (url, "")) { 
        SysLog("config file error: parameter controller amq");
        return 0;
    }
    
    strncpy(path, (char*) cy->getParameter("path").c_str(), sizeof(path));
    if (!strcmp (path, "")) {
        SysLog("config file error: parameter controller path");
        return 0;
    }
    
    strncpy(key, (char*) cy->getParameter("key").c_str(), sizeof(key));
    
    if (!strcmp (key, "")) {
        SysLog("config file error: parameter controller key");
        return 0;
    }
    
    if (!strcmp (key, "none")) {
        ssl = false;
        return 1;
    }
    
    strncpy(cert, (char*) cy->getParameter("cert").c_str(), sizeof(cert));
    if (!strcmp (cert, "")) {
        SysLog("config file error: parameter controller cert");
        return 0;
    }
    
    if (!strcmp (cert, "none")) {
        ssl = false;
        return 1;
    }
    
    strncpy(pwd, (char*) cy->getParameter("pwd").c_str(), sizeof(pwd));
    
    if (!strcmp (pwd, "")) {
        SysLog("config file error: parameter controller pwd");
        return 0;
    }
    
    if (!strcmp (pwd, "none")) {
        ssl = false;
        return 1;
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
                
                if (ssl) {
                    decaf::lang::System::setProperty( "decaf.net.ssl.trustStore", cert );
                    decaf::lang::System::setProperty("decaf.net.ssl.keyStore", key); 
                    decaf::lang::System::setProperty("decaf.net.ssl.keyStorePassword", pwd); 
                }
                
                // Create a ConnectionFactory
                string strUrl(url);
            
                auto_ptr<ConnectionFactory> connectionFactory(
                    ConnectionFactory::createCMSConnectionFactory(strUrl));
            
                // Create a Connection
                connection = connectionFactory->createConnection();
                connection->start();
            }
        
            // Create a Session
            if (this->sessionTransacted) {
                session = connection->createSession(Session::SESSION_TRANSACTED);
            } else {
                session = connection->createSession(Session::AUTO_ACKNOWLEDGE);
            }
            
            // Create the destination (Topic or Queue)
            string strQueue(path);
            
            strQueue = strQueue + "controller";
            
            destination = session->createQueue(strQueue);
                        
            // Create a MessageProducer from the Session to the Topic or Queue
            producer = session->createProducer(destination);
       
            producer->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
        
            mq_counter++;
        
            amq_conn = true;
                 
        } catch (CMSException& e) {
        
            if (conn_attempts > 20) {
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
        
        if (!msg_type) {
            
            // Create an alert
            string strMsg("Collector message");
            auto_ptr<TextMessage> message(session->createTextMessage(strMsg));
            
            string strProbeId(node_id);
            message->setStringProperty("node_id", strProbeId);
            
            message->setIntProperty("msg_type", 1);
                
            string strAlertUuid(((Alert*) e)->alert_uuid);
            message->setStringProperty("alert_uuid", strAlertUuid);
                
            string strRefId(((Alert*) e)->ref_id);
            message->setStringProperty("ref_id", strRefId);
                
            string strSource(((Alert*) e)->source);
            message->setStringProperty("source", strSource);
                
            string strType(((Alert*) e)->type);
            message->setStringProperty("type", strType);
                                
            message->setIntProperty("event", ((Alert*) e)->event);
                    
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
            
            string strEventJson(((Alert*) e)->event_json);
            message->setStringProperty("event_json", strEventJson);  
            
            producer->send(message.get());
            
                    
        }  else {
            
            // Create a stats or logs
            BytesMessage* byte_message = session->createBytesMessage();
                
            string strNodeId(node_id);
            byte_message->setStringProperty("node_id", strNodeId);
            byte_message->setStringProperty("ref_id", "nsm_solution");
            byte_message->setIntProperty("msg_type", msg_type);
                
            vector<unsigned char> vec;
            string msg_comp = ((BinData*) e)->data;
            const char* c = msg_comp.c_str();
            for (int i=0; i < msg_comp.size() + 1; i++) vec.push_back(c[i]);
                
            byte_message->writeBytes(vec);
            producer->send(byte_message);
                                    
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
                
            if (destination != NULL) {
                delete destination;
                destination = NULL;
            }
        
            if (producer != NULL) {
                delete producer;
                producer = NULL;
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
            
                auto_ptr<ConnectionFactory> connectionFactory(
                    ConnectionFactory::createCMSConnectionFactory(strUrl));
                
                connection = connectionFactory->createConnection();
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
            
            if (destination == NULL) {
                // Create the destination (Topic or Queue)
                string strQueue(path);
            
                strQueue = strQueue + "controller";
            
                destination = session->createQueue(strQueue);
            }
            
            if (producer == NULL) {
                        
                // Create a MessageProducer from the Session to the Topic or Queue
                producer = session->createProducer(destination);
       
                producer->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
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
        delete destination;
        destination = NULL;
        
        if (producer) {
            delete producer;
            producer = NULL;
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




