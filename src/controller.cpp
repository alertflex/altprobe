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
 
#include <mutex>
#include <activemq-cpp-3.9.5/cms/Message.h>

#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <libdaemon/dexec.h>

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
Destination* Controller::destResponse;
MessageProducer* Controller::producerResponse;
bool Controller::sessionTransacted = false;

int Controller::connection_error = 0;
int Controller::altprobe_mode = 1;
pid_t Controller::p_pid = 0;

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

void Controller::CheckStatus() {
    
    connection_error++;
    
    if (connection_error > 100) {
        
        if (altprobe_mode == 1) {
            if (daemon_pid_file_kill_wait(SIGTERM, 5) < 0)
                // daemon_log(LOG_ERR, "Failed to kill AlertFlex collector: %s.", strerror(errno));
                SysLog( "Failed to kill alertflex collector, controller/sensors/update modules.");
                // else daemon_log(LOG_ERR, "AlertFlex collector is stopping.");
            else SysLog( "Alertflex collector is stopping, controller/sensors/update modules.");
        } else {
            kill(p_pid, SIGTERM); 
            SysLog( "Alertflex collector is stopping, controller/sensors/update modules.");
        }
        
    }
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
            
            if (producerResponse == NULL) {
            
                // Create the destination for statistics(Queue)
                string strResponse("jms/altprobe/" + node_id + "/" + probe_id + "/response");
            
                destResponse = session->createTopic(strResponse);
                        
                // Create a MessageProducer from the Session to Queue
                producerResponse = session->createProducer(destResponse);
       
                producerResponse->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
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
    
    return 1;
}


int Controller::SendMessage(Event* e) {
    
    int msg_type = e->event_type;
    
    try {
        
        if (msg_type == 0) {
            
            // Create an alert
            auto_ptr<TextMessage> message(session->createTextMessage());
            
            message->setIntProperty("msg_type", 1);
            
            string strRefId(((Alert*) e)->ref_id);
            message->setStringProperty("ref_id", strRefId);
            
            string strNodeId(node_id);
            message->setStringProperty("node_id", strNodeId);
            
            string strAlertUuid(((Alert*) e)->alert_uuid);
            message->setStringProperty("alert_uuid", strAlertUuid);
                
            string strSource(((Alert*) e)->alert_source);
            message->setStringProperty("alert_source", strSource);
                
            string strType(((Alert*) e)->alert_type);
            message->setStringProperty("alert_type", strType);
            
            string strSensor(((Alert*) e)->sensor_id);
            message->setStringProperty("sensor_id", strSensor);
            
            message->setIntProperty("alert_severity", ((Alert*) e)->alert_severity);
            
            string strEventDetails(((Alert*) e)->description);
            message->setStringProperty("description", strEventDetails);
            
            string strEvent(((Alert*) e)->event_id);
            message->setStringProperty("event_id", strEvent);
                    
            message->setIntProperty("event_severity", ((Alert*) e)->event_severity);
            
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
            
            string strUser(((Alert*) e)->user_name);
            message->setStringProperty("user_name", strUser);
            
            string strAgent(((Alert*) e)->agent_name);
            message->setStringProperty("agent_name", strAgent);
            
            char cat_string[OS_STRING_SIZE];
        
            int j = 0;
            for (string i : ((Alert*) e)->list_cats) {
                if ( j < ((Alert*) e)->list_cats.size() - 1) i = i + ", ";
                if (j == 0) strncpy (cat_string, i.c_str(), i.size() + 1);
                else strncat (cat_string, i.c_str(), i.size() + 1);
            
                j++;    
            }
                
            string strEventCat(cat_string);
            message->setStringProperty("categories", strEventCat);
            
            string strSrcip(((Alert*) e)->src_ip);
            message->setStringProperty("src_ip", strSrcip);
                
            string strDstip(((Alert*) e)->dst_ip);
            message->setStringProperty("dst_ip", strDstip);
            
            string strSrcagent(((Alert*) e)->src_hostname);
            message->setStringProperty("src_hostname", strSrcagent);
                
            string strDstagent(((Alert*) e)->dst_hostname);
            message->setStringProperty("dst_hostname", strDstagent);
            
            message->setIntProperty("src_port", ((Alert*) e)->src_port);
            
            message->setIntProperty("dst_port", ((Alert*) e)->dst_port);
			
            string strRegValue(((Alert*) e)->reg_value);
            message->setStringProperty("reg_value", strRegValue);
            
            string strFileName(((Alert*) e)->file_name);
            message->setStringProperty("file_name", strFileName);
            
            string strMD5(((Alert*) e)->hash_md5);
            message->setStringProperty("hash_md5", strMD5);
            
            string strSHA1(((Alert*) e)->hash_sha1);
            message->setStringProperty("hash_sha1", strSHA1);
            
            string strSHA256(((Alert*) e)->hash_sha256);
            message->setStringProperty("hash_sha256", strSHA256);
            
            message->setIntProperty("process_id", ((Alert*) e)->process_id);
            
            string strProcessName(((Alert*) e)->process_name);
            message->setStringProperty("process_name", strProcessName);
            
            string strProcessCmdline(((Alert*) e)->process_cmdline);
            message->setStringProperty("process_cmdline", strProcessCmdline);
            
            string strProcessPath(((Alert*) e)->process_path);
            message->setStringProperty("process_path", strProcessPath);
            
            string strUrlHostname(((Alert*) e)->url_hostname);
            message->setStringProperty("url_hostname", strUrlHostname);
            
            string strUrlPath(((Alert*) e)->url_path);
            message->setStringProperty("url_path", strUrlPath);
            
            string strContainerId(((Alert*) e)->container_id);
            message->setStringProperty("container_id", strContainerId);
                        
            string strContainerName(((Alert*) e)->container_name);
            message->setStringProperty("container_name", strContainerName);
            
            string strCloudInstance(((Alert*) e)->cloud_instance);
            message->setStringProperty("cloud_instance", strCloudInstance);
            
            producerAlerts->send(message.get());
            
                    
        }  else {
            
            BytesMessage* byte_message = session->createBytesMessage();
            
            byte_message->setIntProperty("msg_type", msg_type);
            byte_message->setStringProperty("ref_id", e->ref_id);
            byte_message->setStringProperty("node_id", node_id);
            byte_message->setStringProperty("probe_id", probe_id);
            
            switch (msg_type) {
                case 3 :
                    byte_message->setIntProperty("sensor", ((BinData*) e)->sensor_type);
                    break;
                case 4 :
                    byte_message->setIntProperty("sensor", ((BinData*) e)->sensor_type);
                    byte_message->setStringProperty("rule", ((Rule*) e)->name_rule);
                    break;
                case 5 :
                    byte_message->setStringProperty("target", ((BinData*) e)->target);
                    break;
                case 8 :
                    byte_message->setStringProperty("target", ((BinData*) e)->target);
                    break;
                case 9 :
                    byte_message->setStringProperty("target", ((BinData*) e)->target);
                    break;
                case 10 :
                    byte_message->setStringProperty("target", ((BinData*) e)->target);
                    break;
                case 11 :
                    byte_message->setStringProperty("target", ((BinData*) e)->target);
                    break;
                case 12 :
                    byte_message->setStringProperty("target", ((BinData*) e)->target);
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
        CheckStatus();
        return 0;
    }
        
    return 1;
}

int Controller::SendAgentInfo(string ref, string node, string agent, string json) {
    
    try {
        auto_ptr<TextMessage> message(session->createTextMessage(json));
        message->setStringProperty("agent_name", agent);
        message->setStringProperty("node_id", node);
        message->setStringProperty("ref_id", ref);
        message->setIntProperty("msg_type", 1);
        producerInfo->send(message.get());
    } catch (CMSException& e) {
        SysLog("Agents info wasn't send");
        CheckStatus();
        return 0;
    }
        
    return 1;
}

int Controller::SendResponse( ) {
    
    try {
        
    } catch (CMSException& e) {
        
        return 0;
    }
        
    return 1;
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
        
        delete destResponse;
        destResponse = NULL;
        
        if (producerResponse) {
            delete producerResponse;
            producerResponse = NULL;
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




