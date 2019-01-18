/* 
 * File:  updates.cpp
 * Author: olegzhr
 *
 * Created on November 23, 2017, 3:47 AM
 */
#include "updates.h"

namespace bpt = boost::property_tree;

int Updates::GetConfig() {
       
    update_status = 1;
    return update_status;
}

int Updates::Open() {
    
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
                connection->setExceptionListener(this);
            }
            
            // Create a Session
            if (this->sessionTransacted) {
                session = connection->createSession(Session::SESSION_TRANSACTED);
            } else {
                session = connection->createSession(Session::AUTO_ACKNOWLEDGE);
            }
            
            // Create the destination (Topic or Queue)
            string strTopic(path);
            
            strTopic = strTopic + "collector";
            
            destination = session->createTopic(strTopic);
            
            // Create a MessageConsumer from the Session to the Topic or Queue
            consumer = session->createConsumer(destination);
 
            consumer->setMessageListener(this);
            
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

int Updates::Go(void) {
    
    sleep(1);
    RoutineJob();
    
    return 1;
}

void Updates::RoutineJob() {
    if (!connection_status) Reset();
}


// Called from the consumer since this class is a registered MessageListener.
void Updates::onMessage(const Message* message) {
 
    try {
        const TextMessage* textMessage = dynamic_cast<const TextMessage*> (message);
        
        string text = textMessage->getText();
        stringstream ss(text);
        
        try {
        
            bpt::ptree pt;
            bpt::read_json(ss, pt);
        
            string type = pt.get<string>("type");
            string node = pt.get<string>("node");
            
            
            if (!node.compare(node_id)) {
        
                if (!type.compare("filters")) {
            
                    stringstream oss;
                    
                    bpt::ptree f = pt.get_child("data");
                    bpt::json_parser::write_json(oss, f);
                    string filters = oss.str();
                    
                    fs.ParsFiltersConfig(oss.str());
                    
                    ofstream ostream;
                    
                    try { 
                        
                        ostream.open(FILTERS_FILE, ios_base::trunc);
                        ostream << oss.str();
                        ostream.close();
                        
                    } catch (std::ostream::failure e) {
                        SysLog("Exception for local filters file.");
                        return;
                    }
                } 
            } 
            
        } catch (const std::exception & ex) {
            SysLog((char*) ex.what());
        } 
        
    } catch (CMSException& e) {
        SysLog("ActiveMQ CMS Exception occurred.");
    }
 
    // Commit all messages.
    if (this->sessionTransacted) {
        session->commit();
    }
}
 
// If something bad happens you see it here as this class is also been
// registered as an ExceptionListener with the connection.
void Updates::onException(const CMSException& ex AMQCPP_UNUSED) {
    SysLog("ActiveMQ CMS Exception occurred: update module");
    connection_status =  false;
}

void Updates::Close() {
    
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
        
        if (consumer) {
            delete consumer;
            consumer = NULL;
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


bool Updates::Reset() {
    
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
        
            if (consumer != NULL) {
                delete consumer;
                consumer = NULL;
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
                connection = connectionFactory->createConnection();
                connection->start();
                connection->setExceptionListener(this);
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
                string strTopic(path);
            
                strTopic = strTopic + "collector";
            
                destination = session->createTopic(strTopic);
            }
            
            if (consumer == NULL) {
                        
                // Create a MessageProducer from the Session to the Topic or Queue
                consumer = session->createConsumer(destination);
 
                consumer->setMessageListener(this);
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

int Updates::IsHomeNetwork(string ip) {
    
    if (ip.compare("") == 0) return 0;
    
    if (fs.filter.home_nets.size() != 0) {
        
        std::vector<Network*>::iterator i, end;
        
        for (i = fs.filter.home_nets.begin(), end = fs.filter.home_nets.end(); i != end; ++i) {
            
            string net = (*i)->network;
            string mask = (*i)->netmask;
            
            if(IsIPInRange(ip, net, mask)) return 1;
        }
    }
    
    return 0;
}


