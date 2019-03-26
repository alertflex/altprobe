/* 
 * File:  updates.cpp
 * Author: olegzhr
 *
 * Created on November 23, 2017, 3:47 AM
 */

#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <list>
#include <vector>
#include <memory>
#include <sstream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <iostream>
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
                }
                
                // Create a ConnectionFactory
                string strUrl(url);
            
                auto_ptr<ConnectionFactory> connectionFactory(
                    ConnectionFactory::createCMSConnectionFactory(strUrl));
            
                // Create a Connection
                connection = connectionFactory->createConnection(user,pwd);
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
            
            strTopic = strTopic + fs.filter.ref_id;
            //strTopic = strTopic + project_id;
            
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
        
        string node = message->getStringProperty("node_id");
        string sensor = message->getStringProperty("sensor");
        string msg_type = message->getStringProperty("msg_type");
        string content_type = message->getStringProperty("content_type");
        
        if (!node.compare(node_id)) {
        
            if (!msg_type.compare("byte")) {
        
                const BytesMessage* bytesMessage = dynamic_cast<const BytesMessage*> (message);
        
                const unsigned char* comp = bytesMessage->getBodyBytes();
                int comp_size = bytesMessage->getBodyLength();
        
                stringstream ss, decomp;
        
                ss.write(reinterpret_cast<const char*>(&comp[0]),comp_size);
        
                boost::iostreams::filtering_streambuf<boost::iostreams::input> inbuf;
                inbuf.push(boost::iostreams::gzip_decompressor());
                inbuf.push(ss);
                boost::iostreams::copy(inbuf, decomp);
                boost::iostreams::close(inbuf);
                
                ofstream ostream;
                string cmd;
        
                if (!content_type.compare("filters") && uploadStatus) {
                    
                    fs.ParsFiltersConfig(decomp.str());
                    
                    try { 
                        
                        ostream.open(FILTERS_FILE, ios_base::trunc);
                        ostream << decomp.str();
                        ostream.close();
                        
                        SysLog("filters have been updated");
                        
                        return;
                        
                    } catch (std::ostream::failure e) {
                        SysLog("Exception for local filters file.");
                        return;
                    }
                    
                }
                
                if (!content_type.compare("config") && uploadStatus) {
                    
                    try { 
                    
                        if (sensor_id.compare(sensor)) return;
                        
                        int sensor_type = message->getIntProperty("sensor_type");
                    
                        switch (sensor_type) {
                            case 0 : {
                                string dir_path(suri_path);
                                string file_name(SURI_CONFIG);
                                string file_path = dir_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/alertflex/scripts/restart-suri.sh";
                                }
                                break;
                            
                            case 1 : {
                                string dir_path(wazuh_path);
                                string file_name(OSSEC_CONFIG);
                                string file_path = dir_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/alertflex/scripts/restart-wazuh.sh";
                                }
                                break;
                                
                            case 2 : {
                                string dir_path(modsec_path);
                                string file_name(MODSEC_CONFIG);
                                string file_path = dir_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/alertflex/scripts/restart-modsec.sh";
                                }
                                break;
                                
                            default:
                                return;
                        }
                            
                        ostream << decomp.str();
                        ostream.close();
                        
                        if (arStatus) system(cmd.c_str());
                    
                    } catch (std::ostream::failure e) {
                        SysLog("Exception for local filters file.");
                    }
                        
                }
                
                if (!content_type.compare("rules") && uploadStatus) {
                    
                    try { 
                    
                        if (sensor_id.compare(sensor)) return;
                        
                        int rules_type = message->getIntProperty("rules_type");
                    
                        string rule_name = message->getStringProperty("rule_name");
                        int rule_reload = message->getIntProperty("rule_reload");
                    
                        switch (rules_type) {
                            case 0 : {
                                string rules_path(SURI_RULES_PATH);
                                string file_path = rules_path + rule_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/alertflex/scripts/rulesup-suri.sh";
                                }
                                break;
                            
                            case 1 : {
                                string dir_path(wazuh_path);
                                string rules_path(WAZUH_DECODERS_LOCAL);
                                string file_path = dir_path + rules_path + rule_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/alertflex/scripts/rulesup-wazuh.sh";
                                }
                                break;
                            
                            case 2 : {
                                string dir_path(wazuh_path);
                                string rules_path(WAZUH_RULES_LOCAL);
                                string file_path = dir_path + rules_path + rule_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/alertflex/scripts/rulesup-wazuh.sh";
                                }
                                break;
                                
                            case 3 : {
                                string dir_path(modsec_path);
                                string rules_path(modsec_iprep);
                                string file_path = dir_path + rules_path + rule_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/alertflex/scripts/rulesup-modsec.sh";
                                }
                                break;
                            
                            default:
                                return;
                        }
                        
                        ostream << decomp.str();
                        ostream.close();
                        
                        if (arStatus && rule_reload == 1) system(cmd.c_str());
                    
                    } catch (std::ostream::failure e) {
                        SysLog("Exception for local filters file.");
                            
                    }
                }
                
                
                if (!content_type.compare("iprep") && uploadStatus) {
                    
                    try { 
                    
                        if (sensor_id.compare(sensor)) return;
                        
                        int sensor_type = message->getIntProperty("sensor_type");
                    
                        switch (sensor_type) {
                            case 0 : {
                                string dir_path(suri_path);
                                string iprep_path(suri_iprep);
                                string file_name(SURI_IPREP);
                                string file_path = dir_path + iprep_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/alertflex/scripts/iprepup-suri.sh";
                                }
                                break;
                                
                            case 1 : {
                                string dir_path(wazuh_path);
                                string iprep_path(wazuh_iprep);
                                string file_name(WAZUH_IPREP);
                                string file_path = dir_path + iprep_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/alertflex/scripts/iprepup-wazuh.sh"; 
                                }
                                break;
                                
                            case 2 : {
                                string dir_path(modsec_path);
                                string iprep_path(modsec_iprep);
                                string file_name(MODSEC_IPREP);
                                string file_path = dir_path + iprep_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/alertflex/scripts/iprepup-modsec.sh";
                                }
                                break;
                                
                            default:
                                return;
                        }
                        
                        ostream << decomp.str();
                        ostream.close();
                        
                        if (arStatus) system(cmd.c_str());
                        
                    } catch (std::ostream::failure e) {
                        SysLog("Exception for local filters file.");
                            
                    }
                }
            }
        }  else {  
        
            const TextMessage* textMessage = dynamic_cast<const TextMessage*> (message);
        
            string text = textMessage->getText();
            stringstream ss(text);
        
            try {
        
                bpt::ptree pt;
                bpt::read_json(ss, pt);
        
                if (!content_type.compare("active_response") && arStatus) {
                    
                    string agent = pt.get<string>("agent");
                    string response = pt.get<string>("response");
                    
                    SendArToWazuh(agent, response);
                    
                    string log = "ar: " + response;
                    SysLog((char*) log.c_str());
                }
                
            } catch (const std::exception & ex) {
                SysLog((char*) ex.what());
            }
        }
        
    } catch (CMSException& e) {
        SysLog("ActiveMQ CMS Exception occurred.");
    }
 
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

int Updates::SendArToWazuh(string agent, string json) {
    try
    {
        boost::asio::io_service io_service;
        
        string hostAddress;
        string ip(wazuh_host);
        stringstream ss;
        ss << wazuh_port;
        string port = ss.str();
        
        if (wazuh_port != 80) {
            hostAddress = ip + ":" + port;
        } else { 
            
            hostAddress = ip;
        }
        
        string user(wazuh_user);
        string pwd(wazuh_pwd);
        string token = user + ":" + pwd;
        
        string encoded;
        
        if (!Base64::Encode(token, &encoded)) {
            return 0;
        }
        
        string queryStr = "/active-response/" + agent + "?pretty";

        // Get a list of endpoints corresponding to the server name.
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(ip, port);
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);
        
        boost::asio::streambuf request;
        ostream request_stream(&request);
        request_stream << "PUT " << queryStr << " HTTP/1.1\r\n";  // note that you can change it if you wish to HTTP/1.0
        request_stream << "Host: " << hostAddress << "\r\n";
        request_stream << "Authorization: Basic "<< encoded << "\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Content-Type:application/json \r\n";
        request_stream << "Content-Length: " << json.length() << "\r\n";    
        request_stream << "Connection: close\r\n\r\n";  //NOTE THE Double line feed
        request_stream << json; 
        
        

        // Send the request.
        boost::asio::write(socket, request);

        // Read the response status line. The response streambuf will automatically
        // grow to accommodate the entire line. The growth may be limited by passing
        // a maximum size to the streambuf constructor.
        
        boost::asio::streambuf response;
        boost::asio::read_until(socket, response, "\r\n");

        // Check that response is OK.
        istream response_stream(&response);
        string http_version;
        response_stream >> http_version;
        unsigned int status_code;
        response_stream >> status_code;
        string status_message;
        getline(response_stream, status_message);
        
        if (!response_stream || http_version.substr(0, 5) != "HTTP/") return 0;
        
        if (status_code != 200) return 0;
        
        // Read the response headers, which are terminated by a blank line.
        boost::asio::read_until(socket, response, "\r\n\r\n");

        // Process the response headers.
        string header;
        while (getline(response_stream, header) && header != "\r") { }
        
        stringstream  payload;
        // Write whatever content we already have to output.
        if (response.size() > 0) {
            payload << &response;
        }

        // Read until EOF, writing data to output as we go.
        boost::system::error_code error;
        while (boost::asio::read(socket, response,boost::asio::transfer_at_least(1), error)) {
            payload << &response;
        }

        if (error != boost::asio::error::eof) {
            throw boost::system::system_error(error);
        }
        
        // return payload.str();
        return 1;
    }
    catch (std::exception& e) {
        return 0;
    }

    return 0;
}



