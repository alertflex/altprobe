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

int Updates::Open(int mode, pid_t pid) {
    
    bool amq_conn = false;
    int conn_attempts = 0;
    
    altprobe_mode = mode;
    p_pid = pid;
    
    do {
        try {
            if (connection == NULL) {
                
                activemq::library::ActiveMQCPP::initializeLibrary();
                
                if (ssl_broker) {
                    
                    decaf::lang::System::setProperty( "decaf.net.ssl.trustStore", cert );
                    
                    if (ssl_verify) {
                        decaf::lang::System::setProperty("decaf.net.ssl.disablePeerVerification", "false");
                    } else {
                        decaf::lang::System::setProperty("decaf.net.ssl.disablePeerVerification", "true");
                    }
                    
                } 
                
                if (ssl_client) {
                    decaf::lang::System::setProperty("decaf.net.ssl.keyStore", key); 
                    decaf::lang::System::setProperty("decaf.net.ssl.keyStorePassword", key_pwd); 
                } 
                
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
            
            // Create the MessageConsumer
            string strConsumer("jms/altprobe/" + fs.filter.ref_id);
            
            Destination* consumerTopic = session->createTopic(strConsumer);
            
            // Create a MessageConsumer from the Session to the Topic or Queue
            consumer = session->createConsumer(consumerTopic);
 
            consumer->setMessageListener(this);
            
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

int Updates::Go(void) {
    
    sleep(1);
        
    return 1;
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
        
                if (!content_type.compare("filters") && urStatus) {
                    
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
                
                if (!content_type.compare("config") && urStatus) {
                    
                    try { 
                    
                        if (sensor_id.compare(sensor)) return;
                        
                        int sensor_type = message->getIntProperty("sensor_type");
                    
                        switch (sensor_type) {
                            case 0 : {
                                string dir_path(falco_conf);
                                string file_name(FALCO_CONFIG);
                                string file_path = dir_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/altprobe/scripts/restart-falco.sh";
                                }
                                break;
                            case 1 : {
                                string dir_path(wazuh_conf);
                                string file_name(OSSEC_CONFIG);
                                string file_path = dir_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/altprobe/scripts/restart-wazuh.sh";
                                }
                                break;
                            case 2 : {
                                string dir_path(suri_conf);
                                string file_name(SURI_CONFIG);
                                string file_path = dir_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/altprobe/scripts/restart-suri.sh";
                                }
                                break;
                            case 3 : {
                                string dir_path(modsec_conf);
                                string file_name(MODSEC_CONFIG);
                                string file_path = dir_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/altprobe/scripts/restart-modsec.sh";
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
                
                if (!content_type.compare("rules") && urStatus) {
                    
                    try { 
                    
                        if (sensor_id.compare(sensor)) return;
                        
                        int rules_type = message->getIntProperty("rules_type");
                    
                        string rule_name = message->getStringProperty("rule_name");
                        int rule_reload = message->getIntProperty("rule_reload");
                    
                        switch (rules_type) {
                            case 0 : {
                                string rules_path(falco_local);
                                string file_path = rules_path + rule_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/altprobe/scripts/rulesup-falco.sh";
                                }
                                break;
                            case 1 : {
                                string dir_path(wazuh_local);
                                string rules_path(WAZUH_RULES);
                                string file_path = dir_path + rules_path + rule_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/altprobe/scripts/rulesup-wazuh.sh";
                                }
                                break;
                            case 2 : {
                                string dir_path(wazuh_local);
                                string rules_path(WAZUH_DECODERS);
                                string file_path = dir_path + rules_path + rule_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/altprobe/scripts/rulesup-wazuh.sh";
                                }
                                break;
                            case 3 : {
                                string rules_path(suri_local);
                                string file_path = rules_path + rule_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/altprobe/scripts/rulesup-suri.sh";
                                }
                                break;
                            case 4 : {
                                string rules_path(modsec_local);
                                string file_path = rules_path + rule_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/altprobe/scripts/rulesup-modsec.sh";
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
                
                
                if (!content_type.compare("iprep") && urStatus) {
                    
                    try { 
                    
                        if (sensor_id.compare(sensor)) return;
                        
                        int sensor_type = message->getIntProperty("sensor_type");
                    
                        switch (sensor_type) {
                            
                            case 0 : {
                                string iprep_path(wazuh_local);
                                string file_name(WAZUH_IPREP);
                                string file_path = iprep_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/altprobe/scripts/iprepup-wazuh.sh"; 
                                }
                                break;
                            case 1 : {
                                string iprep_path(suri_local);
                                string file_name(SURI_IPREP);
                                string file_path = iprep_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/altprobe/scripts/iprepup-suri.sh";
                                }
                                break;
                            case 2 : {
                                string iprep_path(modsec_local);
                                string file_name(MODSEC_IPREP);
                                string file_path = iprep_path + file_name;
                                ostream.open(file_path, ios_base::trunc);
                                cmd = "/etc/altprobe/scripts/iprepup-modsec.sh";
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
            
            } else {  
        
                const TextMessage* textMessage = dynamic_cast<const TextMessage*> (message);
        
                string text = textMessage->getText();
                
                if (!sensor_id.compare("master")) {
        
                    try {
        
                        if (!content_type.compare("active_response") && arStatus) {
                            
                            stringstream ss(text);
                            
                            bpt::ptree pt;
                            bpt::read_json(ss, pt);
                    
                            string agent_name = pt.get<string>("agent");
                            string json = pt.get<string>("json");
                                                        
                            // convert agent to number
                            
                            string agent_id = fs.GetAgentIdByName(agent_name);
                    
                            if (!agent_id.empty()) SendArToWazuh(agent_id, json);
                    
                            string log = "ar_json: " + json;
                            // SysLog((char*) log.c_str());
                        }
                        
                        if (!content_type.compare("create_agent") && arStatus) {
                            string agent_name = message->getStringProperty("agent_name");
                            string post_response = CreateAgentWazuh(text);
                            if (!post_response.empty()) {
                                SendAgentInfo(fs.filter.ref_id, node, agent_name, post_response);
                            }
                        }
                
                    } catch (const std::exception & ex) {
                        SysLog((char*) ex.what());
                    }
                }
            }
        }
        
    } catch (CMSException& e) {
        SysLog("ActiveMQ CMS Exception occurred: update module");
        CheckStatus();
        return;
    }
 
    if (this->sessionTransacted) {
        session->commit();
    }
}
 
// If something bad happens you see it here as this class is also been
// registered as an ExceptionListener with the connection.
void Updates::onException(const CMSException& ex AMQCPP_UNUSED) {
    SysLog("ActiveMQ CMS Exception occurred: update module");
    CheckStatus();
}

void Updates::Close() {
    
    // Destroy resources.
    try {
        if (consumer) {
            delete consumerTopic;
            consumerTopic = NULL;
            delete consumer;
            consumer = NULL;
        }
        
        m_controller.lock();
        mq_counter--;
        m_controller.unlock();
        
        if (mq_counter == 0) {
            
            delete session;
            session = NULL;
            
            delete connection;
            connection = NULL;
        }
        
    } catch (CMSException& e) {
        SysLog("activeMQ operation error: destroy resources");
    }
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
        
        string queryStr = "/active-response/" + agent;
        
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
        request_stream << "Content-Type:application/json\r\n";
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

string Updates::CreateAgentWazuh(string json) {
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
        
        string queryStr = "/agents";

        // Get a list of endpoints corresponding to the server name.
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(ip, port);
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);
        
        boost::asio::streambuf request;
        ostream request_stream(&request);
        request_stream << "POST " << queryStr << " HTTP/1.1\r\n";  // note that you can change it if you wish to HTTP/1.0
        request_stream << "Host: " << hostAddress << "\r\n";
        request_stream << "Authorization: Basic "<< encoded << "\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Content-Type:application/json\r\n";
        request_stream << "Content-Length: " << json.length() << "\r\n\r\n";
        request_stream << json;
        
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
        
        if (!response_stream || http_version.substr(0, 5) != "HTTP/") return "";
        
        if (status_code != 200) {
            return "";
        }
        
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
        
        //string s = std::to_string(rep_size);
        //string output = "logs compressed = " + s;
        //SysLog((char*) payload.str().c_str());
        return payload.str();
        
    }
    catch (std::exception& e) {
     
    }

    return "";
}



