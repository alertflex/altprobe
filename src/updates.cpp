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

#define SOCKET_BUFFER_SIZE 2048

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
            string strConsumer("jms/altprobe/" + fs.filter.ref_id + "/" + node_id + "/" + probe_id + "/sensors");
            
            Destination* consumerCommand = session->createQueue(strConsumer);
            
            // Create a MessageConsumer from the Session to the Topic or Queue
            consumer = session->createConsumer(consumerCommand);
 
            consumer->setMessageListener(this);
            
            mq_counter++;
        
            amq_conn = true;
            
            string log = "listens sensors bus";
            SysLog((char*) log.c_str());
 
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
        
        string corr_id = message->getCMSCorrelationID();
        string headerJson = "{ \"request_id\": \"" +  corr_id + "\", ";
        string bodyJson = "\"status\": 400 }";        
        
        if (dynamic_cast<const BytesMessage*> (message)) {
            bodyJson = onBytesMessage(message);
        
        } else {  
            
            if (dynamic_cast<const TextMessage*> (message)) {
                bodyJson = onTextMessage(message);
                
            } 
        }
        
        string responseJson = headerJson + bodyJson;
        
        // Create a MessageProducer from the Session to Queue
        const Destination* tmpDest = message->getCMSReplyTo();
        MessageProducer* tmpProd = session->createProducer(tmpDest);
            
        auto_ptr<TextMessage> response(session->createTextMessage(responseJson));
        tmpProd->send(response.get());
            
        delete tmpProd;
        tmpProd = NULL;
        
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

string Updates::onBytesMessage(const Message* message) {
    
    string ref_id = message->getStringProperty("ref_id");
    if(ref_id.compare(fs.filter.ref_id)) return "\"status\": 400 }";
    
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
    
    string content_type = message->getStringProperty("content_type");
    
    if (!content_type.compare("filters") && ruStatus) {
        
        fs.ParsFiltersConfig(decomp.str());
        
        try { 
            
            ostream.open(FILTERS_FILE, ios_base::trunc);
            ostream << decomp.str();
            ostream.close();
            
            SysLog("filters have been updated");
            
        } catch (std::ostream::failure e) {
            SysLog("Exception for local filters file.");
            return "\"status\": 400 }";
        }
        
        return "\"status\": 200 }"; 
    }
    
    if (!content_type.compare("config") && ruStatus) {
        
        try { 
        
            int sensor_type = message->getIntProperty("sensor_type");
            bool sensor_restart = message->getBooleanProperty("sensor_restart");
            
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
                    string dir_path(modsec_conf);
                    string file_name(MODSEC_CONFIG);
                    string file_path = dir_path + file_name;
                    ostream.open(file_path, ios_base::trunc);
                    cmd = "/etc/altprobe/scripts/restart-modsec.sh";
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
                    string dir_path(wazuh_conf);
                    string file_name(OSSEC_CONFIG);
                    string file_path = dir_path + file_name;
                    ostream.open(file_path, ios_base::trunc);
                    cmd = "/etc/altprobe/scripts/restart-wazuh.sh";
                    }
                    break;
                
                
                default:
                    return "\"status\": 400 }";
            }
                
            ostream << decomp.str();
            ostream.close();
            
            if (rcStatus && sensor_restart) system(cmd.c_str());
        
        } catch (std::ostream::failure e) {
            SysLog("Exception for local filters file.");
            return "\"status\": 400 }"; 
        }
        
        return "\"status\": 200 }";
    }
    
    if (!content_type.compare("rules") && ruStatus) {
        
        try { 
        
            int rules_type = message->getIntProperty("rules_type");
            string rule_name = message->getStringProperty("rule_name");
            bool rule_reload = message->getBooleanProperty("rule_reload");
        
            switch (rules_type) {
                case 0 : {
                    string rules_path(falco_local);
                    string file_path = rules_path + rule_name;
                    ostream.open(file_path, ios_base::trunc);
                    cmd = "/etc/altprobe/scripts/rulesup-falco.sh";
                    }
                    break;
                case 1 : {
                    string rules_path(modsec_local);
                    string file_path = rules_path + rule_name;
                    ostream.open(file_path, ios_base::trunc);
                    cmd = "/etc/altprobe/scripts/rulesup-modsec.sh";
                    }
                    break;
                 case 2 : {
                    string rules_path(suri_local);
                    string file_path = rules_path + rule_name;
                    ostream.open(file_path, ios_base::trunc);
                    cmd = "/etc/altprobe/scripts/rulesup-suri.sh";
                    }
                    break;
                case 3 : {
                    string dir_path(wazuh_local);
                    string rules_path(WAZUH_RULES);
                    string file_path = dir_path + rules_path + rule_name;
                    ostream.open(file_path, ios_base::trunc);
                    cmd = "/etc/altprobe/scripts/rulesup-wazuh.sh";
                    }
                    break;
                case 4 : {
                    string dir_path(wazuh_local);
                    string rules_path(WAZUH_DECODERS);
                    string file_path = dir_path + rules_path + rule_name;
                    ostream.open(file_path, ios_base::trunc);
                    cmd = "/etc/altprobe/scripts/rulesup-wazuh.sh";
                    }
                    break;
               
                default:
                    return "\"status\": 400 }";
            }
            
            ostream << decomp.str();
            ostream.close();
            
            if (rcStatus && rule_reload) system(cmd.c_str());
        
        } catch (std::ostream::failure e) {
            SysLog("Exception for local filters file.");
            return "\"status\": 400 }";    
        }
        
        return "\"status\": 200 }"; 
    }
    
    
    return "\"status\": 400 }";
}

string Updates::onTextMessage(const Message* message) {
    
    const TextMessage* textMessage = dynamic_cast<const TextMessage*> (message);
                
    string c2json = textMessage->getText();
    
    //************************************************************************************************************************
    SysLog((char*) c2json.c_str());
    
    stringstream c2json_ss(c2json);
    bpt::ptree pt;
    bpt::read_json(c2json_ss, pt);
    
    string ref_id =  pt.get<string>("actuator.x-alertflex.tenant","indef");
    
    if(ref_id.compare(fs.filter.ref_id) || !ref_id.compare("indef") || !rcStatus) {
        
        return "\"status\": 400, \"status_text\": \"wrong tenant\" }"; 
    }
    
    
    string action =  pt.get<string>("action","indef");
    string actuator_profile =  pt.get<string>("actuator.x-alertflex.profile","indef");
    
    
    if(!actuator_profile.compare("indef") || !action.compare("indef")) {
    
        return "\"status\": 400, \"status_text\": \"wrong actuator or action\" }"; 
    } 
    
    if(!actuator_profile.compare("suricata_command") && !action.compare("deny")) {
        
        // char test1[] = "{\"command\": \"add-hostbit\", \"arguments\": {\"ipaddress\": \"192.168.1.2\", 
        // \"hostbit\": \"alertflex_ar\", \"expire\": 360}}";
        
        string ip = pt.get<string>("target.ipv4_net","indef");
        string rule = pt.get<string>("args.x-alertflex:suricata_command.rule_name","indef");
        int duration = pt.get<int>("args.duration",0);
        stringstream int_ss;
        int_ss << duration;
              
        string ph1 = "{\"command\": \"add-hostbit\", \"arguments\": {\"ipaddress\": \"";
        string ph2 = "\", \"hostbit\": \"" + rule + "\", \"expire\": ";
        
        string suri_cmd = ph1 + ip + ph2 + int_ss.str() + "}}";
        
        string res = SendArToSuricata(suri_cmd);
        
        if (res.compare("ok")) {
            return "\"status\": 400, \"status_text\": \"" + res + "\" }";
        }
        
        return "\"status\": 200 }";
        
    } 
    
    if(!actuator_profile.compare("wazuh_agent")) {
        
        if(!wazuh_token.compare("indef")) {
            return "\"status\": 400, \"status_text\": \"problem with Wazuh api\" }"; 
        }
        
        if(!action.compare("create")) {
        
            try {
            
                string ip = pt.get<string>("target.device.ipv4_net","indef");
                string agent = pt.get<string>("args.x-alertflex:wazuh_agent.name","indef");
                
                if(!ip.compare("indef") || !agent.compare("indef")) {
    
                    return "\"status\": 400, \"status_text\": \"wrong ip or agent name for create\" }"; 
                } 
                
                string jsonCreateAgent = "{ \"name\": \"" + agent + "\", \"ip\": \"" + ip + "\" }";
        
                string res =  CreateAgentWazuh(jsonCreateAgent);
        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong args\" }"; 
            }
                
        } 
        
        if(!action.compare("delete")) {
        
            try {
            
                string agent = pt.get<string>("args.x-alertflex:wazuh_agent.id","indef");
                
                if(!agent.compare("indef")) {
    
                    return "\"status\": 400, \"status_text\": \"agent id is missing\" }"; 
                } 
                
                string res =  DeleteAgentWazuh(agent);
        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong args\" }"; 
            }
                
        } 
    
        if (!action.compare("start")) {
                    
            string agent = pt.get<string>("target.device.device_id","indef");
                    
            try {
                        
                bpt::ptree pt_args = pt.get_child("args.x-alertflex:wazuh_command");
                std::ostringstream oss;
                write_json(oss, pt_args);
                    
                string args = oss.str();
                                            
                if(!agent.compare("indef") || args.empty()) {
    
                    return "\"status\": 400, \"status_text\": \"wrong agent or args\" }"; 
                } 
            
                string res =  SendArToWazuh(agent, args);
                    
                return res;
                        
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong args\" }"; 
            }
        }
    }
    
    if(!actuator_profile.compare("docker_command") && !action.empty()) {
            
        string id = pt.get<string>("target.device.device_id","indef");
                        
        if(!id.compare("indef")) {
    
            return "\"status\": 400, \"status_text\": \"wrong id for stop\" }"; 
        } 
                
        string res = DockerContainer(id, action);
        
        if (res.compare("ok")) {
            return "\"status\": 400, \"status_text\": \"" + res + "\" }";
        }
        
        return "\"status\": 200 }";
                
    } 
    
    return "\"status\": 400, \"status_text\": \"wrong actuator or action\" }";
}


string Updates::SendArToWazuh(string agent, string json) {
    
    try {
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
        
        // Get a list of endpoints corresponding to the server name.
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(ip, port);
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);
        
        string queryStr = "/active-response/?agents_list=" + agent;
        
        boost::asio::streambuf request;
        ostream request_stream(&request);
        request_stream << "PUT " << queryStr << " HTTP/1.1\r\n";  // note that you can change it if you wish to HTTP/1.0
        request_stream << "Host: " << hostAddress << "\r\n";
        request_stream << "Authorization: Bearer "<< wazuh_token << "\r\n";
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
        
        if (status_code != 200) return "\"status\": 400, \"status_text\": \"error start command\" }";
        
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
        
        return "\"status\": 200 }";
    }
    catch (std::exception& e) {
        
    }

    return "\"status\": 400, \"status_text\": \"error start command\" }";
}

string Updates::CreateAgentWazuh(string json) {
    
    try {
        
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
        
        // Get a list of endpoints corresponding to the server name.
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(ip, port);
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);
        
        boost::asio::streambuf request;
        ostream request_stream(&request);
        request_stream << "POST /agents HTTP/1.1\r\n";  
        request_stream << "Host: " << hostAddress << "\r\n";
        request_stream << "Authorization: Bearer "<< wazuh_token << "\r\n";
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
        
        if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
            return "\"status\": 400, \"status_text\": \"error response from wazuh api\" }";
        }
        
        if (status_code != 200) {
            return "\"status\": 400, \"status_text\": \"error response from wazuh api\" }";
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
        
        boost::asio::read_until(socket, response, boost::regex("}.*}"));
        
        payload << &response;
        
        stringstream response_ss(payload.str());
        bpt::ptree pt;
        bpt::read_json(response_ss, pt);
        
        string id = pt.get<string>("data.id","indef");
        string key = pt.get<string>("data.key","indef");
                
        if(!id.compare("indef") || !key.compare("indef")) {
    
            return "\"status\": 400, \"status_text\": \"error response from wazuh - key or id\" }"; 
        } 
        
        return "\"status\": 200, \"result\": { \"x-alertflex:wazuh_agent\": { \"id\": \"" + id + "\", \"key\": \"" + key + "\"} } }";
        
    }
    catch (std::exception& e) {
        
    }

    return "\"status\": 400, \"status_text\": \"wazuh api exception\" }";
}

string Updates::DeleteAgentWazuh(string agent) {
    
    try {
        
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
        
        // Get a list of endpoints corresponding to the server name.
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(ip, port);
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);
        
        boost::asio::streambuf request;
        ostream request_stream(&request);
        request_stream << "DELETE /agents?status=all&purge=true&older_than=10s&agents_list=" + agent + " HTTP/1.1\r\n";  
        request_stream << "Host: " << hostAddress << "\r\n";
        request_stream << "Authorization: Bearer "<< wazuh_token << "\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Connection: close\r\n\r\n";
        
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
        
        if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
            return "\"status\": 400, \"status_text\": \"error response from wazuh api\" }";
        }
        
        if (status_code != 200) {
            return "\"status\": 400, \"status_text\": \"error response from wazuh api\" }";
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
        
        boost::asio::read_until(socket, response, boost::regex("}.*}"));
        
        payload << &response;
        
        stringstream response_ss(payload.str());
        bpt::ptree pt;
        bpt::read_json(response_ss, pt);
        
        int total_affected_items = pt.get<int>("data.total_affected_items",0);
        int total_failed_items = pt.get<int>("data.total_failed_items",0);
                
        if(total_affected_items != 1 || total_failed_items != 0) {
    
            return "\"status\": 400, \"status_text\": \"error response from wazuh - key or id\" }"; 
        } 
        
        return  "\"status\": 200 }";
        
    }
    catch (std::exception& e) {
        
    }

    return "\"status\": 400, \"status_text\": \"wazuh api exception\" }";
}

string Updates::SendArToSuricata(string json) {
    
    int sck;
    struct sockaddr_un addr;
    char buffer[SOCKET_BUFFER_SIZE];
    int ret;
    
    if (suriSocketStatus) {
    
        try
        {
            /* create socket */
            sck = socket(AF_UNIX, SOCK_STREAM, 0);
            if (sck == -1) {
		close (sck);
		return "suricata_unixsocket: can not create socket";
            }

            /* set address */
            addr.sun_family = AF_UNIX;
        
            strncpy(addr.sun_path, suri_socket, sizeof(addr.sun_path));
            addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

            /* Connect to unix socket */
            ret = connect(sck, (struct sockaddr *) &addr, sizeof(addr));
            if (ret == -1) {
		close (sck);
		return "suricata_unixsocket: can not connect to socket";
            }
        
            char test[] = "{\"version\": \"0.1\"}";
            int siz = strlen(test);

            ret = send(sck, test, siz, 0);
            if (ret == -1) {
		close (sck);
		return "suricata_unixsocket: can not send version";
            } else if (ret < siz) {
		close (sck);
		return "suricata_unixsocket: unable to send all string";
            }
        
            memset(buffer, 0, sizeof(buffer));
            ret = read(sck, buffer, sizeof(buffer));
            if (ret == -1) {
		close (sck);
		return "suricata_unixsocket: can not read answer (version)";
            } 

            siz = strlen(json.c_str());

            ret = send(sck, json.c_str(), siz, 0);
            if (ret == -1) {
		close (sck);
		return "suricata_unixsocket: can not send parameters";
            } 
        
            memset(buffer, 0, SOCKET_BUFFER_SIZE);
            ret = read(sck, buffer, SOCKET_BUFFER_SIZE);
            if (ret == -1) {
		close (sck);
		return "suricata_unixsocket: can not read answer";
            }
            
            close (sck);
            return "ok";
        }
        catch (std::exception& e) {
            close (sck);
            return "suricata_unixsocket: exception";
        }
    }

    return "suricata_unixsocket: error";
}

string Updates::DockerContainer(string id, string cmd) {
    
    int sck;
    struct sockaddr_un addr;
    int ret;
    
    if (dockerSocketStatus) {
    
        try {
        
            /* create socket */
            sck = socket(AF_UNIX, SOCK_STREAM, 0);
            if (sck == -1) {
                close (sck);
                return "can not create socket";
            }
            
            /* set address */
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, docker_socket, sizeof(addr.sun_path));
            addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

            /* Connect to unix socket */
            ret = connect(sck, (struct sockaddr *) &addr, sizeof(addr));
            if (ret == -1) {
                close (sck);
                return "can not connect to socket";
            }
        
            std::string req = "POST /v1.40/containers/";
            req += id;
            req += "/";
            req += cmd;
            req += " HTTP/1.1\r\n";
            req += "Host: localhost\r\n";
            req += "Accept: */*\r\n\r\n";
        
            int siz = req.size();

            ret = send(sck, req.c_str(), siz, 0);
            if (ret == -1) {
                close (sck);
                return "can not send request";
            } else if (ret < siz) {
                close (sck);
                return "unable send all size of message";
            }
        
            char buffer[SOCKET_BUFFER_SIZE];
            memset(buffer, 0, sizeof(buffer));
        
            ret = read(sck, buffer, SOCKET_BUFFER_SIZE);
            if (ret == -1) {
                close (sck);
                return "can not read answer";
            } 
        
            close (sck);
            return "ok";
        
        } catch (std::exception& e) {
            close (sck);
            return "docker_unixsocket: exception";
        }
    }

    return "docker_unixsocket: error";
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




