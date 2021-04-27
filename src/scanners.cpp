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

#include "scanners.h"

#define SOCKET_BUFFER_SIZE 2048

namespace bpt = boost::property_tree;

int Scanners::GetConfig() {
       
    update_status = 1;
    return update_status;
}

int Scanners::Open(int mode, pid_t pid) {
    
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
            
            string ref_id;
            
            if(project_id.compare(fs.filter.ref_id) && project_id.compare("indef")) {
                ref_id = project_id;
            } else {
                ref_id = fs.filter.ref_id;
            }
            
            // Create the MessageConsumer
            string strConsumer("jms/altprobe/" + ref_id + "/" + node_id + "/" + probe_id + "/scanners");
            
            Destination* consumerCommand = session->createQueue(strConsumer);
            
            // Create a MessageConsumer from the Session to the Topic or Queue
            consumer = session->createConsumer(consumerCommand);
 
            consumer->setMessageListener(this);
            
            mq_counter++;
        
            amq_conn = true;
            
            string log = "Altprobe listen scanners bus";
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

int Scanners::Go(void) {
    
    sleep(1);
        
    return 1;
}

// Called from the consumer since this class is a registered MessageListener.
void Scanners::onMessage(const Message* message) {
    
    try {
        
        string corr_id = message->getCMSCorrelationID();
        string headerJson = "{ \"request_id\": \"" +  corr_id + "\", ";
        string bodyJson = "\"status\": 400 }";        
        
        if (dynamic_cast<const TextMessage*> (message)) {
            bodyJson = onTextMessage(message);
        } else {
            SysLog("ActiveMQ CMS Exception occurred: update module");
            CheckStatus();
            return;
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
void Scanners::onException(const CMSException& ex AMQCPP_UNUSED) {
    SysLog("ActiveMQ CMS Exception occurred: update module");
    CheckStatus();
}

void Scanners::Close() {
    
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

string Scanners::onTextMessage(const Message* message) {
    
    const TextMessage* textMessage = dynamic_cast<const TextMessage*> (message);
                
    string c2json = textMessage->getText();
    
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
    
    if(!actuator_profile.compare("docker_bench")) {
        
        if(!action.compare("scan")) {
                    
            try {
            
                string res =  ScanDockerBench();
                        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong response\" }"; 
            }
                
        } 
    }
    
    if(!actuator_profile.compare("kube_bench")) {
        
        if(!action.compare("scan")) {
                    
            try {
            
                string res =  ScanKubeBench();
                        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong response\" }"; 
            }
                
        } 
    }
    
    if(!actuator_profile.compare("kube_hunter")) {
        
        if(!action.compare("scan")) {
                    
            try {
                
                string target = pt.get<string>("target.device.device_id","indef");
                        
                if(!target.compare("indef")) {
    
                    return "\"status\": 400, \"status_text\": \"wrong target\" }"; 
                } 
            
                string res =  ScanKubeHunter(target);
                        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong response\" }"; 
            }
                
        } 
    }
    
    if(!actuator_profile.compare("nmap")) {
        
        if(!action.compare("scan")) {
                    
            try {
                
                string target = pt.get<string>("target.device.device_id","indef");
                        
                if(!target.compare("indef")) {
    
                    return "\"status\": 400, \"status_text\": \"wrong target\" }"; 
                } 
            
                string res =  ScanNmap(target);
                        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong response\" }"; 
            }
                
        } 
    }
    
    if(!actuator_profile.compare("snyk")) {
        
        if(!action.compare("scan")) {
                    
            try {
                
                string target = pt.get<string>("target.device.device_id","indef");
                        
                if(!target.compare("indef")) {
    
                    return "\"status\": 400, \"status_text\": \"wrong target\" }"; 
                } 
            
                string res =  ScanSnyk(target);
                        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong response\" }"; 
            }
                
        } 
    }
    
    if(!actuator_profile.compare("trivy")) {
        
        if(!action.compare("scan")) {
                    
            try {
                
                string target = pt.get<string>("target.device.device_id","indef");
                        
                if(!target.compare("indef")) {
    
                    return "\"status\": 400, \"status_text\": \"wrong target\" }"; 
                } 
            
                string res =  ScanTrivy(target);
                        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong response\" }"; 
            }
                
        } 
    }
    
    if(!actuator_profile.compare("zap")) {
        
        if(!action.compare("scan")) {
                    
            try {
                
                string target = pt.get<string>("target.device.device_id","indef");
                        
                if(!target.compare("indef")) {
    
                    return "\"status\": 400, \"status_text\": \"wrong target\" }"; 
                } 
            
                string res =  ScanZap(target);
                        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong response\" }"; 
            }
                
        } 
    }
    
    return "\"status\": 400, \"status_text\": \"wrong actuator or action\" }";
}

string Scanners::ScanDockerBench(void) {
    
    try {
        
        // command example - cd /root/docker-bench-security && sh docker-bench-security.sh -l report
        
        string cmd = "/etc/altprobe/scripts/docker-bench.sh";
        
        system(cmd.c_str());
        
        std::ifstream docker_report;
        
        // dockerbench_result is a path to result.json for example - /root/docker-bench-security/report.json
        docker_report.open(dockerbench_result,ios::binary);
        strStream << docker_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 5;
        SendMessage(&bd);
                
        docker_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "docker_bench: error";
    } 
    
    return "ok";
    
}

string Scanners::ScanKubeBench(void) {
    
    try {
        
        string cmd = "/etc/altprobe/scripts/kube-bench.sh";
        
        system(cmd.c_str());
        
        std::ifstream kubebench_report;
        
        kubebench_report.open(kubebench_result,ios::binary);
        strStream << kubebench_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 6;
        SendMessage(&bd);
                
        kubebench_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "kube_bench: error";
    } 
    
    return "ok";
    
}

string Scanners::ScanKubeHunter(string target) {
    
    try {
        
        string cmd = "/etc/altprobe/scripts/kube-hunter.sh " + target;
        
        system(cmd.c_str());
        
        std::ifstream kubehunter_report;
        
        kubehunter_report.open(kubehunter_result,ios::binary);
        strStream << kubehunter_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 7;
        bd.target = target;
        SendMessage(&bd);
                
        kubehunter_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "kube_hunter: error";
    } 
    
    return "ok";
    
}


string Scanners::ScanNmap(string target) {
    
    try {
        
        string cmd = "/etc/altprobe/scripts/nmap.sh " + target;
        
        system(cmd.c_str());
        
        std::ifstream nmap_report;
        
        nmap_report.open(nmap_result,ios::binary);
        strStream << nmap_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 8;
        bd.target = target;
        SendMessage(&bd);
                
        nmap_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "nmap: error";
    } 
    
    return "ok";
    
}

string Scanners::ScanSnyk(string target) {
    
    try {
        
        string cmd = "/etc/altprobe/scripts/snyk.sh " + target;
        
        system(cmd.c_str());
        
        std::ifstream snyk_report;
        
        snyk_report.open(snyk_result,ios::binary);
        strStream << snyk_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 9;
        bd.target = target;
        SendMessage(&bd);
                
        snyk_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "snyk: error";
    } 
    
    return "ok";
    
}

string Scanners::ScanTrivy(string target) {
    
    try {
        
        string cmd = "/etc/altprobe/scripts/trivy.sh " + target;
        
        system(cmd.c_str());
        
        std::ifstream trivy_report;
        
        trivy_report.open(trivy_result,ios::binary);
        strStream << trivy_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 10;
        bd.target = target;
        SendMessage(&bd);
                
        trivy_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "trivy: error";
    } 
    
    return "ok";
    
}

string Scanners::ScanZap(string target) {
    
    try {
        
        string cmd = "/etc/altprobe/scripts/zap.sh " + target;
        
        system(cmd.c_str());
        
        std::ifstream zap_report;
        
        zap_report.open(zap_result,ios::binary);
        strStream << zap_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 11;
        bd.target = target;
        SendMessage(&bd);
                
        zap_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "zap: error";
    } 
    
    return "ok";
    
}




