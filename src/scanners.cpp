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
            
            string log = "listens scanners bus";
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
            SysLog("ActiveMQ CMS Exception occurred: scanners module");
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
        SysLog("ActiveMQ CMS Exception occurred: scanners module");
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
    SysLog("ActiveMQ CMS Exception occurred: scanners module");
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
    
    string container =  pt.get<string>("actuator.x-alertflex.container","indef");
    
    int delay = pt.get<int>("args.delay",0);
        
    
    if(!actuator_profile.compare("indef") || !action.compare("indef")) {
    
        return "\"status\": 400, \"status_text\": \"wrong actuator or action\" }"; 
    } 
    
    if(!actuator_profile.compare("dependency_check")) {
        
        if(!action.compare("scan")) {
                    
            try {
                
                string target = pt.get<string>("target.device.device_id","indef");
                        
                if(!target.compare("indef") && !container.compare("indef")) {
    
                    return "\"status\": 400, \"status_text\": \"wrong target or container\" }"; 
                } 
            
                string res =  ScanDependencyCheck(target, container, delay);
                        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong response\" }"; 
            }
                
        } 
    }
    
    if(!actuator_profile.compare("docker_bench")) {
        
        if(!action.compare("scan")) {
                    
            try {
                
                string res =  ScanDockerBench(container, delay);
                        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong response\" }"; 
            }
                
        } 
    }
    
    if(!actuator_profile.compare("kube_bench")) {
        
        if(!action.compare("scan")) {
                    
            try {
            
                string res =  ScanKubeBench(container, delay);
                        
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
                        
                if(!target.compare("indef") && !container.compare("indef")) {
    
                    return "\"status\": 400, \"status_text\": \"wrong target or container\" }"; 
                } 
            
                string res =  ScanKubeHunter(target, container, delay);
                        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong response\" }"; 
            }
                
        } 
    }
    
    if(!actuator_profile.compare("sonarqube")) {
        
        if(!action.compare("scan")) {
                    
            try {
                
                string target = pt.get<string>("target.device.device_id","indef");
                        
                if(!target.compare("indef") && !container.compare("indef")) {
    
                    return "\"status\": 400, \"status_text\": \"wrong target or container\" }"; 
                } 
            
                string res =  ScanSonarQube(target, container, delay);
                        
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
                
                if(!target.compare("indef") && !container.compare("indef")) {
    
                    return "\"status\": 400, \"status_text\": \"wrong target or container\" }"; 
                } 
            
                string res =  ScanTrivy(target, container, delay);
                        
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
                
                if(!target.compare("indef") && !container.compare("indef")) {
    
                    return "\"status\": 400, \"status_text\": \"wrong target or container\" }"; 
                } 
            
                string res =  ScanZap(target, container, delay);
                        
                return res;
            
            } catch (const std::exception & ex) {
                return "\"status\": 400, \"status_text\": \"wrong response\" }"; 
            }
                
        } 
    }
    
    return "\"status\": 400, \"status_text\": \"wrong actuator or action\" }";
}

string Scanners::ScanDependencyCheck(string target, string container, int delay) {
    
    try {
        
        std::remove(dependencycheck_result);
        
        if(!container.compare("indef")) {
        
            string cmd = "/etc/altprobe/scripts/dependency-check.sh " + target;
        
            system(cmd.c_str());
        
        } else {
            
            string res = DockerCommand(container, "start");
        
            if (res.compare("ok")) {
                return "dependency-check container: error";
            }
            
            int res_wait = 0;
            int i = 0;
            for (; i < delay && res_wait == 0; i++) {
                sleep(1);
                res_wait = DockerWait(container);
            }
            
            if(res_wait == 0) return "dependency-check container: error";
        }
        
        std::ifstream dependencycheck_report;
        
        dependencycheck_report.open(dependencycheck_result,ios::binary);
        strStream << dependencycheck_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 5;
        bd.target = target;
        SendMessage(&bd);
                
        dependencycheck_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "dependency-check: error";
    } 
    
    return "\"status\": 200 }";
    
}

string Scanners::ScanDockerBench(string container, int delay) {
    
    try {
        
         std::remove(dockerbench_result);
        
        // command example - cd /root/docker-bench-security && sh docker-bench-security.sh -l report
        
        if(!container.compare("indef")) {
        
            string cmd = "/etc/altprobe/scripts/docker-bench.sh";
        
            system(cmd.c_str());
        
        } else {
             
            string res = DockerCommand(container, "start");
        
            if (res.compare("ok")) {
                return "docker-bench container: error";
            }
            
            int res_wait = 0;
            int i = 0;
            for (; i < delay && res_wait == 0; i++) {
                sleep(1);
                res_wait = DockerWait(container);
            }
            
            if(res_wait == 0) return "docker-bench container: error";
        }
        
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
        bd.event_type = 6;
        SendMessage(&bd);
                
        docker_report.close();
        boost::iostreams::close(in);
        ResetStreams();
       
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "docker_bench: error";
    } 
    
    return "\"status\": 200 }";
    
}

string Scanners::ScanKubeBench(string container, int delay) {
    
    try {
        
        std::remove(kubebench_result);
        
        if(!container.compare("indef")) {
        
            string cmd = "/etc/altprobe/scripts/kube-bench.sh";
        
            system(cmd.c_str());
        
        } else {
             
            string res = DockerCommand(container, "start");
        
            if (res.compare("ok")) {
                return "kube-bench container: error";
            }
            
            int res_wait = 0;
            int i = 0;
            for (; i < delay && res_wait == 0; i++) {
                sleep(1);
                res_wait = DockerWait(container);
            }
            
            if(res_wait == 0) return "kube-bench container: error";
        }
        
        std::ifstream kubebench_report;
        
        kubebench_report.open(kubebench_result,ios::binary);
        strStream << kubebench_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 7;
        SendMessage(&bd);
                
        kubebench_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "kube_bench: error";
    } 
    
    return "\"status\": 200 }";
    
}

string Scanners::ScanKubeHunter(string target, string container, int delay) {
    
    try {
        
        std::remove(kubehunter_result);
        
        if(!container.compare("indef")) {
        
            string cmd = "/etc/altprobe/scripts/kube-hunter.sh " + target;
        
            system(cmd.c_str());
        
        } else {
             
            string res = DockerCommand(container, "start");
        
            if (res.compare("ok")) {
                return "kube-hunter container: error";
            }
            
            int res_wait = 0;
            int i = 0;
            for (; i < delay && res_wait == 0; i++) {
                sleep(1);
                res_wait = DockerWait(container);
            }
            
            if(res_wait == 0) return "kube-hunter container: error";
        }
        
        std::ifstream kubehunter_report;
        
        kubehunter_report.open(kubehunter_result,ios::binary);
        strStream << kubehunter_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 8;
        bd.target = target;
        SendMessage(&bd);
                
        kubehunter_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "kube_hunter: error";
    } 
    
    return "\"status\": 200 }";
    
}


string Scanners::ScanSonarQube(string target, string container, int delay) {
    
    try {
        
        if(!container.compare("indef")) {
        
            string cmd = "/etc/altprobe/scripts/sonarqube.sh " + target;
        
            system(cmd.c_str());
        
        } else {
             
            string res = DockerCommand(container, "start");
        
            if (res.compare("ok")) {
                return "sonarqube container: error";
            }
            
            int res_wait = 0;
            int i = 0;
            for (; i < delay && res_wait == 0; i++) {
                sleep(1);
                res_wait = DockerWait(container);
            }
            
            if(res_wait == 0) return "sonarqube container: error";
        }
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "sonarqube: error";
    } 
    
    return "\"status\": 200 }";
    
}


string Scanners::ScanTrivy(string target, string container, int delay) {
    
    try {
        
        std::remove(trivy_result);
        
        if(!container.compare("indef")) {
        
            string cmd = "/etc/altprobe/scripts/trivy.sh " + target;
        
            system(cmd.c_str());
        
        } else {
             
            string res = DockerCommand(container, "start");
        
            if (res.compare("ok")) {
                return "trivy container: error";
            }
            
            int res_wait = 0;
            int i = 0;
            for (; i < delay && res_wait == 0; i++) {
                sleep(1);
                res_wait = DockerWait(container);
            }
            
            if(res_wait == 0) return "trivy container: error";
        }
        
        std::ifstream trivy_report;
        
        trivy_report.open(trivy_result,ios::binary);
        strStream << trivy_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 9;
        bd.target = target;
        SendMessage(&bd);
                
        trivy_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "trivy: error";
    } 
    
    return "\"status\": 200 }";
    
}

string Scanners::ScanZap(string target, string container, int delay) {
    
    try {
        
        std::remove(zap_result);
        
        if(!container.compare("indef")) {
        
            string cmd = "/etc/altprobe/scripts/zap.sh " + target;
        
            system(cmd.c_str());
        
        } else {
             
            string res = DockerCommand(container, "start");
        
            if (res.compare("ok")) {
                return "zap container: error";
            }
            
            int res_wait = 0;
            int i = 0;
            for (; i < delay && res_wait == 0; i++) {
                sleep(1);
                res_wait = DockerWait(container);
            }
            
            if(res_wait == 0) return "zap container: error";
        }
        
        std::ifstream zap_report;
        
        zap_report.open(zap_result,ios::binary);
        strStream << zap_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 10;
        bd.target = target;
        SendMessage(&bd);
                
        zap_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return "zap: error";
    } 
    
    return "\"status\": 200 }";
    
}

string Scanners::DockerCommand(string id, string cmd) {
    
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

int Scanners::DockerWait(string id) {
    
    int sck;
    struct sockaddr_un addr;
    int ret;
    
    char* buffer;
    buffer = new char[SOCKET_BUFFER_SIZE];
    
    if (dockerSocketStatus) {
    
        try {
            
            /* create socket */
            sck = socket(AF_UNIX, SOCK_STREAM, 0);
            if (sck == -1) {
                delete [] buffer;
                close (sck);
                return 0;
            }
            
            /* set address */
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, docker_socket, sizeof(addr.sun_path));
            addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

            /* Connect to unix socket */
            ret = connect(sck, (struct sockaddr *) &addr, sizeof(addr));
            if (ret == -1) {
                delete [] buffer;
                close (sck);
                return 0;
            }
        
            std::string req = "POST /v1.40/containers/";
            req += id;
            req += "/wait";
            req += " HTTP/1.1\r\n";
            req += "Host: localhost\r\n";
            req += "Accept: */*\r\n\r\n";
        
            int siz = req.size();

            ret = send(sck, req.c_str(), siz, 0);
            if (ret == -1) {
                delete [] buffer;
                close (sck);
                return 0;
            } else if (ret < siz) {
                delete [] buffer;
                close (sck);
                return 0;
            }
        
            ret = read(sck, buffer, SOCKET_BUFFER_SIZE);
            if (ret == -1) {
                delete [] buffer;
                close (sck);
                return 0;
            } 
            
            char res = ' ';
            int j = 0;
            
            for (int i = 0; i < SOCKET_BUFFER_SIZE; i++) {
            
                char test = (char) buffer[i];
            
                if (j == 12) {
                    
                    res = test;
                    
                    if (res == '0') {
                        delete [] buffer;
                        close (sck);
                        return 1;
                    }
                    
                    break;
                }
            
                if ( test == '\n') j++;
            }
        
        } catch (std::exception& e) {
            
        }
        
        close (sck);
    }

    delete [] buffer;
    return 0;
}



