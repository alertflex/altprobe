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

#ifndef UPDATES_H
#define	UPDATES_H

#include <boost/asio.hpp>
#include "base64.h"
#include "controller.h"
#include "filters.h"

using boost::asio::ip::tcp;
using namespace std;

class Updates : public Controller,
        public ExceptionListener,
        public MessageListener {
public: 
    
    Destination* consumerCommand;
    MessageConsumer* consumer;
    int update_status;
    
    BinData bd;
    std::stringstream strStream, comp;
    
    FiltersSingleton fs;
        
    Updates() {
        consumer = NULL;
        update_status = 0;
    }
        
    virtual int Open(int mode, pid_t pid);
    virtual void Close();
    virtual int GetConfig();
    int GetStatus() {
        return update_status;
    }
    
    int Go();
    void onMessage(const Message* message);
    void onException(const CMSException& ex AMQCPP_UNUSED);
    string onBytesMessage(const Message* message);
    string onTextMessage(const Message* message);
    string SendArToWazuh(string agent, string json);
    string SendArToSuricata(string json);
    string CreateAgentWazuh(string json);
    string DockerContainer(string id, string cmd);
    
    string ScanDockerBench(void);
    string ScanKubeBench(void);
    string ScanKubeHunter(string target);
    string ScanNmap(string target);
    string ScanSnyk(string target);
    string ScanTrivy(string target);
    string ScanZap(string target);
    
    void ResetStreams() {
        comp.str("");
        comp.clear();
        strStream.str("");
        strStream.clear();
    }
    
    
    int IsHomeNetwork(string ip);
};

#endif	/* UPDATES_H */

