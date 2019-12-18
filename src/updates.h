/* 
 * File:   updates.h
 * Author: olegzhr
 *
 * Created on November 23, 2017, 3:47 AM
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
    
    Destination* consumerTopic;
    MessageConsumer* consumer;
    int update_status;
    
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
    int IsHomeNetwork(string ip);   
    int SendArToWazuh(string agent, string json);
    string CreateAgentWazuh(string json);
};

#endif	/* UPDATES_H */

