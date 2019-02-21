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
    
    MessageConsumer* consumer;
    int update_status;
    
    FiltersSingleton fs;
        
    Updates() {
        consumer = NULL;
        update_status = 0;
    }
        
    virtual int Open();
    virtual void Close();
    virtual bool Reset();
    virtual int GetConfig();
    int GetStatus() {
        return update_status;
    }
    
    int Go();
    void RoutineJob();
    void onMessage(const Message* message);
    void onException(const CMSException& ex AMQCPP_UNUSED);
    int IsHomeNetwork(string ip);   
    int SendArToWazuh(string agent, string json);
    int SendToIpset(string ip);
};

#endif	/* UPDATES_H */

