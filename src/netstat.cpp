/* 
 * File:   netstat.cpp
 * Author: Oleg Zharkov
 *
 * Created on May 15, 2020, 3:07 PM
 */

#include "netstat.h"

boost::lockfree::spsc_queue<Netstat> q_netstat{NET_QUEUE_SIZE};

