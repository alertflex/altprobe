/* 
 * File:   netflow.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */

#include "netflow.h"

boost::lockfree::spsc_queue<NetflowRecord> q_netflow{NETFLOW_QUEUE_SIZE};