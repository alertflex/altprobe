/* 
 * File:   flows.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */

#include "flows.h"

boost::lockfree::spsc_queue<FlowsRecord> q_flows{FLOWS_QUEUE_SIZE};
boost::lockfree::spsc_queue<Traffic> q_netstat{NETSTAT_QUEUE_SIZE};