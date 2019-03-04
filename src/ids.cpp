/* 
 * File:   ids.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */

#include "ids.h"

boost::lockfree::spsc_queue<IdsRecord> q_hids{IDS_QUEUE_SIZE};
boost::lockfree::spsc_queue<IdsRecord> q_nids{IDS_QUEUE_SIZE};
boost::lockfree::spsc_queue<IdsRecord> q_waf{IDS_QUEUE_SIZE};
