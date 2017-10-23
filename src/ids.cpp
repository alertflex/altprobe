/* 
 * File:   ids.cpp
 * Author: Oleg Zharkov
 *
 * Created on February 27, 2014, 3:07 PM
 */

#include "ids.h"

boost::lockfree::spsc_queue<IdsRecord> q_ids{IDS_QUEUE_SIZE};
