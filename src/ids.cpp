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

#include "ids.h"

boost::lockfree::spsc_queue<IdsRecord> q_hids{IDS_QUEUE_SIZE};
boost::lockfree::spsc_queue<IdsRecord> q_nids{IDS_QUEUE_SIZE};
boost::lockfree::spsc_queue<IdsRecord> q_crs{IDS_QUEUE_SIZE};
boost::lockfree::spsc_queue<IdsRecord> q_waf{IDS_QUEUE_SIZE};
boost::lockfree::spsc_queue<IdsRecord> q_aws_waf{IDS_QUEUE_SIZE};
