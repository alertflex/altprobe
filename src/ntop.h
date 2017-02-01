/**
 * This file is part of Altprobe.
 *
 * Altprobe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Altprobe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Altprobe.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NTOP_H
#define	NTOP_H

#include "sinks.h"

class FlowRecord
{
public:
    unsigned long flow_id;
    char src_ip[IP_SIZE];             
    char src_country[OS_BUFFER_SIZE];    
    unsigned int src_port; 
    unsigned int src_tos;
    char dst_ip[IP_SIZE];         
    char dst_country[OS_BUFFER_SIZE];   
    unsigned int dst_port; 
    unsigned int dst_tos;
    unsigned int in_bytes;         
    unsigned int out_bytes;          
    char protocol[OS_HEADER_SIZE];           
    char l7protocol[OS_HEADER_SIZE]; 
    char datetime[OS_DATETIME_SIZE];      
    
    void Reset() {
        flow_id = 0;
        memset(src_ip, 0, sizeof(src_ip));
        memset(src_country, 0, sizeof(src_country));
        src_port = 0;
        src_tos = 0;
        memset(dst_ip, 0, sizeof(dst_ip));
        memset(dst_country, 0, sizeof(dst_country));
        dst_port = 0;
        dst_tos = 0;
        in_bytes = 0;
        out_bytes = 0;
        memset(protocol, 0, sizeof(protocol));
        memset(l7protocol, 0, sizeof(l7protocol));
        memset(datetime, 0, sizeof(datetime));
    }
    
    FlowRecord () {
        Reset();
    }
};


class Ntop : public ProbeObject {
public:  
    int state;
    
    Sinks sk;
    
    // ZeroMQ variables
    char url[OS_HEADER_SIZE];
    
    void* context;
    void* subscriber;
    int rc;
    
    //Traffic stat record
    FlowRecord* rec;

    
    //JSON string from netflow
    char payload[OS_LONG_BUFFER_SIZE];
        
    char black_list[BLACKLIST_SIZE][IP_SIZE];
    int size_list; //block_list is not using if size_list=0 
    bool white_list; 
    
    Ntop () {
        // create new Flow record
        rec = new FlowRecord();
    }
    
    int Open();
    void Close();
    
    virtual int GetConfig(config_t cfg);
    int Go();
    
        
    int OpenZmq();
    void ParsJson ();
    bool CheckBlackList();
    int ReceiveEvent();
    void SendEvent();
    int GetState() { return state; }
    
    void ResetPayload() {
        memset(payload, 0, sizeof(payload));
    }
};

#endif	/* NTOP_H */