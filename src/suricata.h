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

#ifndef SURICATA_H
#define	SURICATA_H

#include "sinks.h"

class SuricataAlert
{
public:
    char action[OS_HEADER_SIZE];
    unsigned int gid;
    unsigned int signature_id;
    unsigned int rev;
    char signature[OS_BUFFER_SIZE];
    char category[OS_LONG_HEADER_SIZE];
    unsigned int severity;
    
    void Reset() {
        memset(action, 0, sizeof(action));
        gid = 0;
        signature_id = 0;
        rev = 0;
        memset(signature, 0, sizeof(signature));
        memset(category, 0, sizeof(category));
        severity = 0;
    }
};

//  Suricata record                              
class SuricataRecord {
public:
    
    // *** Common fields
    char time_stamp[OS_DATETIME_SIZE];
    unsigned int flow_id;
    char in_iface[PORT_SIZE];
    char event_type[OS_HEADER_SIZE];
    char src_ip[IP_SIZE];
    unsigned int src_port;
    char dst_ip[IP_SIZE];
    unsigned int dst_port;
    char protocol[OS_HEADER_SIZE];
    char payload_printable[OS_MAXSTR_SIZE];
    unsigned int stream;
    char datetime[OS_DATETIME_SIZE]; 
    
    //  Record  Alert 
    SuricataAlert alert;
    
    void Reset() {
        //reset rule class object
        memset(time_stamp, 0, sizeof(time_stamp));
        flow_id = 0;
        memset(in_iface, 0, sizeof(in_iface));
        memset(event_type, 0, sizeof(event_type));
        memset(src_ip, 0, sizeof(src_ip));
        src_port = 0;
        memset(dst_ip, 0, sizeof(dst_ip));
        dst_port = 0;
        memset(protocol, 0, sizeof(protocol));
        memset(payload_printable, 0, sizeof(payload_printable));
        unsigned int stream = 0;
        memset(datetime, 0, sizeof(datetime));
        
        alert.Reset();
    }
};


class Suricata : public ProbeObject {
public:  
    
    int state;
    
    Sinks sk;
    
    //Suricata record
    SuricataRecord rec;
    
    // Evo file variables
    char path_to_log[OS_HEADER_SIZE];
    
    FILE *fp;
    fpos_t fp_pos;
    
    //Socket parameters
    int s;
    struct sockaddr_un srv_un;
        
    //JSON string from suricata
    char payload[OS_PAYLOAD_SIZE];
    
        
    int black_list[BLACKLIST_SIZE];
    int white_list[BLACKLIST_SIZE];
    int size_black_list; 
    int size_white_list; 
    
    int alerts_priority;
    
    
    Suricata () {
        alerts_priority = 2;
        size_black_list = 0;
        size_white_list = 0;
        rec.Reset();
    }
    
    int Open();
    void Close();
    
    virtual int GetConfig(config_t cfg);
    int Go();
    
        
    int OpenFile();
    int ParsJson();
    bool CheckBlackList();
    bool CheckWhiteList();
    void SendEvent();
    int GetState() { return state; }
    
    void ResetPayload() {
        memset(payload, 0, sizeof(payload));
    }
    
};

#endif	/* SURICATA_H */

