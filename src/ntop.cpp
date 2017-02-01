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

#include <zmq.h>
#include "ntop.h"

int Ntop::GetConfig(config_t cfg) {
    
    int flag;
    config_setting_t *list; 
    const char *base = NULL;
    
    //Read sinks config
    if(!sk.GetConfig(cfg)) return 0;
    
    if (!config_lookup_bool(&cfg, "sources.ntop.destination.graylog", &flag)) {
        SysLog("Ntop config - GrayLog flag is missing.");
        sk.SetStateGraylog(-1);
    }
    else sk.SetStateGraylog(flag);
    
    list = config_lookup(&cfg, "sources.ntop.filters.ip_list.black");
    
    if (list != 0) {
        size_list = config_setting_length(list);
        white_list = false;
        for (int i = 0; i < size_list; i++) {
            base = config_setting_get_string_elem(list, i);
            strncpy (black_list[i], base,  IP_SIZE);
        }
    }
    else {
        list = config_lookup(&cfg, "sources.ntop.filters.ip_list.white");
        if (list != 0) {
            size_list = config_setting_length(list);
            white_list = true;
            for (int i = 0; i < size_list; i++) {
                base = config_setting_get_string_elem(list, i);
                strncpy (black_list[i], base,  IP_SIZE);
            }
        }
    }
    
    if (config_lookup_string(&cfg, "sources.ntop.url", &base)) {
        if (!strcmp(base, "none")) state = 0;
        else {
            strncpy (url, base,  OS_HEADER_SIZE);
            state = 1;
        }
    }
    else goto return_with_error;
    
      
    return 1;
    
return_with_error:
    SysLog("Error in Ntop parameters.");
    return 0;
}

int  Ntop::OpenZmq(void) {
    context = zmq_ctx_new();
    subscriber = zmq_socket(context, ZMQ_SUB);
    
    rc = zmq_connect(subscriber, url);

    if (rc != 0) return 0;
    
    rc = zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, 0, 0);
    
    if (rc != 0) return 0;
    
    return 1;
}
    
    
int  Ntop::Open() {
    
    if (!sk.Open()) return 0;
    
    if (!OpenZmq()) {
        SysLog("Failed to connect to ntop server over zmq.");
        return 0;
    }
    
    return 1;
}

void  Ntop::Close() {
    
    sk.Close();
    
    if (!rc) {
        zmq_close(subscriber);
        zmq_ctx_destroy(context);
    }
    
}


int Ntop::Go(void) {
    
    time_t rawtime;
    struct tm * timeinfo;
    
    ResetPayload();
        
    // read Netflow data from port
    if (ReceiveEvent()) {
        // pars string to record of class
        ParsJson();
        
        if (CheckBlackList()) {
            //add rec to queue
            SendEvent();
            // 
        }
    }
    
    return 1;
}

bool Ntop::CheckBlackList() {
    int i;
    
    if (size_list != 0) {
        if (!white_list) { //check black list
            for (i = 0; i < size_list; i++) {
                if (strcmp(black_list[i], rec->dst_ip) == 0) return false;
                if (strcmp(black_list[i], rec->src_ip) == 0) return false;
            }
        }
        else { // check white list
            for (i = 0; i < size_list; i++) { 
                if (strcmp(black_list[i], rec->dst_ip) == 0) return true;
                if (strcmp(black_list[i], rec->src_ip) == 0) return true;
            }
            return false;
        }    
    }
    
    return true;
}


int Ntop::ReceiveEvent(void)
{
    struct zmq_msg_hdr h;
    int size;
    
    size = zmq_recv(subscriber, &h, sizeof(h), 0); 
    
    if (size != sizeof(h) || h.version != MSG_VERSION) {
        SysLog("Failed reading event from zmq for Ntop.");
        return 0;
    }
    
    size = zmq_recv(subscriber, payload, OS_LONG_BUFFER_SIZE, 0); 
    
    return 1;
}

void Ntop::ParsJson () {
    time_t rawtime;
    struct tm * timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(rec->datetime,sizeof(rec->datetime),"%Y-%m-%d %H:%M:%S",timeinfo);
    
    std::stringstream ss(payload);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    
    rec->flow_id = pt.get<int>("148",0);
        
    std::string src_ip = pt.get<std::string>("8","");
    strncpy (rec->src_ip, src_ip.c_str(), sizeof(rec->src_ip));
        
    std::string src_country = pt.get<std::string>("57573","");
    strncpy (rec->src_country, src_country.c_str(), sizeof(src_country));
    if (!strcmp(rec->src_country, "")) strncpy (rec->src_country, "Unknown\0", sizeof("Unknown\0"));
    
    rec->src_port = pt.get<int>("7",0);
    
    rec->src_tos = pt.get<int>("5",0);
    
    std::string dst_ip = pt.get<std::string>("12","");
    strncpy (rec->dst_ip, dst_ip.c_str(), sizeof(rec->dst_ip));
        
    std::string dst_country = pt.get<std::string>("57575","");
    strncpy (rec->dst_country, dst_country.c_str(), sizeof(dst_country));
    if (!strcmp(rec->dst_country, "")) strncpy (rec->dst_country, "Unknown\0", sizeof("Unknown\0"));
    
    rec->dst_port = pt.get<int>("11",0);
        
    rec->dst_tos = pt.get<int>("55",0);
        
    rec->in_bytes = pt.get<int>("1",0);
    
    rec->out_bytes = pt.get<int>("23",0);
    
    std::string protocol = pt.get<std::string>("58500","");
    strncpy (rec->protocol, protocol.c_str(), sizeof(rec->protocol));
    
    std::string l7protocol = pt.get<std::string>("57591","");
    strncpy (rec->l7protocol, l7protocol.c_str(), sizeof(rec->l7protocol));
    
}

void Ntop::SendEvent() {
    
    if (sk.GetStateGraylog()) {
        
        char level[OS_HEADER_SIZE];
    
        strncpy (payload, "{\"version\": \"1.1\",\"host\":\"", sizeof("{\"version\": \"1.1\",\"host\":\""));
        strncat (payload, probe_id, sizeof(probe_id));
        strncat (payload, "\",\"short_message\":\"", sizeof("\",\"short_message\":\""));
        strncat (payload, "nProbe", sizeof("nProbe"));
        strncat (payload, "\",\"full_message\":\"", sizeof("\",\"full_message\":\""));
        strncat (payload, "Ntop netflow sensor", sizeof("Ntop netflow sensor"));
        strncat (payload, "\",\"level\":", sizeof("\",\"level\":"));
        sprintf (level, "%d", 6);
        strncat (payload, level, sizeof(level));
        strncat (payload, ",\"_event_type\":\"nProbe\",\"_time_of_flow\":\"",sizeof(",\"_event_type\":\"nProbe\",\"_time_of_flow\":\""));
        strncat (payload, rec->datetime, sizeof(rec->datetime));
        strncat (payload, "\",\"_protocol\":\"", sizeof("\",\"_protocol\":\""));
        strncat (payload, rec->l7protocol, sizeof(rec->l7protocol));
        strncat (payload, "\",\"_srcip\":\"", sizeof("\",\"_srcip\":\""));
        strncat (payload, rec->src_ip, sizeof(rec->src_ip));
        strncat (payload, "\",\"_dstip\":\"", sizeof("\",\"_dstip\":\""));
        strncat (payload, rec->dst_ip, sizeof(rec->dst_ip));
        strncat (payload, "\",\"_srcport\":", sizeof("\",\"_srcport\":"));
        sprintf (level, "%d", rec->src_port);
        strncat (payload, level, sizeof(level));
        strncat (payload, ",\"_dstport\":", sizeof(",\"_dstport\":"));
        sprintf (level, "%d", rec->dst_port);
        strncat (payload, level, sizeof(level));
        strncat (payload, ",\"_inbytes\":", sizeof(",\"_inbytes\":"));
        sprintf (level, "%d", rec->in_bytes);
        strncat (payload, level, sizeof(level));
        strncat (payload, ",\"_outbytes\":", sizeof(",\"_outbytes\":"));
        sprintf (level, "%d", rec->out_bytes);
        strncat (payload, level, sizeof(level));
        strncat (payload, "}", sizeof("}"));
        
        sk.graylog.SendMessage(payload);
        
    }
}



