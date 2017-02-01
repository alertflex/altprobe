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
 
#include "suricata.h"


int Suricata::GetConfig(config_t cfg) {
    int flag;
    config_setting_t *list; 
    const char *base = NULL;
    
    //Read sinks config
    if(!sk.GetConfig(cfg)) return 0;
    
    if (!config_lookup_bool(&cfg, "sources.suricata.destination.mysql", &flag)) {
        SysLog("Suricata config - MySQL flag is missing.");
        sk.SetStateMysql(-1);
    }
    else sk.SetStateMysql(flag);
    
    if (!config_lookup_bool(&cfg, "sources.suricata.destination.graylog", &flag)) {
        SysLog("Suricata config - GrayLog flag is missing.");
        sk.SetStateGraylog(-1);
    }
    else sk.SetStateGraylog(flag);
    
    list = config_lookup(&cfg, "sources.suricata.filters.rules_list.black");
    if (list != 0) {
        size_black_list = config_setting_length(list);
        for (int i = 0; i < size_black_list; i++) black_list[i] = config_setting_get_int_elem(list, i);
    }
    
    list = config_lookup(&cfg, "sources.suricata.filters.rules_list.white");
    if (list != 0) {
        size_white_list = config_setting_length(list);
        for (int i = 0; i < size_white_list; i++) white_list[i] = config_setting_get_int_elem(list, i);
    }
    
    if (config_lookup_string(&cfg, "sources.suricata.file", &base)) {
        if (!strcmp(base, "none")) state = 0;
        else {
            strncpy (path_to_log, base,  OS_HEADER_SIZE);
            state = 1;
        }
    }
    else goto return_with_error;
    
    config_lookup_int(&cfg, "sources.suricata.filters.priority", &alerts_priority);
    
    return 1;
    
return_with_error:
    SysLog("Error in Suricata parameters.");
    return 0;
}

int Suricata::OpenFile(void) {
    
    /*fp = fopen(path_to_log, "r");
    if(fopen == NULL) return 0;
    
    fseek(fp,0,SEEK_END);
      
    return 1;*/
    
    if ((s = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
        SysLog("Failed open socket for Suricata.");
        return 0;
    }
      
    
    srv_un.sun_family = AF_UNIX;
    strncpy(srv_un.sun_path, path_to_log, sizeof(srv_un.sun_path));
    /*If you leave the file behind when you're finished, or perhaps crash after binding, the next bind will fail
    / with "address in use". Which just means, the file is already there.*/
    unlink(srv_un.sun_path); 
    
    if ( ::bind(s, (struct sockaddr *) &srv_un, sizeof(srv_un)) == -1) {
        SysLog("Failed bind to socket for Suricata.");
        return 0;
    }
    
    
    return 1;
}
    
    
int Suricata::Open() {
    
    if (!sk.Open()) return 0;
    
    if (!OpenFile()) {
        SysLog("Failed open eve file for Suricata server.");
        return 0;
    }
    
    rec.Reset();
    
    return 1;
    
}

void Suricata::Close() {
    
    sk.Close();
    
    close(s);
    unlink(srv_un.sun_path);
    //if (fp != NULL) fclose(fp);
}


int Suricata::Go(void) {
    
    time_t rawtime;
    struct tm * timeinfo;
    
    ResetPayload();
        
    // read NIDS data from port
    switch (read(s, payload, OS_PAYLOAD_SIZE)) 
    {
        case 0: 
            //usleep(1000);
            break;
            
        case -1:
            SysLog("Failed reading events from eve/socket file of Suricata.");
            break;
        default: 
            if((ParsJson() == 1) && !CheckBlackList()) {
                
                if (!CheckWhiteList()) {
                    if(alerts_priority >= rec.alert.severity) SendEvent();
                }
                else SendEvent();
            }
            
    }
        
    return 1;
}



bool Suricata::CheckBlackList() {
    int i;
    
    if (size_black_list != 0)
        for (i = 0; i < size_black_list; i++) 
            if (black_list[i] == rec.alert.signature_id) return true;
    
    return false;
}

bool Suricata::CheckWhiteList() {
    int i;
    
    if (size_white_list != 0) 
        for (i = 0; i < size_white_list; i++) 
                if (white_list[i] == rec.alert.signature_id) return true;
        
    return false;
}

/*
int Suricata::ReadRecord(void) 
{
    if (fgets(payload, OS_MAXSTR_SIZE, fp) == NULL) {
        if (feof(fp)) return 0;
        
        SysLog("Failed reading events from eve file of Suricata.");
        return -1;
    }
    return 1;
}*/

int Suricata::ParsJson (void) {
    time_t rawtime;
    struct tm * timeinfo;
    
    std::stringstream ss(payload);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    
    boost::optional< boost::property_tree::ptree& > alert = pt.get_child_optional( "alert" );
    
    if (alert)
    {
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        strftime(rec.datetime,sizeof(rec.datetime),"%Y-%m-%d %H:%M:%S",timeinfo);
        
        std::string event_timestamp = pt.get<std::string>("timestamp","");
        strncpy (rec.time_stamp, event_timestamp.c_str(), sizeof(rec.time_stamp));
        
        rec.flow_id = pt.get<int>("flow_id",0);
        
        std::string event_in_iface = pt.get<std::string>("in_iface","");
        strncpy (rec.in_iface, event_in_iface.c_str(), sizeof(rec.in_iface));
        
        std::string event_type = pt.get<std::string>("event_type","");
        strncpy (rec.event_type, event_type.c_str(), sizeof(rec.event_type));
        
        std::string event_src_ip = pt.get<std::string>("src_ip","");
        strncpy (rec.src_ip, event_src_ip.c_str(), sizeof(rec.src_ip));
        
        rec.src_port = pt.get<int>("src_port",0);
        
        std::string event_dst_ip = pt.get<std::string>("dest_ip","");
        strncpy (rec.dst_ip, event_dst_ip.c_str(), sizeof(rec.dst_ip));
        
        rec.dst_port = pt.get<int>("dest_port",0);
        
        std::string event_protocol = pt.get<std::string>("proto","");
        strncpy (rec.protocol, event_protocol.c_str(), sizeof(rec.protocol));
        
        std::string event_payload_printable = pt.get<std::string>("payload_printable","");
        strncpy (rec.payload_printable, event_payload_printable.c_str(), sizeof(rec.payload_printable));
        for (int i=0; (i < OS_MAXSTR_SIZE) || rec.payload_printable[i] == '\0'; i++) {
            if (rec.payload_printable[i] == '\'' || rec.payload_printable[i] == '\"' || rec.payload_printable[i] == '\\') rec.payload_printable[i] = ' ';
        }
        
        rec.stream = pt.get<int>("stream",0); 
        
        // alert record
        std::string alert_action = pt.get<std::string>("alert.action","");
        strncpy (rec.alert.action, alert_action.c_str(), sizeof(rec.alert.action));
        
        rec.alert.gid = pt.get<int>("alert.gid",0); 
        rec.alert.signature_id = pt.get<int>("alert.signature_id",0); 
        rec.alert.rev = pt.get<int>("alert.rev",0);
        
        std::string alert_signature = pt.get<std::string>("alert.signature","");
        strncpy (rec.alert.signature, alert_signature.c_str(), sizeof(rec.alert.signature));
        
        std::string alert_category = pt.get<std::string>("alert.category","");
        strncpy (rec.alert.category, alert_category.c_str(), sizeof(rec.alert.category));
        
        rec.alert.severity = pt.get<int>("alert.severity",0);
        if (rec.alert.severity == 0) rec.alert.severity = 4;
        
        return 1;
    }
    return 0;
}

void Suricata::SendEvent() {
    
    char sqlQuery[OS_PAYLOAD_SIZE+1];
    int cx;
    
    if (sk.GetStateGraylog()) {
        
        char level[OS_HEADER_SIZE];
    
        strncpy (payload, "{\"version\": \"1.1\",\"host\":\"", sizeof("{\"version\": \"1.1\",\"host\":\""));
        strncat (payload, probe_id, sizeof(probe_id));
        strncat (payload, "\",\"short_message\":\"", sizeof("\",\"short_message\":\""));
        strncat (payload, "Suricata", sizeof("Suricata"));
        strncat (payload, "\",\"full_message\":\"", sizeof("\",\"full_message\":\""));
        strncat (payload, "Suricata IDS", sizeof("Suricata IDS"));
        strncat (payload, "\",\"level\":", sizeof("\",\"level\":"));
        sprintf (level, "%d", rec.alert.severity);
        strncat (payload, level, sizeof(level));
        strncat (payload, ",\"_event_type\":\"Suricata\",",sizeof(",\"_event_type\":\"suricata\","));
        strncat (payload, "\"_time_of_event\":\"", sizeof("\"_time_of_event\":\""));
        strncat (payload, rec.datetime, sizeof(rec.datetime));
        strncat (payload, "\",\"_time_stamp\":\"", sizeof("\",\"_time_stamp\":\""));
        strncat (payload, rec.time_stamp, sizeof(rec.time_stamp));
        strncat (payload, "\",\"_flow_id\":", sizeof("\",\"_flow_id\":"));
        sprintf (level, "%d", rec.flow_id);
        strncat (payload, level, sizeof(level));
        strncat (payload, ",\"_stream\":", sizeof(",\"_stream\":"));
        sprintf (level, "%d", rec.stream);
        strncat (payload, level, sizeof(level));
        strncat (payload, ",\"_in_iface\":\"", sizeof(",\"_in_iface\":\""));
        strncat (payload, rec.in_iface, sizeof(rec.in_iface));
        strncat (payload, "\",\"category\":\"", sizeof("\",\"category\":\""));
        strncat (payload, rec.alert.category, sizeof(rec.alert.category));
        strncat (payload, "\",\"signature\":\"", sizeof("\",\"signature\":\""));
        strncat (payload, rec.alert.signature, sizeof(rec.alert.signature));
        strncat (payload, "\",\"_srcip\":\"", sizeof("\",\"_srcip\":\""));
        strncat (payload, rec.src_ip, sizeof(rec.src_ip));
        strncat (payload, "\",\"_dstip\":\"", sizeof("\",\"_dstip\":\""));
        strncat (payload, rec.dst_ip, sizeof(rec.dst_ip));
        strncat (payload, "\",\"_srcport\":", sizeof("\",\"_srcport\":"));
        sprintf (level, "%d", rec.src_port);
        strncat (payload, level, sizeof(level));
        strncat (payload, ",\"_dstport\":", sizeof(",\"_dstport\":"));
        sprintf (level, "%d", rec.dst_port);
        strncat (payload, level, sizeof(level));
        strncat (payload, ",\"_gid\":", sizeof("\",\"_gid\":"));
        sprintf (level, "%d", rec.alert.gid);
        strncat (payload, level, sizeof(level));
        strncat (payload, ",\"_signature_id\":", sizeof(",\"_signature_id\":"));
        sprintf (level, "%d", rec.alert.signature_id);
        strncat (payload, level, sizeof(level));
        strncat (payload, ",\"_rev\":", sizeof(",\"_rev\":"));
        sprintf (level, "%d", rec.alert.rev);
        strncat (payload, level, sizeof(level));
        strncat (payload, ",\"_action\":\"", sizeof("\",\"_action\":\""));
        strncat (payload, rec.alert.action, sizeof(rec.alert.action));
        strncat (payload, "\"}", sizeof("\"}"));
        
        sk.graylog.SendMessage(payload);
    }
    
    if (sk.GetStateMysql()) {
    
        cx = snprintf ( sqlQuery, OS_PAYLOAD_SIZE+1, 
            "INSERT INTO suricata_events (probe_id, time_of_event, time_stamp, flow_id, stream, in_iface, event_type, srcip, dstip, srcport, dstport, protocol, payload_printable, action, gid, signature_id, rev, signature, category, severity) VALUES ('%s', '%s', '%s', %u, %u, '%s', '%s', '%s', '%s', %u, %u, '%s', '%s', '%s', %u, %u, %u, '%s', '%s', %u)", 
            probe_id, rec.datetime, rec.time_stamp, rec.flow_id, rec.stream, rec.in_iface, rec.event_type, rec.src_ip, rec.dst_ip, rec.src_port,
            rec.dst_port, rec.protocol, rec.payload_printable, rec.alert.action,
            rec.alert.gid, rec.alert.signature_id, rec.alert.rev, rec.alert.signature, rec.alert.category, rec.alert.severity);
    
        sk.mysql.Query(sqlQuery);
    }
}
