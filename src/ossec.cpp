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
 
#include "ossec.h"

namespace bpt = boost::property_tree;


int Ossec::GetConfig(config_t cfg) {
    int flag;
    config_setting_t *list; 
    const char *base = NULL;
       
    //Read sinks config
    if(!sk.GetConfig(cfg)) return 0;
    
    if (!config_lookup_bool(&cfg, "sources.ossec.destination.mysql", &flag)) {
        SysLog("OSSEC config - MySQL flag is missing.");
        sk.SetStateMysql(-1);
    }
    else sk.SetStateMysql(flag);
    
    
    if (!config_lookup_bool(&cfg, "sources.ossec.destination.graylog", &flag)) {
        SysLog("OSSEC config - GrayLog flag is missing.");
        sk.SetStateGraylog(-1);
    }
    else sk.SetStateGraylog(flag);
    
    list = config_lookup(&cfg, "sources.ossec.filters.rules_list.black");
    if (list != 0) {
        size_black_list = config_setting_length(list);
        for (int i = 0; i < size_black_list; i++) black_list[i] = config_setting_get_int_elem(list, i);
    
    }
    
    list = config_lookup(&cfg, "sources.ossec.filters.rules_list.white");
    if (list != 0) {
        size_white_list = config_setting_length(list);
        for (int i = 0; i < size_white_list; i++) white_list[i] = config_setting_get_int_elem(list, i);
    }
    
    
    if (config_lookup_string(&cfg, "sources.ossec.url", &base)) {
        if (!strcmp(base, "none")) state = 0;
        else {
            strncpy (url, base,  OS_HEADER_SIZE);
            state = 1;
        }
    }
    else goto return_with_error;
    
    config_lookup_int(&cfg, "sources.ossec.filters.priority", &alerts_priority);
    
    return 1;
    
return_with_error:
    SysLog("Error in OSSEC parameters.");
    return 0;
}


int Ossec::OpenZmq(void) {
    char t[OS_HEADER_SIZE];
     
    context = zmq_ctx_new();
    subscriber = zmq_socket(context, ZMQ_SUB);
    
    rc = zmq_connect(subscriber, url);

    if (rc != 0) return 0;
    
    sprintf(t, "ossec.alerts"); 
    rc = zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, t, strlen(t));
    
    if (rc != 0) return 0;
    
    return 1;
}
    
    
int Ossec::Open() {
    
    if (!sk.Open()) return 0;
    
    if (!OpenZmq()) {
        SysLog("Failed to connect to OSSEC server over zmq.");
        return 0;
    }
    
    rec.Reset();
    
    return 1;
}

void Ossec::Close() {
    
    sk.Close();
    
    if (!rc) {
        zmq_close(subscriber);
        zmq_ctx_destroy(context);
    }
}


int Ossec::Go(void) {
    
    time_t rawtime;
    struct tm * timeinfo;
    
    Reset();
    
    // read OSSEC data from port
    if (ReceiveEvent()) {
        
        // pars string to record of class
        ParsJson();
        
        if (!CheckBlackList()) {
            
            if (!CheckWhiteList()) {
                if(alerts_priority >= rec.rule.level) {
                    SendEvent();
                }
            }
            else SendEvent();
        }
    }
        
    return 1;
}


bool Ossec::CheckBlackList() {
    int i;
    
    if (size_black_list != 0)
        for (i = 0; i < size_black_list; i++) 
            if (black_list[i] == rec.rule.sidid) return true;
    
    return false;
}

bool Ossec::CheckWhiteList() {
    int i;
    
    if (size_white_list != 0) 
        for (i = 0; i < size_white_list; i++) 
                if (white_list[i] == rec.rule.sidid) return true;
        
    return false;
}

int Ossec::ReceiveEvent(void) 
{
    struct zmq_msg_hdr h;
    int ret;
    
    ret = zmq_recv(subscriber, &h, sizeof(h), 0); 
    if (ret == -1) {
        SysLog("Failed reading event (phase 1) from zmq for OSSEC.");
        return 0;
    }
    ret = zmq_recv(subscriber, payload, OS_PAYLOAD_SIZE, 0); 
    if (ret == -1) {
        SysLog("Failed reading event (phase 2) from zmq for OSSEC.");
        return 0;
    }
    
    return 1;
}

void Ossec::ParsJson () {
    
    stringstream ss(payload);
    bpt::ptree pt;
    bpt::read_json(ss, pt);
    
    // rule
    rec.rule.sidid = pt.get<int>("rule.sidid",0);
    
    rec.rule.level = pt.get<int>("rule.level",0);
    
    rec.rule.comment = pt.get<string>("rule.comment","");
    
    rec.rule.cve = pt.get<string>("rule.cve","");
    
    rec.rule.info = pt.get<string>("rule.info","");
    
    try {
    
        bpt::ptree groups_cats = pt.get_child("rule.groups");
    
        BOOST_FOREACH(bpt::ptree::value_type &v, groups_cats) {
            assert(v.first.empty()); // array elements have no names
            rec.rule.list_cats.push_back(v.second.data());
        }
    } catch (bpt::ptree_bad_path& e) {}
    
    try {
    
        bpt::ptree pcidss_cats = pt.get_child("rule.PCI_DSS");
        BOOST_FOREACH(bpt::ptree::value_type &v, pcidss_cats) {
            assert(v.first.empty()); // array elements have no names
            string pcidss = "pci_dss_" + v.second.data();
            rec.rule.list_cats.push_back(pcidss);
        }  
    
    } catch (bpt::ptree_bad_path& e) {}
    
    // root
    rec.action = pt.get<string>("action","");
        
    rec.protocol = pt.get<string>("protocol","");
        
    rec.hostname = pt.get<string>("hostname","");
        
    rec.location = pt.get<string>("location","");
        
    rec.full_log = pt.get<string>("full_log","");
    for (int i=0; i < rec.full_log.size(); i++)
        if (rec.full_log[i] == '\'' || rec.full_log[i] == '\"' || rec.full_log[i] == '\\') rec.full_log[i] = ' ';
    
    rec.srcip = pt.get<string>("srcip","");
        
    string srcport = pt.get<string>("srcport","0");
    rec.srcport = stoi( srcport );
    
    rec.srcuser = pt.get<string>("srcuser","");
    
    rec.dstip = pt.get<string>("dstip","");
        
    string dstport = pt.get<string>("dstport","0");
    rec.dstport = stoi( dstport );
    
    rec.dstuser = pt.get<string>("dstuser","");
        
    // file
    
    rec.file.filename = pt.get<string>("SyscheckFile.path","");
    
    rec.file.md5_before = pt.get<string>("SyscheckFile.md5_before","");
    
    rec.file.md5_after = pt.get<string>("SyscheckFile.md5_after","");
    
    rec.file.sha1_before = pt.get<string>("SyscheckFile.sha1_before","");
    
    rec.file.sha1_after = pt.get<string>("SyscheckFile.sha1_after","");
    
    rec.file.owner_before = pt.get<string>("SyscheckFile.owner_before","");
        
    rec.file.owner_after = pt.get<string>("SyscheckFile.owner_after","");
           
    rec.file.gowner_before = pt.get<string>("SyscheckFile.gowner_before","");
    
    rec.file.gowner_after = pt.get<string>("SyscheckFile.gowner_after","");
    
    pt.clear();   
        
}

void Ossec::SendEvent() {
    
    char sqlQuery[OS_PAYLOAD_SIZE+1];
    int cx;
    
    if (sk.GetStateGraylog()) {
        
        stringstream ss;
    
        ss << "{\"version\": \"1.1\",\"host\":\"";
        ss << probe_id;
        ss << "\",\"short_message\":\"OSSEC\"";
        ss << ",\"full_message\":\"Wazuh IDS\"";
        ss << ",\"level\":";
        ss << rec.rule.level;
        ss << ",\"_event_type\":\"OSSEC\",";
        ss << "\"_time_of_event\":\"";
        ss << GetCollectorTimeGraylogFormat();
        ss << "\",\"_comment\":\"";
        ss << rec.rule.comment;
        ss << "\",\"_full_log\":\"";
        ss <<  rec.full_log;
        ss << "\",\"_sidid\":";
        ss << rec.rule.sidid;
        ss << ",\"_group_name\":\"";
    
        int j = 0;
        for (string i : rec.rule.list_cats) {
            if (j != 0 && j < rec.rule.list_cats.size()) ss << ", ";
            ss << i;
            
            j++;    
        }
    
        ss << "\",\"_cve\":\"";
        ss << rec.rule.cve;
        ss << "\",\"_info\":\"";
        ss << rec.rule.info;
        ss << "\",\"_hostname\":\"";
        ss << rec.hostname;
        ss << "\",\"_location\":\"";
        ss << rec.location;
        ss << "\",\"_srcip\":\"";
        ss << rec.srcip;
        ss << "\",\"_dstip\":\"";
        ss << rec.dstip;
        ss << "\",\"_srcport\":";
        ss << rec.srcport;
        ss << ",\"_dstport\":";
        ss << rec.dstport;
        ss << ",\"_action\":\"";
        ss << rec.action;
        ss << "\",\"_srcuser\":\"";
        ss << rec.srcuser;
        ss << "\",\"_dstuser\":\"";
        ss << rec.dstuser;
        if (rec.file.filename.compare("") != 0) {
            ss << "\",\"_filename\":\"";
            ss << rec.file.filename;
            ss << "\",\"_md5_before\":\"";
            ss << rec.file.md5_before;
            ss << "\",\"_md5_after\":\"";
            ss << rec.file.md5_after;
            ss << "\",\"_sha1_before\":\"";
            ss << rec.file.sha1_before;
            ss << "\",\"_sha1_after\":\"";
            ss << rec.file.sha1_after;
            ss << "\",\"_owner_before\":\"";
            ss << rec.file.owner_before;
            ss << "\",\"_owner_after\":\"";
            ss << rec.file.owner_after;
            ss << "\",\"_gowner_before\":\"";
            ss << rec.file.gowner_before;
            ss << "\",\"_gowner_after\":\"";
            ss << rec.file.gowner_after;
        }
        ss << "\"}";
    
        strncpy (payload, ss.str().c_str(), sizeof(payload));
        
        sk.graylog.SendMessage(payload);
        
    }
    
    if (sk.GetStateMysql()) {
        
        char comment[OS_BUFFER_SIZE]; /* description in the xml */
        strncpy (comment, rec.rule.comment.c_str(), sizeof(comment));
        
        char group_name[OS_BUFFER_SIZE];
        stringstream ss;
        int j = 0;
        for (string i : rec.rule.list_cats) {
            if (j != 0 && j < rec.rule.list_cats.size()) ss << ", ";
            ss << i;
            
            j++;    
        }
        strncpy (group_name, ss.str().c_str(), sizeof(group_name));
        
        char cve[OS_LONG_HEADER_SIZE];
        strncpy (cve, rec.rule.cve.c_str(), sizeof(cve));
        
        char info[OS_LONG_HEADER_SIZE];
        strncpy (info, rec.rule.info.c_str(), sizeof(info));
        
        char full_log[OS_MAXSTR_SIZE];
        strncpy (full_log, rec.full_log.c_str(), sizeof(full_log));
    
        char location[OS_LONG_HEADER_SIZE];
        strncpy (location, rec.location.c_str(), sizeof(location));
    
        char hostname[OS_HEADER_SIZE];
        strncpy (hostname, rec.hostname.c_str(), sizeof(hostname));
    
        char srcip[IP_SIZE];
        strncpy (srcip, rec.srcip.c_str(), sizeof(srcip));
    
        char dstip[IP_SIZE];
        strncpy (dstip, rec.dstip.c_str(), sizeof(dstip));
    
        char protocol[OS_HEADER_SIZE];
        strncpy (protocol, rec.protocol.c_str(), sizeof(protocol));
    
        char action[OS_LONG_HEADER_SIZE];
        strncpy (action, rec.action.c_str(), sizeof(action));
    
        char srcuser[OS_HEADER_SIZE];
        strncpy (srcuser, rec.srcuser.c_str(), sizeof(srcuser));
    
        char dstuser[OS_HEADER_SIZE];
        strncpy (dstuser, rec.srcuser.c_str(), sizeof(dstuser));
    
        char datetime[OS_DATETIME_SIZE];
        time_t rawtime;
        struct tm * timeinfo;
    
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        strftime(datetime, sizeof(datetime),"%Y-%m-%d %H:%M:%S",timeinfo);
        
        
        char filename[OS_LONG_HEADER_SIZE];
        strncpy (filename, rec.file.filename.c_str(), sizeof(filename));
        
        char md5_before[OS_LONG_HEADER_SIZE];
        strncpy (md5_before, rec.file.md5_before.c_str(), sizeof(md5_before));
    
        char md5_after[OS_LONG_HEADER_SIZE];
        strncpy (md5_after, rec.file.md5_after.c_str(), sizeof(md5_after));
    
        char sha1_before[OS_LONG_HEADER_SIZE];
        strncpy (sha1_before, rec.file.sha1_before.c_str(), sizeof(sha1_before));
    
        char sha1_after[OS_LONG_HEADER_SIZE];
        strncpy (sha1_after, rec.file.sha1_after.c_str(), sizeof(sha1_after));
    
        char owner_before[OS_LONG_HEADER_SIZE];
        strncpy (owner_before, rec.file.owner_before.c_str(), sizeof(owner_before));
    
        char owner_after[OS_LONG_HEADER_SIZE];
        strncpy (owner_after, rec.file.owner_after.c_str(), sizeof(owner_after));
    
        char gowner_before[OS_LONG_HEADER_SIZE];
        strncpy (gowner_before, rec.file.gowner_before.c_str(), sizeof(gowner_before));
    
        char gowner_after[OS_LONG_HEADER_SIZE];
        strncpy (gowner_after, rec.file.gowner_after.c_str(), sizeof(gowner_after));        
    
        cx = snprintf ( sqlQuery, OS_PAYLOAD_SIZE+1, 
            "INSERT INTO ossec_events (probe_id, level, sidid, comment, group_name, cve, info, full_log, hostname, location, srcip, dstip, srcport, dstport, protocol, action, srcuser, dstuser, time_of_event, filename, md5_before, md5_after, sha1_before, sha1_after, owner_before, owner_after, gowner_before, gowner_after) VALUES ('%s', %u, %u, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %u, %u, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')", 
            probe_id, rec.rule.level, rec.rule.sidid, comment, group_name, cve, info, full_log, hostname, location, srcip, dstip, rec.srcport, rec.dstport, protocol, action, srcuser, dstuser, datetime, filename, md5_before, md5_after, sha1_before, sha1_after, owner_before, owner_after, gowner_before, gowner_after);
        
        sk.mysql.Query(sqlQuery);
        
    }
}
