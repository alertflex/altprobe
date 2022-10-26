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

#ifndef COBJECT_H
#define	COBJECT_H

#include "main.h"
#include "config.h"

using namespace std;

class CollectorObject {
public:
    
    //
    static string node_id;
    static string host_name;
    static string project_id;
    
    static char maxmind_path[OS_BUFFER_SIZE]; 
    static bool maxmind_status;
    
    static char remote_control[OS_HEADER_SIZE];
    static bool rcStatus;
        
    static int time_delta;
    static int log_size;
    static char log_path[OS_BUFFER_SIZE]; 
    
    static long startup_timer;
    static long gosleep_timer;
    
    // Suricata socket parameters
    static char suri_socket[OS_BUFFER_SIZE];
    // Docker socket parameters
    static char docker_socket[OS_BUFFER_SIZE];
    // K8s namespace
    static char k8s_namespace[OS_BUFFER_SIZE];
            
    static bool suriSocketStatus;
    static bool dockerSocketStatus;
    static bool k8sStatus;
        
    // scanners
    static char dependencycheck_result[OS_BUFFER_SIZE]; 
    static char dockerbench_result[OS_BUFFER_SIZE]; 
    static char kubebench_result[OS_BUFFER_SIZE]; 
    static char kubehunter_result[OS_BUFFER_SIZE]; 
    static char nmap_result[OS_BUFFER_SIZE]; 
    static char tfsec_result[OS_BUFFER_SIZE]; 
    static char trivy_result[OS_BUFFER_SIZE];
    static char zap_result[OS_BUFFER_SIZE]; 
        
    // sensors
    
    static char falco_log[OS_BUFFER_SIZE]; 
    static int falcolog_status;
    static char falco_local[OS_BUFFER_SIZE];
    static char falco_rules[OS_BUFFER_SIZE];
    
    static char modsec_log[OS_BUFFER_SIZE];
    static int modseclog_status;
    static char modsec_local[OS_BUFFER_SIZE];
    static char modsec_rules[OS_BUFFER_SIZE];
    
    static char suri_log[OS_BUFFER_SIZE]; 
    static int surilog_status;
    static char suri_local[OS_BUFFER_SIZE];
    static char suri_rules[OS_BUFFER_SIZE];
    
    static char wazuh_log[OS_BUFFER_SIZE];
    static int wazuhlog_status;
    static char wazuh_local[OS_BUFFER_SIZE];
    static char wazuh_rules[OS_BUFFER_SIZE];
    
    static char wazuh_host[OS_HEADER_SIZE];
    static int wazuh_port;
    static char wazuh_user[OS_HEADER_SIZE];
    static char wazuh_pwd[OS_HEADER_SIZE];
    static string wazuh_token;
    static bool wazuhServerStatus;
    
    char collector_time[OS_DATETIME_SIZE]; 
    
    //Syslog info string
    static char SysLogInfo[OS_LONG_HEADER_SIZE];
    
    CollectorObject () {
        node_id.clear();
        host_name.clear();
        suriSocketStatus = true;
        dockerSocketStatus = true;
        k8sStatus = true;
        wazuhServerStatus = true;
        maxmind_status = true;
        rcStatus = false;
        time_delta = 0;
        log_size = 0;
        startup_timer = 0;
        gosleep_timer = 0;
        wazuh_port = 0;
    }
    
    string GetNodeId()  { return node_id; }
    virtual int GetConfig();
    
    string GetNodeTime();
    string GetGraylogFormat();
    void ReplaceAll(string& input, const string& from, const string& to);
    
    long GetStartupTimer() { return startup_timer; }
    long GetGosleepTimer() { return gosleep_timer; }
        
    static void SysLog(char* info);
    static int ValidDigit(char* ip_str);
    static int IsValidIp(string ip);
    static uint32_t IPToUInt(string ip);
    static bool IsIPInRange(string ip, string network, string mask);
    static unsigned int GetBufferSize(char* source);
};

class Event {
public:
    int event_type;
    
    string ref_id;
    
    void Reset() {
        ref_id.clear();
        event_type  = 0;
    }
};

class BinData : public Event {
public:   
    string data;
    string target;
    int sensor_type;
        
    void Reset() {
        Event::Reset();
        sensor_type = 0;
        data.clear();
        target.clear();
    }
    
    BinData () {
        data.clear();
        target.clear();
        event_type = 2;
        sensor_type = 0;
    }
};

class Rule : public BinData {
public:   
    string name_rule;
        
    void Reset() {
        BinData::Reset();
        name_rule.clear();
    }
    
    Rule () {
        data.clear();
        name_rule.clear();
        event_type = 5;
    }
};

class Alert : public Event {
public:    
    // Record
    string alert_uuid;
    string alert_source;
    string alert_type;
    string sensor_id;
    int alert_severity;
    string description;
    string event_id;
    int event_severity;
    
    string location;
    string action; 
    string filter;
    string status;
    string info;
    string user_name;
    string agent_name;
    string event_time;
    
    std::vector<string> list_cats;
    
    string src_ip;
    string dst_ip;
    string src_hostname;
    string dst_hostname;
    unsigned int src_port;
    unsigned int dst_port;
	
    string file_name;
        
    string reg_value;
	
    string hash_md5;
    string hash_sha1;
    string hash_sha256;
	
    unsigned int process_id;
    string process_name;
    string process_cmdline;
    string process_path;
    
    string url_hostname;
    string url_path;
    
    string container_id;
    string container_name;
    
    string cloud_instance;
    
    bool log;
    
    void Reset() {
        
        Event::Reset();
        event_type = 0;
		
        alert_uuid.clear();
        alert_source.clear();
	alert_type.clear();
	sensor_id.clear();
	alert_severity = 0;
	description.clear();
	
	event_id.clear();
	event_severity = 0;
    
	src_ip.clear();
	dst_ip.clear();
	src_hostname.clear();
	dst_hostname.clear();
	src_port = 0;
	dst_port = 0;
	
	reg_value.clear();
	file_name.clear();
	        
	hash_md5.clear();
	hash_sha1.clear();
        hash_sha256.clear();
	
	process_id = 0;
	process_name.clear();
	process_cmdline.clear();
        process_path.clear();
		
	url_hostname.clear();
	url_path.clear();
        
        container_id.clear();
        container_name.clear();
        
        cloud_instance.clear();
        
        user_name.clear();
	agent_name.clear();
		
	location.clear();
	action.clear(); 
	filter.clear();
	status.clear();
	info.clear();
	event_time.clear();
        
        list_cats.clear();
        
        log = false;
    }
    
    void CreateAlertUUID(void);
};

#endif	/* COBJECT_H */

