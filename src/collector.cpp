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

#include <sstream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
extern "C" {
    #include <config/kube_config.h>
    #include <api/CoreV1API.h>
}
#include <stdio.h>
#include <kubernetes/model/v1_object_meta.h>
#include <kubernetes/model/v1_pod_spec.h>

#include "collector.h"

#define SOCKET_BUFFER_SIZE 64000

int Collector::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    if (!sk.GetReportsPeriod()) return 0;
    
    return 1;
    
}

int  Collector::Open() {
    
    if (!sk.Open()) return 0;
    
    ref_id = hids->fs.filter.ref_id;
    
    if (wazuhServerStatus) {
        if (GetToken()){
            SysLog("connection with Wazuh server is established");
        } 
    }
    
    return 1;
}

bool Collector::GetToken() {
    
    try {
        
        boost::asio::io_service io_service;
        
        string hostAddress;
        string user(wazuh_user);
        string password(wazuh_pwd);
        string ip(wazuh_host);
        stringstream ss;
        ss << wazuh_port;
        string port = ss.str();
        
        if (wazuh_port != 80) {
            hostAddress = ip + ":" + port;
        } else { 
            hostAddress = ip;
        }
        
        string token = user + ":" + password;
        string encoded;
        
        if (!Base64::Encode(token, &encoded)) {
            wazuh_token = "indef";
            return false;
        }
        
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(ip, port);
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);
        
        string queryStr = "/security/user/authenticate?raw=true";

        boost::asio::streambuf request;
        ostream request_stream(&request);
        request_stream << "GET " << queryStr << " HTTP/1.1\r\n";  
        request_stream << "Host: " << hostAddress << "\r\n";
        request_stream << "Authorization: Basic "<< encoded << "\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Connection: close\r\n\r\n";

        boost::asio::write(socket, request);

        boost::asio::streambuf response;
        boost::asio::read_until(socket, response, "\r\n");

        istream response_stream(&response);
        string http_version;
        response_stream >> http_version;
        unsigned int status_code;
        response_stream >> status_code;
        string status_message;
        getline(response_stream, status_message);
        
        if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
            wazuh_token = "indef";
            return false;
        }
        
        if (status_code != 200) {
            wazuh_token = "indef";
            return false;
        }
        
        boost::asio::read_until(socket, response, "\r\n\r\n");

        string header;
        while (getline(response_stream, header) && header != "\r") { }
        
        stringstream  payload;
        if (response.size() > 0) {
            payload << &response;
        }

        boost::system::error_code error;
        while (boost::asio::read(socket, response,boost::asio::transfer_at_least(1), error)) {
            payload << &response;
        }

        if (error != boost::asio::error::eof) {
            throw boost::system::system_error(error);
        }
        
        wazuh_token = payload.str();
        
        return true;
    
    } catch (std::exception& ex) { 
        
    }

    wazuh_token = "indef";
    return false;
   
}

void  Collector::Close() {
    
    sk.Close();
    
}

int Collector::Go(void) {
    
    long counter_seconds = 0;
                
    while(1) { 
        
        while (sk.GetReportsPeriod() > counter_seconds && sk.GetReportsPeriod() != 0) {
            counter_seconds++;
            sleep(1);
        }
        
        counter_seconds = 0;
                
        StatJob();
        
        if (rcStatus) {
                
            if (wazuhServerStatus) {
                if (GetToken()) {
                    UpdateAgents();
                } else {
                    SysLog("connection to Wazuh server is lost");
                }
            }
            
            if (dockerSocketStatus) {
                SysLog("connection to Docker");
                UpdateContainers();
            } else {
                SysLog("no connection to Docker");
            }
            
            if (k8sStatus) {
                SysLog("connection to K8s");
                UpdatePods();
            } else {
                SysLog("no connection to K8s");
            }
            
            UpdateSensorsStatus();
           
            SysLog("update sensors status has been done");
        }
    }
    
    return 1;
}

void Collector::StatJob() {
    
    stringstream ss;
    
    unsigned long ccrs = crs->ResetEventsCounter();
    unsigned long chids = hids->ResetEventsCounter();
    unsigned long cnids = nids->ResetEventsCounter();
    unsigned long cwaf = waf->ResetEventsCounter() + aws_waf->ResetEventsCounter();
    unsigned long cremlog = rem_log->ResetEventsCounter();
    unsigned long vremlog = rem_log->ResetEventsVolume();
    unsigned long cremstat = rem_stat->ResetEventsCounter();
    unsigned long vremstat = rem_stat->ResetEventsVolume();
        
    ss << "{ \"type\": \"node_monitor\", \"data\": { \"ref_id\": \"";
    ss << ref_id;
    
    ss << "\", \"crs\": ";
    ss << to_string(ccrs);
        
    ss << ", \"hids\": ";
    ss << to_string(chids);
        
    ss << ", \"nids\": ";
    ss << to_string(cnids);
    
    ss << ", \"waf\": ";
    ss << to_string(cwaf);
    
    ss << ", \"log_counter\": ";
    ss << to_string(cremlog);
        
    ss << ", \"log_volume\": ";
    ss << to_string(vremlog);
        
    ss << ", \"stat_counter\": ";
    ss << to_string(cremstat);
        
    ss << ", \"stat_volume\": ";
    ss << to_string(vremstat);
        
    ss << ", \"time_of_survey\": \"";
    ss << GetNodeTime();
    ss << "\" } }";
        
    q_stats_collr.push(ss.str());
        
    ss.str("");
    ss.clear();
}

void Collector::UpdateAgents(void) {
    
    agents_payload.clear();
    
    GetAgents("/agents");
    if (!agents_payload.empty()) {
        
        ParsAgents();
    
        if (fs.agents_list.size() != 0) {
    
            std::vector<Agent>::iterator i, end;
            int j = 0;
            
            string report = "{ \"type\": \"agents_list\", \"data\" : [ ";
            
            for (i = fs.agents_list.begin(), end = fs.agents_list.end(); i != end; ++i) {
                
                report += "{ \"id\": \"";
                report += i->id;
        
                report += "\", \"ip\": \"";
                report += i->ip;
                
                report += "\", \"name\": \"";
                report += i->name;
                
                report += "\", \"status\": \"";
                report += i->status;
                
                report += "\", \"date_add\": \"";
                report += i->dateAdd;
                
                report += "\", \"version\": \"";
                report += i->version;
                
                report += "\", \"manager_host\": \"";
                report += host_name + ".hids";
                
                report += "\", \"os_platform\": \"";
                report += i->os_platform;
                
                report += "\", \"os_version\": \"";
                report += i->os_version;
                
                report += "\", \"os_name\": \"";
                report += i->os_name;
                
                report += "\", \"group\": \"";
                report += i->group;
                
                report += "\", \"time_of_survey\": \"";
                report +=  GetNodeTime();
                
                report += "\" }";
        
                if ( j < fs.agents_list.size() - 1) {
                    report += ", "; 
                    j++;
                }
            }
            
            report += " ] }";
            q_stats_collr.push(report);
            
            for (i = fs.agents_list.begin(), end = fs.agents_list.end(); i != end; ++i) {
                
                GetAgents("/sca/" + i->id);
                if (!agents_payload.empty()) {
                    
                    stringstream ss(agents_payload);
                
                    bpt::ptree pt;
    
                    try {
    
                        bpt::read_json(ss, pt);
    
                        int err =  pt.get<int>("error");
    
                        if(err == 0) {
    
                            int totalItems =  pt.get<int>("data.total_affected_items");
    
                            bpt::ptree policy_ptree = pt.get_child("data.affected_items");
    
                            BOOST_FOREACH(bpt::ptree::value_type &policies, policy_ptree) {
        
                                string policy_id = policies.second.get<string>("policy_id");
            
                                string url = "/sca/";
                                url += i->id;
                                url += "/checks/";
                                url += policy_id;
                                url += "?result=failed";
            
                                GetAgents(url);
                                if (!agents_payload.empty()) PushAgents("sca", i->name);
                            }
                        }
                    } catch (const std::exception & ex) {
                        SysLog((char*) ex.what());
                        SysLog("Collector::UpdateAgents");
                    } 
                    
                    pt.clear();
                }
            }
        }
    }
}

void Collector::GetAgents(const string& url_request) {
    
    try {
        
        boost::asio::io_service io_service;
        
        string hostAddress;
        string ip(wazuh_host);
        stringstream ss;
        ss << wazuh_port;
        string port = ss.str();
        
        if (wazuh_port != 80) {
            hostAddress = ip + ":" + port;
        } else { 
            
            hostAddress = ip;
        }
        
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(ip, port);
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);

        boost::asio::streambuf request;
        ostream request_stream(&request);
        request_stream << "GET " << url_request << " HTTP/1.1\r\n";  
        request_stream << "Host: " << hostAddress << "\r\n";
        request_stream << "Authorization: Bearer "<< wazuh_token << "\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Connection: close\r\n\r\n";

        boost::asio::write(socket, request);

        boost::asio::streambuf response;
        boost::asio::read_until(socket, response, "\r\n");

        istream response_stream(&response);
        string http_version;
        response_stream >> http_version;
        unsigned int status_code;
        response_stream >> status_code;
        string status_message;
        getline(response_stream, status_message);
        
        if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
            
            agents_payload.clear();
            return;
        }
        
        if (status_code != 200) {
            
            agents_payload.clear();
            return;
        }
        
        boost::asio::read_until(socket, response, "\r\n\r\n");

        string header;
        while (getline(response_stream, header) && header != "\r") { }
        
        stringstream  payload;
        if (response.size() > 0) {
            payload << &response;
        }

        boost::system::error_code error;
        while (boost::asio::read(socket, response,boost::asio::transfer_at_least(1), error)) {
            payload << &response;
        }

        if (error != boost::asio::error::eof) {
            throw boost::system::system_error(error);
        }
        
        agents_payload = payload.str();
        
        return;
    
    } catch (std::exception& ex) { 
        
    }

    agents_payload.clear();
   
}

void Collector::ParsAgents () {
    
    stringstream ss(agents_payload);
    
    try {
    
        bpt::ptree pt;
        bpt::read_json(ss, pt);
        
        int err =  pt.get<int>("error");
        
        if(err == 0) {
    
            int totalItems =  pt.get<int>("data.total_affected_items");
    
            bpt::ptree agents_ptree = pt.get_child("data.affected_items");
    
            BOOST_FOREACH(bpt::ptree::value_type &agents, agents_ptree) {
            
                string id = agents.second.get<string>("id");
                string ip = agents.second.get<string>("ip");
                string name = agents.second.get<string>("name");
                string status = agents.second.get<string>("status");
                string dateAdd = agents.second.get<string>("dateAdd");
                string version = "wazuh"; //agents.second.get<string>("version");
                string manager_host = host_name + ".hids"; //agents.second.get<string>("manager");
                string os_platform = agents.second.get<string>("os.platform", "indef");
                string os_version = agents.second.get<string>("os.version", "indef");
                string os_name = agents.second.get<string>("os.name", "indef"); 
                
                string group = "indef";
                
                if(agents.second.get_child_optional("group") != boost::none) {

                    bpt::ptree pt_group = agents.second.get_child("group");
                    
                    BOOST_FOREACH(bpt::ptree::value_type &g, pt_group) {
                        assert(g.first.empty()); // array elements have no names
                        if (g.second.data().compare("default") != 0) group = g.second.data();
                    }
                }
                
                fs.UpdateAgentsList(id, ip, name, status, dateAdd, version, manager_host, os_platform, os_version, os_name, group);
            }
        }
        
        pt.clear();
    
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        SysLog("Collector::ParsAgents");
    } 
}

void Collector::PushAgents(const string&  type, const string&  agent) {
    
    stringstream ss(agents_payload);
    stringstream ss1;
    
    bpt::ptree pt;
        
    try {
    
        bpt::read_json(ss, pt);
        
        int err = pt.get<int>("error");
        
        if(err == 0) {
        
            pt.put("type",type);
            pt.put("agent",agent);
            
            bpt::write_json(ss1, pt);
            
            q_stats_collr.push(ss1.str());
            
        }
            
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        SysLog("Collector::PushAgents");
    } 
    
    pt.clear();
}

void Collector::UpdateContainers(void) {
    
    containers_payload.clear();
    
    if (falcolog_status == 1) {
        
        try {
    
            GetContainers();
            
            if (!containers_payload.empty()) {
            
                ParsContainers();
        
                if (!containers_payload.empty()) {
        
                    string report = "{ \"type\": \"containers_list\",\"probe\": \"";
                    report += host_name + ".docker";
                    report += "\", \"data\" : ";
                    report += containers_payload;
                    report += " }";
        
                    q_stats_collr.push(report);
                }
            }
    
        } catch (const std::exception & ex) {
            SysLog((char*) ex.what());
            SysLog("Collector::UpdateContainers");
        } 
    }
}

void Collector::GetContainers() {
    
    try {
        
        int sck;
	struct sockaddr_un addr;
	int ret;
        
        stringstream response_ss;
        bpt::ptree pt;
                
        /* create socket */
	sck = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sck == -1) {
            SysLog("can not create docker socket");
            containers_payload.clear();
            return;
	}

	/* set address */
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, docker_socket, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

	/* Connect to unix socket */
	ret = connect(sck, (struct sockaddr *) &addr, sizeof(addr));
	if (ret == -1) {
            SysLog("can not connect to docket socket");
            containers_payload.clear();
            return;
	}
        
        std::string req = "GET /v1.40/containers/json HTTP/1.1\r\n";
        req += "Host: localhost\r\n";
        req += "Accept: */*\r\n\r\n";
        
        int siz = req.size();

	ret = send(sck, req.c_str(), siz, 0);
	if (ret == -1) {
            SysLog("Can not send request to docker socket");
            containers_payload.clear();
            return;
	} else if (ret < siz) {
            SysLog("Unable to send all size message to docker socket");
            containers_payload.clear();
            return;
	}
        
        char buffer[SOCKET_BUFFER_SIZE];
        memset(buffer, 0, SOCKET_BUFFER_SIZE);
        
	ret = read(sck, buffer, SOCKET_BUFFER_SIZE);
	if (ret == -1) {
            SysLog("Can not read answer from docker socket");
            containers_payload.clear();
            return;
	} 
        
        int i = 0;
        int j = 0;
        int k = 0;
        
        bool chunked = false;
                
        for (; i < SOCKET_BUFFER_SIZE && k <= 7; i++) {
            char test = (char) buffer[i];
            if ( test == '\n') k++;
            if (k == 7) j++;
        }
        
        int begin_str = i - j;
        
        if (k == 8) {
            
            std::string str_chunked(buffer + begin_str, buffer + i);
            
            if (str_chunked.find("chunked") != std::string::npos) {
                chunked = true;
            } else {
                containers_payload.append(buffer + i);
            }
        }
        
        for (int m = 0; chunked && m < 10; m++) {
            
            int l = 0;
            
            for (k = 0, j = 0; i < SOCKET_BUFFER_SIZE && k <= 2; i++) {
                char test = (char) buffer[i];
                if ( test == '\n') k++;
            
                if (k == 1) l++;
            
                if (k == 2) {
                
                    if (j == 0) {
                        //check string 1 if it eq 0
                        int x;
                        begin_str = i - l;
                        std::string str_lenth(buffer + begin_str, l);
                        std::stringstream ss;
                        ss << std::hex << str_lenth;
                        ss >> x;
                    
                        if (x == 0) chunked = false;
                    }
                
                    j++;
                }
            } 
        
            if (chunked) {
                begin_str = i - j;
                containers_payload.append(buffer + begin_str, j);
            }
        }
        
        close(sck);
        
        return;
    
    } catch (std::exception& ex) {
        SysLog((char*) ex.what());
        SysLog("Collector::GetContainers");
    }

    containers_payload.clear();
}

void Collector::ParsContainers() {
    
    stringstream ss(containers_payload);
    
    try {
        
        bpt::ptree pt;
        bpt::read_json(ss, pt);
        containers_list.clear();
            
        BOOST_FOREACH(bpt::ptree::value_type &container, pt) {
                
            string id = container.second.get<string>("Id","indef");
            string image = container.second.get<string>("Image","indef");
            string image_id = container.second.get<string>("ImageID","indef");
            
            containers_list.push_back(Container(id, image, image_id));
        }
        
        pt.clear();
        
        return;
    
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        SysLog("Collector::ParsContainers");
    } 
    
    containers_payload.clear();
}

bool Collector::GetPods(string space) {
    
    char* basePath = NULL;
    sslConfig_t* sslConfig = NULL;
    list_t* apiKeys = NULL;
    
    int rc = load_kube_config(&basePath, &sslConfig, &apiKeys, NULL);   /* NULL means loading configuration from $HOME/.kube/config */
    if (rc != 0) {
        SysLog("Cannot load kubernetes configuration.\n");
        return false;
    }
    
    apiClient_t* apiClient = apiClient_create_with_base_path(basePath, sslConfig, apiKeys);
    if (!apiClient) {
        SysLog("Cannot create a kubernetes client.\n");
        return false;
    }
    
    v1_pod_list_t* pod_list = NULL;
    pod_list = CoreV1API_listNamespacedPod(apiClient, (char*) space.c_str(),   
        NULL,    /* pretty */
        0,       /* allowWatchBookmarks */
        NULL,    /* continue */
        NULL,    /* fieldSelector */
        NULL,    /* labelSelector */
        0,       /* limit */
        NULL,    /* resourceVersion */
        NULL,    /* resourceVersionMatch */
        0,       /* timeoutSeconds */
        0        /* watch */
    );
    
    if (pod_list) {
        
        listEntry_t *listEntry = NULL;
        
        v1_pod_t* pod = NULL;
        
        pods_payload = "[";
        
        list_ForEach(listEntry, pod_list->items) {
            
            pod = (v1_pod_t *) listEntry->data;
            
            pods_payload += "{ \"name\": \"";
            string k8s(pod->metadata->name);
            pods_payload += k8s;
            
            pods_payload += "\", \"name_space\": \"";
            string name_space(pod->metadata->_namespace);
            pods_payload += name_space;
            
            pods_payload += "\", \"creation_timestamp\": \"";
            string creation_timestamp(pod->metadata->creation_timestamp);
            pods_payload += creation_timestamp;
            
            pods_payload += "\", \"uid\": \"";
            string uid(pod->metadata->uid);
            pods_payload += uid;
            
            pods_payload += "\", \"host_ip\": \"";
            string host_ip(pod->status->host_ip);
            pods_payload += host_ip;
            
            pods_payload += "\", \"pod_ip\": \"";
            string pod_ip(pod->status->pod_ip);
            pods_payload += pod_ip;
            
            pods_payload += "\", \"phase\": \"";
            string phase(pod->status->phase);
            pods_payload += phase;
            
            pods_payload += "\", \"node_name\": \"";
            string node_name(pod->spec->node_name);
            pods_payload += node_name;
            
            pods_payload += "\"} ,";
            
        }
        
        pods_payload.resize(pods_payload.size() - 1);
        pods_payload.append("]");
        
        v1_pod_list_free(pod_list);
        
        pod_list = NULL;
        
    } else {
        pods_payload = "[ ]";
    }
    
    apiClient_free(apiClient);
    apiClient = NULL;
    free_client_config(basePath, sslConfig, apiKeys);
    basePath = NULL;
    sslConfig = NULL;
    apiKeys = NULL;
    apiClient_unsetupGlobalEnv();
    
    return true;
}

void Collector::UpdatePods(void) {
    
    pods_payload.clear();
    
    if (falcolog_status == 1) {
        
        try {
            
            if (fs.namespaces_list.size()  != 0) {
                
                std::vector<Namespace>::iterator i, end;  
                
                for (i = fs.namespaces_list.begin(), end = fs.namespaces_list.end(); i != end; ++i) {
                    
                    if (GetPods(i->name)) {
            
                        string report = "{ \"type\": \"pods_list\",\"probe\": \"";
                        report += host_name + ".k8s";
                        report += "\", \"data\" : ";
                        report += pods_payload;
                        report += " }";
                
                        q_stats_collr.push(report);
                    }
                }
            } else {
                string def_space = "default";
                
                if (GetPods(def_space)) {
            
                    string report = "{ \"type\": \"pods_list\",\"probe\": \"";
                    report += host_name;
                    report += "\", \"data\" : ";
                    report += pods_payload;
                    report += " }";
                
                    q_stats_collr.push(report);
                }
            }
        } catch (const std::exception & ex) {
            SysLog((char*) ex.what());
            SysLog("Collector::UpdatePods");
        } 
    } 
}

void Collector::UpdateSensorsStatus() {
    
    stringstream ss;
    
    int scrs = crs->status;
    int shids = hids->status;
    int snids = nids->status;
    int swaf = waf->status;
    int saws_waf = aws_waf->status;
    
    int sips = suriSocketStatus ? 1 : 0;
    int sdocker = dockerSocketStatus ? 1 : 0;
    int sk8s = k8sStatus ? 1 : 0;
    
    int strivy = 1;
    if (!strcmp (trivy_path, "indef")) { 
        strivy = 0;
    }
    
    int skubehunter = 1;
    if (!strcmp (kubehunter_script, "indef")) { 
        skubehunter = 0;
    }
    
    int szap = 1;
    if (!strcmp (zap_script, "indef")) { 
        szap = 0;
    }
    
    ss << "{ \"type\": \"probes-status\", \"data\": { \"crs\": ";
    ss << to_string(scrs);
    
    ss << ", \"hids\": ";
    ss << to_string(shids);
        
    ss << ", \"nids\": ";
    ss << to_string(snids);
    
    ss << ", \"waf\": ";
    ss << to_string(swaf);
    
    ss << ", \"aws-waf\": ";
    ss << to_string(saws_waf);
    
    ss << ", \"ips\": ";
    ss << to_string(sips);
        
    ss << ", \"docker\": ";
    ss << to_string(sdocker);
        
    ss << ", \"k8s\": ";
    ss << to_string(sk8s);
        
    ss << ", \"trivy\": ";
    ss << to_string(strivy);
    
    ss << ", \"kube-hunter\": ";
    ss << to_string(skubehunter);
    
    ss << ", \"zap\": ";
    ss << to_string(szap);
        
    ss << ", \"time_of_survey\": \"";
    ss << GetNodeTime();
    ss << "\" } }";
        
    boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
    in.push(boost::iostreams::gzip_compressor());
    in.push(ss);
    boost::iostreams::copy(in, comp);
    boost::iostreams::close(in);

    bd.data = comp.str();
    bd.ref_id = fs.filter.ref_id;
    bd.event_type = 3;
    sk.SendMessage(&bd);
    
    boost::iostreams::close(in);
    ss.clear();
    comp.str("");
    comp.clear();
        
    return;
    
}








