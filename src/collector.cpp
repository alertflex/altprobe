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

#include "collector.h"

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
            SysLog("connection between Wazuh server and Altprobe is established");
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
    long counter_reports = 0;
            
    while(1) { 
        
        while (sk.GetReportsPeriod() > counter_seconds && sk.GetReportsPeriod() != 0) {
            counter_seconds++;
            sleep(1);
        }
        
        counter_seconds = 0;
        counter_reports++;
        
        StatJob();
        
        if (sk.GetLongtaskPeriod() >= counter_reports && sk.GetLongtaskPeriod() != 0) {
            
            if (ruStatus) {
                
                if (wazuhServerStatus) {
                    if (GetToken()) {
                        SysLog("connection between Wazuh server and Altprobe is established");
                        UpdateAgents();
                    }
                }
                
                UpdateFalcoConfig();
            
                UpdateSuriConfig();
            
                UpdateOssecConfig();
            
                UpdateFalcoRules();
            
                UpdateSuriRules();
            
                UpdateOssecRules();
                
                UpdateContainers();
            
                DockerBenchJob();
            
                TrivyJob();
            
                string update_notification = "update for altprobe has been done";
                SysLog((char*) update_notification.c_str());
            }
        
            counter_reports = 0;
        }
    }
    
    return 1;
}

void Collector::StatJob() {
    
    stringstream ss;
    
    unsigned long ccrs = crs->ResetEventsCounter();
    unsigned long chids = hids->ResetEventsCounter();
    unsigned long cnids = nids->ResetEventsCounter();
    unsigned long cmisc = misc->ResetEventsCounter();
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
    
    ss << ", \"misc\": ";
    ss << to_string(cmisc);
    
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

string Collector::GetAgents(string url_request) {
    
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
        
        if (!response_stream || http_version.substr(0, 5) != "HTTP/") return NULL;
        
        if (status_code != 200) return "";
        
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
        
        return payload.str();
    
    } catch (std::exception& ex) { 
        
    }

    return "";
   
}

void Collector::ParsAgents (string json) {
    
    stringstream ss(json);
    
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
                string version = agents.second.get<string>("version");
                string manager_host = agents.second.get<string>("manager");
                string os_platform = agents.second.get<string>("os.platform", "indef");
                string os_version = agents.second.get<string>("os.version", "indef");
                string os_name = agents.second.get<string>("os.name", "indef");
        
                fs.UpdateAgentsList(id, ip, name, status, dateAdd, version, manager_host, os_platform, os_version, os_name);
            }
        }
        
        pt.clear();
    
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
}

void Collector::UpdateAgents(void) {
        
    string payload = GetAgents("/agents");
    
    if (!payload.empty()) {
        
        ParsAgents(payload);
    
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
                report += i->manager_host;
                
                report += "\", \"os_platform\": \"";
                report += i->os_platform;
                
                report += "\", \"os_version\": \"";
                report += i->os_version;
                
                report += "\", \"os_name\": \"";
                report += i->os_name;
                
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
                
                payload = GetAgents("/syscollector/" + i->id + "/processes");
                
                PushAgents(payload,"processes",i->id);
                
                payload = GetAgents("/syscollector/" + i->id + "/packages");
                
                PushAgents(payload,"packages",i->id);
                
                payload = GetAgents("/sca/" + i->id);
                
                stringstream ss(payload);
                
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
            
                            payload = GetAgents(url);
            
                            PushAgents(payload,"sca",i->id);
                        }
                    }
    
                } catch (const std::exception & ex) {
                    SysLog((char*) ex.what());
                } 
                
                pt.clear();
            }
        }
    }
}

void Collector::PushAgents(string json, string type, string agent) {
    
    stringstream ss(json);
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
    } 
    
    pt.clear();
}

string Collector::GetContainers(void) {
    
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
            return "";
	}

	/* set address */
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, docker_socket, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

	/* Connect to unix socket */
	ret = connect(sck, (struct sockaddr *) &addr, sizeof(addr));
	if (ret == -1) {
            SysLog("can not connect to docket socket");
            return "";
	}
        
        std::string req = "GET /v1.40/containers/json HTTP/1.1\r\n";
        req += "Host: localhost\r\n";
        req += "Accept: */*\r\n\r\n";
        
        int siz = req.size();

	ret = send(sck, req.c_str(), siz, 0);
	if (ret == -1) {
            SysLog("Can not send request to docker socket");
            return "";
	} else if (ret < siz) {
            SysLog("Unable to send all size message to docker socket");
            return "";
	}
        
        char buffer[64000];
        memset(buffer, 0, 64000);
        
	ret = read(sck, buffer, 64000);
	if (ret == -1) {
            SysLog("Can not read answer from docker socket");
            return "";
	} 
        
        int i = 0;
        int j = 0;
        
        for (; i < 64000 && j <= 7; i++) {
            char test = (char) buffer[i];
            if ( test == '\n') j++;
        }
        
        string payload(buffer + i);
        
        if (j > 7) return payload;
    
    } catch (std::exception& ex) {
        SysLog((char*) ex.what());
    }

    return "";
}

void Collector::ParsContainers(string json) {
    
    stringstream ss(json);
    
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
    
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
}

void Collector::UpdateContainers(void) {
    
    if (dockerSocketStatus) {
    
        try {
    
            string payload = GetContainers();
            ParsContainers(payload);
        
            if (!payload.empty()) {
        
                string report = "{ \"type\": \"containers_list\",\"probe\": \"";
                report += probe_id;
                report += "\", \"data\" : ";
                report += payload;
                report += " }";
        
                q_stats_collr.push(report);
            }
    
        } catch (const std::exception & ex) {
            SysLog((char*) ex.what());
        } 
    }
}

void Collector::UpdateFalcoConfig() {
    
    if (!strcmp (falco_conf, "indef")) return; 
    
    try {
        
        std::ifstream falco_config;
        string dir_path(falco_conf);
        string file_name(FALCO_CONFIG);
        string file_path = dir_path + file_name;
        //SysLog((char*) file_path.c_str());
        falco_config.open(file_path,ios::binary);
        strStream << falco_config.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        //string s = std::to_string(rep_size);
        //string output = "logs compressed = " + s;
        // SysLog((char*) strStream.str().c_str());
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.sensor_type = 0;
        bd.event_type = 3;
        sk.SendMessage(&bd);
        
        falco_config.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
    
}


void Collector::UpdateOssecConfig() {
    
    if (!strcmp (wazuh_conf, "indef")) return; 
    
    try {
        
        std::ifstream ossec_config;
        string dir_path(wazuh_conf);
        string file_name(OSSEC_CONFIG);
        string file_path = dir_path + file_name;
        
        ossec_config.open(file_path,ios::binary);
        strStream << ossec_config.rdbuf();
            
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        boost::iostreams::close(in);

        //string s = std::to_string(rep_size);
        //string output = "logs compressed = " + s;
        // SysLog((char*) strStream.str().c_str());
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.sensor_type = 1;
        bd.event_type = 3;
        sk.SendMessage(&bd);
        
        ossec_config.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
}

void Collector::UpdateSuriConfig() {
    
    if (!strcmp (suri_conf, "indef")) return; 
    
    try {
        
        std::ifstream suri_config;
        string dir_path(suri_conf);
        string file_name(SURI_CONFIG);
        string file_path = dir_path + file_name;
        //SysLog((char*) file_path.c_str());
        suri_config.open(file_path,ios::binary);
        strStream << suri_config.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        //string s = std::to_string(rep_size);
        //string output = "logs compressed = " + s;
        // SysLog((char*) strStream.str().c_str());
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.sensor_type = 2;
        bd.event_type = 3;
        sk.SendMessage(&bd);
        
        suri_config.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
}

void Collector::UpdateFalcoRules() {
    
    if (!strcmp (falco_rules, "indef")) return; 
    
    try {
        
        path p (falco_rules);

        directory_iterator end_itr;
        
        // cycle through the directory
        int i = 0;
        path file_path;
        string file_name;
        
        for (directory_iterator itr(p); itr != end_itr; ++itr, i++) {
            
            if (is_regular_file(itr->path())) {
                
                file_path = itr->path();
                file_name = file_path.filename().string();
                std::ifstream falco_rules;
                falco_rules.open(file_path.string(),ios::binary);
                strStream << falco_rules.rdbuf();
        
                boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
                in.push(boost::iostreams::gzip_compressor());
                in.push(strStream);
                boost::iostreams::copy(in, comp);
                
                rd.data = comp.str();
                rd.name_rule = file_name;
                rd.ref_id = fs.filter.ref_id;
                rd.sensor_type = 0;
                rd.event_type = 4;
                sk.SendMessage(&rd);
        
                falco_rules.close();
                boost::iostreams::close(in);
                ResetStreams();
            }
        }
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
    
}

void Collector::UpdateOssecRules() {
    
    if (!strcmp (wazuh_rules, "indef")) return; 
    
    try {
        
        string root(wazuh_rules);
        string rules(WAZUH_RULES);
        
        path p (root + rules);
        
        directory_iterator end_itr;
        
        // cycle through the directory
        int i = 0;
        path file_path;
        string file_name;
        
        for (directory_iterator itr(p); itr != end_itr; ++itr, i++) {
            
            if (is_regular_file(itr->path())) {
                
                file_path = itr->path();
                file_name = file_path.filename().string();
                std::ifstream ossec_rules;
                ossec_rules.open(file_path.string(),ios::binary);
                strStream << ossec_rules.rdbuf();
        
                boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
                in.push(boost::iostreams::gzip_compressor());
                in.push(strStream);
                boost::iostreams::copy(in, comp);
                
                rd.data = comp.str();
                rd.name_rule = file_name;
                rd.ref_id = fs.filter.ref_id;
                rd.sensor_type = 1;
                rd.event_type = 4;
                sk.SendMessage(&rd);
        
                ossec_rules.close();
                boost::iostreams::close(in);
                ResetStreams();
            }
        }
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
}

void Collector::UpdateSuriRules() {
    
    if (!strcmp (suri_rules, "indef")) return; 
    
    try {
        
        path p (suri_rules);

        directory_iterator end_itr;
        
        // cycle through the directory
        int i = 0;
        path file_path;
        string file_name;
        
        for (directory_iterator itr(p); itr != end_itr; ++itr, i++) {
            
            if (is_regular_file(itr->path())) {
                
                file_path = itr->path();
                file_name = file_path.filename().string();
                std::ifstream suri_rules;
                suri_rules.open(file_path.string(),ios::binary);
                strStream << suri_rules.rdbuf();
        
                boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
                in.push(boost::iostreams::gzip_compressor());
                in.push(strStream);
                boost::iostreams::copy(in, comp);
                
                rd.data = comp.str();
                rd.name_rule = file_name;
                rd.ref_id = fs.filter.ref_id;
                rd.sensor_type = 2;
                rd.event_type = 4;
                sk.SendMessage(&rd);
        
                suri_rules.close();
                boost::iostreams::close(in);
                ResetStreams();
            }
        }
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
}

void Collector::DockerBenchJob() {
    
    if (!strcmp (docker_bench, "indef")) return; 
    
    try {
        
        string cmd = "cd ";
        cmd += docker_bench;
        cmd += " && sh docker-bench-security.sh -l report";
    
        system(cmd.c_str());
        
        string db_report = docker_bench;
        db_report += "report.json";
        
        std::ifstream docker_report;
        string file_path(db_report);
        docker_report.open(file_path,ios::binary);
        strStream << docker_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 5;
        sk.SendMessage(&bd);
                
        docker_report.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
    
}

void Collector::TrivyJob() {
    
    if (!strcmp (trivy, "indef")) return; 
    
    try {
        
        std::vector<Container>::iterator i, end;
        
        for (i = containers_list.begin(), end = containers_list.end(); i != end; ++i) {
        
            string cmd = "trivy -f json -o ";
            cmd += trivy;
            cmd += " ";
            cmd += i->image;
            
            system(cmd.c_str());
                    
            std::ifstream trivy_report;
            string file_path(trivy);
            trivy_report.open(file_path,ios::binary);
            strStream << trivy_report.rdbuf();
        
            boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
            in.push(boost::iostreams::gzip_compressor());
            in.push(strStream);
            boost::iostreams::copy(in, comp);
        
            bd.data = comp.str();
            bd.ref_id = fs.filter.ref_id;
            bd.event_type = 6;
            sk.SendMessage(&bd);
            
            trivy_report.close();
            boost::iostreams::close(in);
            ResetStreams();
        }
                
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
}




