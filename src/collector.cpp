/* 
 * File:   collector.cpp
 * Author: Oleg Zharkov
 *
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
        string payload = WazuhGet("/agents");
        if (!payload.empty()){
            SysLog("connection between Wazuh server and Altprobe is established");
            ParsAgents(payload);
        }
        else {
            wazuhServerStatus = false;
            SysLog("error of connection between Wazuh server and Altprobe");
        }
    }
    
    return 1;
}

void  Collector::Close() {
    
    sk.Close();
    
}


int Collector::Go(void) {
    
    struct timeval start, end;
    long seconds = 0;
    long reports = 0;
            
    while(1) { 
        
        while (sk.GetReportsPeriod() > seconds) {
            seconds++;
            sleep(1);
        }
        
        UpdateRulesConfigs();
        
        seconds = 0;
        
        if (update_timer == 0) RoutineJob();
        
        reports++;
        
        if (docker_timer == reports && docker_timer != 0) {
            
            DockerBenchJob();
            TrivyJob();
            
            reports = 0;
        }
        
    }
    
    return 1;
}

void Collector::UpdateRulesConfigs() {
    
    if (urStatus) {
    
        if(update_timer == 1) {
            
            UpdateFilters();
            UpdateFalcoConfig();
            UpdateSuriConfig();
            UpdateOssecConfig();
            UpdateModsecConfig();
            UpdateSuriRules();
            UpdateOssecRules();
            UpdateModsecRules();
            UpdateFalcoRules();
        
            string update_notification = "configs and rules update have been done";
            SysLog((char*) update_notification.c_str());
        
            update_timer--;
        
        } else {
            if (update_timer > 1) update_timer--;
        }
    
    } else update_timer = 0;
}

void Collector::RoutineJob() {
    
    stringstream ss;
    
    unsigned long ccrs = crs->ResetEventsCounter();
    unsigned long chids = hids->ResetEventsCounter();
    unsigned long cnids = nids->ResetEventsCounter();
    unsigned long cwaf = waf->ResetEventsCounter();
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
    
    ss << ", \"waf\": ";
    ss << to_string(cwaf);
        
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
        
    unsigned long magent = fs.agents_list.size();
    unsigned long mhnetf = fs.filter.home_nets.size();
    unsigned long mcrsf = fs.filter.crs.gl.size();
    unsigned long mhidsf = fs.filter.hids.gl.size();
    unsigned long mnidsf = fs.filter.nids.gl.size();
    unsigned long mwaff = fs.filter.waf.gl.size();
           
    ss << "{ \"type\": \"node_filters\", \"data\": { \"ref_id\": \"";
    ss << ref_id;
        
    ss << "\", \"agent_list\": ";
    ss << to_string(magent);
        
    ss << ", \"hnet_list\": ";
    ss << to_string(mhnetf);
    
    ss << ", \"crs_filters\": ";
    ss << to_string(mcrsf);
        
    ss << ", \"hids_filters\": ";
    ss << to_string(mhidsf);
        
    ss << ", \"nids_filters\": ";
    ss << to_string(mnidsf);
    
    ss << ", \"waf_filters\": ";
    ss << to_string(mwaff);
        
    ss << ", \"time_of_survey\": \"";
    ss << GetNodeTime();
    ss << "\" } }";
        
    q_stats_collr.push(ss.str());
        
    ss.str("");
    ss.clear();
        
    if (wazuhServerStatus) {
        string payload = WazuhGet("/agents");
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
                    
                    payload = WazuhGet("/sca/" + i->id);
                    
                    ControllerPush(payload,"sca",i->id);
                    
                    payload = WazuhGet("/syscollector/" + i->id + "/processes");
                    
                    ControllerPush(payload,"processes",i->id);
                    
                    payload = WazuhGet("/syscollector/" + i->id + "/packages");
                    
                    ControllerPush(payload,"packages",i->id);
                }
            }
        }
    }
}

string Collector::WazuhGet(string queryStr) {
    
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
        
        string user(wazuh_user);
        string pwd(wazuh_pwd);
        string token = user + ":" + pwd;
        
        string encoded;
        
        if (!Base64::Encode(token, &encoded)) {
            return "";
        }
        
        // string queryStr = "/agents?pretty";

        tcp::resolver resolver(io_service);
        tcp::resolver::query query(ip, port);
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);

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
    }
    catch (std::exception& e) {
        return "";
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
    
            int totalItems =  pt.get<int>("data.totalItems");
    
            bpt::ptree agents_ptree = pt.get_child("data.items");
    
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
    
    return;
}

void Collector::ControllerPush(string json, string type, string agent) {
    
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
            
            pt.clear();
            
        }
            
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
}

void Collector::UpdateFilters() {
    
    try {
        
        std::ifstream filters_config;
        filters_config.open(FILTERS_FILE,ios::binary);
        strStream << filters_config.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        //string s = std::to_string(rep_size);
        //string output = "logs compressed = " + s;
        // SysLog((char*) strStream.str().c_str());
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 3;
        sk.SendMessage(&bd);
        
        filters_config.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
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
        bd.event_type = 4;
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
        bd.event_type = 5;
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
        bd.event_type = 6;
        sk.SendMessage(&bd);
        
        suri_config.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
}

void Collector::UpdateModsecConfig() {
    
    if (!strcmp (modsec_conf, "indef")) return; 
    
    try {
        
        std::ifstream modsec_config;
        string dir_path(modsec_conf);
        string file_name(MODSEC_CONFIG);
        string file_path = dir_path + file_name;
        //SysLog((char*) file_path.c_str());
        modsec_config.open(file_path,ios::binary);
        strStream << modsec_config.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
         bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 7;
        sk.SendMessage(&bd);
        
        modsec_config.close();
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
                rd.event_type = 8;
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
                rd.event_type = 9;
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
                rd.event_type = 10;
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

void Collector::UpdateModsecRules() {
    
    if (!strcmp (modsec_rules, "indef")) return; 
    
    try {
        
        string root(modsec_rules);
                
        path p (root + "rules");

        directory_iterator end_itr;
        
        // cycle through the directory
        int i = 0;
        path file_path;
        string file_name;
        
        for (directory_iterator itr(p); itr != end_itr; ++itr, i++) {
            
            if (is_regular_file(itr->path())) {
                
                file_path = itr->path();
                file_name = file_path.filename().string();
                std::ifstream modsec_rules;
                modsec_rules.open(file_path.string(),ios::binary);
                strStream << modsec_rules.rdbuf();
        
                boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
                in.push(boost::iostreams::gzip_compressor());
                in.push(strStream);
                boost::iostreams::copy(in, comp);
                
                rd.data = comp.str();
                rd.name_rule = file_name;
                rd.ref_id = fs.filter.ref_id;
                rd.event_type = 11;
                sk.SendMessage(&rd);
        
                modsec_rules.close();
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
        
        string cmd = "/etc/altprobe/scripts/docker-bench.sh";
    
        system(cmd.c_str());
        
        std::ifstream docker_report;
        string file_path(docker_bench);
        docker_report.open(file_path,ios::binary);
        strStream << docker_report.rdbuf();
        
        boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
        in.push(boost::iostreams::gzip_compressor());
        in.push(strStream);
        boost::iostreams::copy(in, comp);
        
        bd.data = comp.str();
        bd.ref_id = fs.filter.ref_id;
        bd.event_type = 12;
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
        
        std::ifstream trivy_scripts ("/etc/altprobe/scripts/trivy.sh");
        string script;
        
        while (getline(trivy_scripts, script)) {
            
            if (script.size() != 0) {
        
                if (script.at(0) != '#' && script.at(0) != '\n' ) {
                    
                    system(script.c_str());
                    
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
                    bd.event_type = 14;
                    sk.SendMessage(&bd);
                
                    trivy_report.close();
                    boost::iostreams::close(in);
                    ResetStreams();
                }
            }
        }
        
        trivy_scripts.close();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
    
}




