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
    
    if (sk.GetReportsPeriod()) status = 1;
    
    return 1;
    
}


int  Collector::Open() {
    
    if (!sk.Open()) return 0;
    
    ref_id = hids->fs.filter.ref_id;
    
    if (wazuhServerStatus) {
        string payload = GetAgentsStatus();
        if (!payload.empty()){
            SysLog("connection between Wazuh server and Altprobe is established");
            ParsAgentsStatus(payload);
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
            
    while(1) {  
        
        if(update_timer == 1) {
            
            string cmd = "alertflex-update";
            system(cmd.c_str());
            
            UpdateFilters();
            UpdateSuriConfig();
            UpdateOssecConfig();
            UpdateModsecConfig();
            UpdateSuriRules();
            UpdateOssecRules();
            UpdateModsecRules();
            update_timer = 0;
        }
        
        gettimeofday(&start, NULL);
        while (sk.GetReportsPeriod() > seconds) {
            gettimeofday(&end, NULL);
            seconds  = end.tv_sec  - start.tv_sec;
            
            usleep(GetGosleepTimer()*60);
        }
        RoutineJob();
        seconds = 0;
    }
    
    return 1;
}

void Collector::RoutineJob() {
    
    stringstream ss;
        
    unsigned long chids = hids->ResetEventsCounter();
    unsigned long cnids = nids->ResetEventsCounter();
    unsigned long cwaf = waf->ResetEventsCounter();
    unsigned long cmisc = misc->ResetEventsCounter();
    unsigned long cmetrics = met->ResetEventsCounter();
    unsigned long cstatflows = stat_flows->ResetEventsCounter();
    unsigned long cremlog = rem_log->ResetEventsCounter();
    unsigned long vremlog = rem_log->ResetEventsVolume();
    unsigned long cremstat = rem_stat->ResetEventsCounter();
    unsigned long vremstat = rem_stat->ResetEventsVolume();
        
    ss << "{ \"type\": \"node_monitor\", \"data\": { \"ref_id\": \"";
    ss << ref_id;
        
    ss << "\", \"hids\": ";
    ss << to_string(chids);
        
    ss << ", \"nids\": ";
    ss << to_string(cnids);
    
    ss << ", \"waf\": ";
    ss << to_string(cwaf);
        
    ss << ", \"misc\": ";
    ss << to_string(cmisc);
        
    ss << ", \"metrics\": ";
    ss << to_string(cmetrics);
        
    ss << ", \"flows\": ";
    ss << to_string(cstatflows);
        
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
        
    unsigned long mapp = stat_flows->mem_mon.applications;
    unsigned long mcount = stat_flows->mem_mon.countries;
    unsigned long mdns = stat_flows->mem_mon.dns_queries;
    unsigned long mssh = stat_flows->mem_mon.ssh_sessions;
    unsigned long mtopt = stat_flows->mem_mon.top_talkers;
    unsigned long mahids = stat_ids->mem_mon.hids_alerts_list;
    unsigned long manids = stat_ids->mem_mon.nids_alerts_list;
    unsigned long mfimc = stat_ids->mem_mon.fim_cause;
    unsigned long mfimf = stat_ids->mem_mon.fim_file;
    unsigned long mhidss = stat_ids->mem_mon.hids_srcip;
    unsigned long mhidsl = stat_ids->mem_mon.hids_location;
    unsigned long midsc = stat_ids->mem_mon.ids_category;
    unsigned long midse = stat_ids->mem_mon.ids_event;
    unsigned long mnidsd = stat_ids->mem_mon.nids_dstip;
    unsigned long mnidss = stat_ids->mem_mon.nids_srcip;
    unsigned long mwafs = stat_ids->mem_mon.waf_source;
    unsigned long mwaft = stat_ids->mem_mon.waf_target;
    unsigned long musers = stat_ids->mem_mon.user_event;
                        
    ss << "{ \"type\": \"node_memory\", \"data\": { \"ref_id\": \"";
    ss << ref_id;
        
    ss << "\", \"flows_application\": ";
    ss << to_string(mapp);
        
    ss << ", \"flows_countries\": ";
    ss << to_string(mcount);
        
    ss << ", \"flows_dns\": ";
    ss << to_string(mdns);
        
    ss << ", \"flows_ssh\": ";
    ss << to_string(mssh);
        
    ss << ", \"flows_talkers\": ";
    ss << to_string(mtopt);
        
    ss << ", \"hids_alerts\": ";
    ss << to_string(mahids);
        
    ss << ", \"nids_alerts\": ";
    ss << to_string(manids);
        
    ss << ", \"fim_cause\": ";
    ss << to_string(mfimc);
        
    ss << ", \"fim_file\": ";
    ss << to_string(mfimf);
        
    ss << ", \"hids_srcip\": ";
    ss << to_string(mhidss);
        
    ss << ", \"hids_location\": ";
    ss << to_string(mhidsl);
        
    ss << ", \"ids_category\": ";
    ss << to_string(midse);
        
    ss << ", \"ids_event\": ";
    ss << to_string(midse);
        
    ss << ", \"nids_dstip\": ";
    ss << to_string(mnidsd);
        
    ss << ", \"nids_srcip\": ";
    ss << to_string(mnidss);
    
    ss << ", \"waf_source\": ";
    ss << to_string(mwafs);
        
    ss << ", \"waf_target\": ";
    ss << to_string(mwaft);
    
    ss << ", \"user_event\": ";
    ss << to_string(musers);
        
    ss << ", \"time_of_survey\": \"";
    ss << GetNodeTime();
    ss << "\" } }";
        
    q_stats_collr.push(ss.str());
        
    ss.str("");
    ss.clear();
        
    unsigned long magent = fs.agents_list.size();
    unsigned long mhnetf = fs.filter.home_nets.size();
    unsigned long mhidsf = fs.filter.hids.gl.size();
    unsigned long mnidsf = fs.filter.nids.gl.size();
    unsigned long mwaff = fs.filter.waf.gl.size();
    unsigned long mmetf = 0;
    unsigned long mtraf = fs.filter.traf.th.size();
        
    ss << "{ \"type\": \"node_filters\", \"data\": { \"ref_id\": \"";
    ss << ref_id;
        
    ss << "\", \"agent_list\": ";
    ss << to_string(magent);
        
    ss << ", \"hnet_list\": ";
    ss << to_string(mhnetf);
        
    ss << ", \"hids_filters\": ";
    ss << to_string(mhidsf);
        
    ss << ", \"nids_filters\": ";
    ss << to_string(mnidsf);
    
    ss << ", \"waf_filters\": ";
    ss << to_string(mwaff);
        
    ss << ", \"metric_filters\": ";
    ss << to_string(mmetf);
        
    ss << ", \"traffic_filters\": ";
    ss << to_string(mtraf);
        
    ss << ", \"time_of_survey\": \"";
    ss << GetNodeTime();
    ss << "\" } }";
        
    q_stats_collr.push(ss.str());
        
    ss.str("");
    ss.clear();
        
    if (wazuhServerStatus) {
        string payload = GetAgentsStatus();
        if (!payload.empty()) {
            
            ParsAgentsStatus(payload);
        
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
            }
        }
    }
}

string Collector::GetAgentsStatus() {
    try
    {
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
        
        string queryStr = "/agents?pretty";

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

void Collector::ParsAgentsStatus (string status) {
    
    stringstream ss(status);
    
    try {
    
        bpt::ptree pt;
        bpt::read_json(ss, pt);
        
        int error =  pt.get<int>("error");
    
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
        
        pt.clear();
    
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
}

void Collector::UpdateFilters() {
    
    try {
        
        ifstream filters_config;
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

void Collector::UpdateSuriConfig() {
    
    if (!strcmp (suri_path, "none")) return; 
    
    try {
        
        ifstream suri_config;
        string dir_path(suri_path);
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
        bd.event_type = 4;
        sk.SendMessage(&bd);
        
        suri_config.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
}

void Collector::UpdateOssecConfig() {
    
    if (!strcmp (wazuh_path, "none")) return; 
    
    try {
        
        ifstream ossec_config;
        string dir_path(wazuh_path);
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

void Collector::UpdateModsecConfig() {
    
    if (!strcmp (modsec_path, "none")) return; 
    
    try {
        
        ifstream modsec_config;
        string dir_path(modsec_path);
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
        bd.event_type = 6;
        sk.SendMessage(&bd);
        
        modsec_config.close();
        boost::iostreams::close(in);
        ResetStreams();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
    } 
    
    return;
}

void Collector::UpdateSuriRules() {
    
    if (!strcmp (suri_rules, "none")) return; 
    
    try {
        
        string root(suri_path);
        string rules(suri_rules);
        
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
                ifstream suri_rules;
                suri_rules.open(file_path.string(),ios::binary);
                strStream << suri_rules.rdbuf();
        
                boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
                in.push(boost::iostreams::gzip_compressor());
                in.push(strStream);
                boost::iostreams::copy(in, comp);
                
                rd.data = comp.str();
                rd.name_rule = file_name;
                rd.ref_id = fs.filter.ref_id;
                rd.event_type = 7;
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

void Collector::UpdateOssecRules() {
    
    if (!strcmp (wazuh_rules, "none")) return; 
    
    try {
        
        string root(wazuh_path);
        string rules(wazuh_rules);
        
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
                ifstream ossec_rules;
                ossec_rules.open(file_path.string(),ios::binary);
                strStream << ossec_rules.rdbuf();
        
                boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
                in.push(boost::iostreams::gzip_compressor());
                in.push(strStream);
                boost::iostreams::copy(in, comp);
                
                rd.data = comp.str();
                rd.name_rule = file_name;
                rd.ref_id = fs.filter.ref_id;
                rd.event_type = 8;
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

void Collector::UpdateModsecRules() {
    
    if (!strcmp (modsec_rules, "none")) return; 
    
    try {
        
        string root(modsec_path);
        string rules(modsec_rules);
        
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
                ifstream modsec_rules;
                modsec_rules.open(file_path.string(),ios::binary);
                strStream << modsec_rules.rdbuf();
        
                boost::iostreams::filtering_streambuf< boost::iostreams::input> in;
                in.push(boost::iostreams::gzip_compressor());
                in.push(strStream);
                boost::iostreams::copy(in, comp);
                
                rd.data = comp.str();
                rd.name_rule = file_name;
                rd.ref_id = fs.filter.ref_id;
                rd.event_type = 9;
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




