/* 
 * File:   filters.h
 * Author: Oleg Zharkov
 */
#include <sys/socket.h>
#include "filters.h"

namespace bpt = boost::property_tree;

// FS states
int FiltersSingleton::status = 0;

Filters FiltersSingleton::filter;
std::vector<Agent> FiltersSingleton::agents_list;

int FiltersSingleton::GetFiltersConfig() {
    
    if (!status) {
        
        
        ifstream file(FILTERS_FILE);
        string str; 
        
        ifstream filters_config;
        filters_config.open(FILTERS_FILE);
        stringstream strStream;
        strStream << filters_config.rdbuf();
        
        if (ParsFiltersConfig(strStream.str())) {
            status = 1;
            return status;
        }
    
        SysLog("filters file error: error parsing config data\n");
        return 0;
    }
    
    return 1;
    
}

boost::shared_mutex FiltersSingleton::filters_update;

int FiltersSingleton::ParsFiltersConfig(string f) {
    
    boost::unique_lock<boost::shared_mutex> lock(filters_update);
    
    filter.Reset();
    
    try {
                
        stringstream ss(f);
        
        string id;
        bpt::ptree pt;
        bpt::read_json(ss, pt);
        
        filter.ref_id =  pt.get<string>("ref_id");
        filter.desc =  pt.get<string>("filter_desc");
                
        bpt::ptree home_networks = pt.get_child("home_net");
        BOOST_FOREACH(bpt::ptree::value_type &h_nets, home_networks) {
            
            Network* net = new Network();
            
            net->network = h_nets.second.get<string>("network");
            net->netmask = h_nets.second.get<string>("netmask");
            net->alert_suppress = h_nets.second.get<bool>("alert_suppress");
            
            filter.home_nets.push_back(net);
        }
        
        bpt::ptree name_alias = pt.get_child("alias");
        BOOST_FOREACH(bpt::ptree::value_type &n_alias, name_alias) {
            
            Alias* al = new Alias;
            
            al->agent_name = n_alias.second.get<string>("agent_name");
            al->host_name = n_alias.second.get<string>("host_name");
            al->ip = n_alias.second.get<string>("ip");
                        
            if (al->ip.compare("indef") == 0) {
                
                struct hostent *hostaddr = gethostbyname(al->host_name.c_str());
        
                if (hostaddr != NULL) {
                    
                    al->ip = inet_ntoa(*(struct in_addr *)hostaddr->h_addr_list[0]);
                    filter.alias.push_back(al);
                    
                }
            }
            else filter.alias.push_back(al);
        }
        
        bpt::ptree filters = pt.get_child("sources");
        
        // HIDS
        filter.hids.log = filters.get<bool>("hids.log");
        filter.hids.severity = filters.get<int>("hids.severity");
        
        bpt::ptree hids_bw_list = filters.get_child("hids.bw_list");
        BOOST_FOREACH(bpt::ptree::value_type &hids_list, hids_bw_list) {
            
            BwList* bwl = new BwList();
            
            bwl->event = hids_list.second.get<int>("event");
            bwl->host = hids_list.second.get<string>("agent");
            bwl->action = hids_list.second.get<string>("action");
            
            bwl->agr.reproduced = hids_list.second.get<int>("aggregate.reproduced");  
            bwl->agr.in_period = hids_list.second.get<int>("aggregate.in_period");  
            bwl->agr.new_event = hids_list.second.get<int>("aggregate.new_event");           
            bwl->agr.new_severity = hids_list.second.get<int>("aggregate.new_severity");
            bwl->agr.new_category = hids_list.second.get<string>("aggregate.new_category");
            bwl->agr.new_description = hids_list.second.get<string>("aggregate.new_description");
            
            filter.hids.bwl.push_back(bwl);
        }
        
        // NIDS
        filter.nids.log = filters.get<bool>("nids.log");
        filter.nids.severity = filters.get<int>("nids.severity");
        
        bpt::ptree nids_bw_list = filters.get_child("nids.bw_list");
        BOOST_FOREACH(bpt::ptree::value_type &nids_list, nids_bw_list) {
            
            BwList* bwl = new BwList();
            
            bwl->event = nids_list.second.get<int>("event");
            bwl->host = nids_list.second.get<string>("agent");
            bwl->action = nids_list.second.get<string>("action");
            
            bwl->agr.reproduced = nids_list.second.get<int>("aggregate.reproduced");  
            bwl->agr.in_period = nids_list.second.get<int>("aggregate.in_period");  
            bwl->agr.new_event = nids_list.second.get<int>("aggregate.new_event");           
            bwl->agr.new_severity = nids_list.second.get<int>("aggregate.new_severity");
            bwl->agr.new_category = nids_list.second.get<string>("aggregate.new_category");
            bwl->agr.new_description = nids_list.second.get<string>("aggregate.new_description");
            
            filter.nids.bwl.push_back(bwl);
        }
        
        // NET
        filter.traf.log = filters.get<bool>("netflow.log");
        filter.traf.top_talkers = filters.get<int>("netflow.top_talkers");
        
        bpt::ptree traffic_th_list = filters.get_child("netflow.thresholds");
        BOOST_FOREACH(bpt::ptree::value_type &traffic_list, traffic_th_list) {
            
            Threshold* t = new Threshold();
            
            t->host = traffic_list.second.get<string>("network");
            t->element = traffic_list.second.get<string>("netmask");
            t->parameter = traffic_list.second.get<string>("appl");
            t->action = traffic_list.second.get<string>("action");
            
            t->value_min = traffic_list.second.get<int>("min");
            t->value_max = traffic_list.second.get<int>("max");
                        
            t->agr.reproduced = traffic_list.second.get<int>("aggregate.reproduced");  
            t->agr.in_period = traffic_list.second.get<int>("aggregate.in_period");  
            t->agr.new_event = traffic_list.second.get<int>("aggregate.new_event");           
            t->agr.new_severity = traffic_list.second.get<int>("aggregate.new_severity");
            t->agr.new_category = traffic_list.second.get<string>("aggregate.new_category");
            t->agr.new_description = traffic_list.second.get<string>("aggregate.new_description");
            
            filter.traf.th.push_back(t);
        }
        
        pt.clear();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return 0;
    } 
    
    return 1;
}

boost::shared_mutex FiltersSingleton::agents_update;

void FiltersSingleton::UpdateAgentsList(string id, string ip, string name, string status, 
    string date, string version, string manager, string os_platf, string os_ver, string os_name) {
    
    boost::unique_lock<boost::shared_mutex> lock(agents_update);
    
    std::vector<Agent>::iterator i, end;    
    
    for (i = agents_list.begin(), end = agents_list.end(); i != end; ++i) {
        if (i->name.compare(name) == 0) {
            i->id = id;
            i->ip = ip;
            i->dateAdd = date;
            i->manager_host = manager;
            i->os_name = os_name;
            i->os_platform = os_platf;
            i->os_version = os_ver;
            i->version = version;
            i->status = status;
            return;
        }
    }
    
    agents_list.push_back(Agent(id, ip, name, status, date, version, manager, os_platf, os_ver, os_name));
    
}

string FiltersSingleton::GetAgentNameByIP(string ip) {
    
    boost::shared_lock<boost::shared_mutex> lock(agents_update);
    
    std::vector<Alias*>::iterator i_al, end_al;
    
    for(i_al = filter.alias.begin(), end_al = filter.alias.end(); i_al != end_al; ++i_al) {
        if ((*i_al)->ip.compare(ip) == 0) {
            return (*i_al)->agent_name; 
        }
    }
    
    std::vector<Agent>::iterator i_ag, end_ag;
    
    for(i_ag = agents_list.begin(), end_ag = agents_list.end(); i_ag != end_ag; ++i_ag) {
        if (i_ag->ip.compare(ip) == 0) {
            return i_ag->name;
        }
    }
    
    return "home_net";
}


