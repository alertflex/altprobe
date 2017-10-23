/* 
 * File:   filters.h
 * Author: Oleg Zharkov
 */

#include "filters.h"

namespace bpt = boost::property_tree;

// FS states
int FiltersSingleton::status = 0;

// Buffer for data
char* FiltersSingleton::config_data;
int FiltersSingleton::config_data_len = 0;

// local file settings
FILE* FiltersSingleton::f;
char FiltersSingleton::config_file[OS_STRING_SIZE];

Filters FiltersSingleton::filter;

int FiltersSingleton::GetFiltersConfig() {
    
    if (!status) {
        
        config_data = (char*) malloc(ZDATALEN * sizeof(char));
        config_data_len = ZDATALEN;
    
        f = fopen(FILTERS_FILE, "r");
    
        fseek(f, 0, SEEK_END);
        config_data_len = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        if (config_data_len + 1 > ZDATALEN) {
            SysLog("Error size for filters config\n");
            fclose(f);
            return 0;
        }
        
        fread(config_data, config_data_len, 1, f); 
    
        if (ParsConfig()) {
            status = 1;
            
            fclose(f);
            free(config_data);
            
            return 1;
        }
    
        SysLog("filters file error: error parsing config data\n");
    
        fclose(f);
        free(config_data);
    
        return 0;
    }
    
    return 1;
    
}


int FiltersSingleton::ParsConfig() {
    
    try {
                
        stringstream ss(config_data);
        
        string id;
        bpt::ptree pt;
        bpt::read_json(ss, pt);
        
        filter.ref_id =  pt.get<string>("ref_id");
        filter.name =  pt.get<string>("filter_name");
                
        bpt::ptree home_networks = pt.get_child("home_net");
        BOOST_FOREACH(bpt::ptree::value_type &h_nets, home_networks) {
            
            Network* net = new Network();
            
            net->network = h_nets.second.get<string>("network");
            net->netmask = h_nets.second.get<string>("netmask");
            
            filter.home_nets.push_back(net);
        }
        
        bpt::ptree filters = pt.get_child("sources");
        
        // HIDS
        filter.hids.log = filters.get<bool>("hids.log");
        filter.hids.severity = filters.get<int>("hids.severity");
        
        bpt::ptree hids_bw_list = filters.get_child("hids.bw_list");
        BOOST_FOREACH(bpt::ptree::value_type &hids_list, hids_bw_list) {
            
            BwList* bwl = new BwList();
            
            bwl->event = hids_list.second.get<int>("event");
            bwl->ip = hids_list.second.get<string>("ip");
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
            bwl->ip = nids_list.second.get<string>("ip");
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
        filter.traffic.log = filters.get<bool>("traffic.log");
        filter.traffic.top_talkers = filters.get<int>("traffic.top_talkers");
        
        bpt::ptree traffic_th_list = filters.get_child("traffic.thresholds");
        BOOST_FOREACH(bpt::ptree::value_type &traffic_list, traffic_th_list) {
            
            Threshold* t = new Threshold();
            
            t->ip = traffic_list.second.get<string>("ip");
            t->app_proto = traffic_list.second.get<string>("appl");
            t->action = traffic_list.second.get<string>("action");
            
            t->traffic_min = traffic_list.second.get<int>("min");
            t->traffic_max = traffic_list.second.get<int>("max");
                        
            t->agr.reproduced = traffic_list.second.get<int>("aggregate.reproduced");  
            t->agr.in_period = traffic_list.second.get<int>("aggregate.in_period");  
            t->agr.new_event = traffic_list.second.get<int>("aggregate.new_event");           
            t->agr.new_severity = traffic_list.second.get<int>("aggregate.new_severity");
            t->agr.new_category = traffic_list.second.get<string>("aggregate.new_category");
            t->agr.new_description = traffic_list.second.get<string>("aggregate.new_description");
            
            filter.traffic.th.push_back(t);
        }
        
        pt.clear();
        
    } catch (const std::exception & ex) {
        SysLog((char*) ex.what());
        return 0;
    } 
    
    return 1;
}


