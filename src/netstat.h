/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   netstat.h
 * Author: Oleg Zharkov
 *
 * Created on May 15, 2020, 10:47 PM
 */

#ifndef NETSTAT_H
#define NETSTAT_H

#include "main.h"

using namespace std;

class Netstat {
public:
    string ref_id;
    string ids;
    unsigned long drop;
    unsigned long accept;
    unsigned long invalid;
    unsigned long pkts;
    unsigned long bytes;
    
    unsigned long ipv4;
    unsigned long ipv6;
    unsigned long ethernet;
    unsigned long tcp;
    unsigned long udp;
    unsigned long sctp;
    unsigned long icmpv4;
    unsigned long icmpv6;
    unsigned long ppp;
    unsigned long pppoe;
    unsigned long gre;
    unsigned long vlan;
    unsigned long vlan_qinq;
    unsigned long teredo;
    unsigned long ipv4_in_ipv6;
    unsigned long ipv6_in_ipv6;
    unsigned long mpls;
        
    void Reset() {
        ref_id.clear();
        ids.clear();
        invalid = 0;
        pkts = 0;
        bytes = 0;
        ipv4 = 0;
        ipv6 = 0;
        ethernet = 0;
        tcp = 0;
        udp = 0;
        sctp = 0;
        icmpv4 = 0;
        icmpv6 = 0;
        ppp = 0;
        pppoe = 0;
        gre = 0;
        vlan = 0;
        vlan_qinq = 0;
        teredo = 0;
        ipv4_in_ipv6 = 0;
        ipv6_in_ipv6 = 0;
        mpls = 0;
    }
    
    void Aggregate (Netstat* ns) {
        ref_id = ns->ref_id;
        invalid = invalid + ns->invalid;
        pkts = pkts + ns->pkts;
        bytes = bytes + ns->bytes;
        ipv4 = ipv4 + ns->ipv4;
        ipv6 = ipv6 + ns->ipv6;
        ethernet = ethernet + ns->ethernet;
        tcp = tcp + ns->tcp;
        udp = udp + ns->udp;
        sctp = sctp + ns->sctp;
        icmpv4 = icmpv4 + ns->icmpv4;
        icmpv6 = icmpv6 + ns->icmpv6;
        ppp = ppp + ns->ppp;
        pppoe = pppoe + ns->pppoe;
        gre = gre + ns->gre;
        vlan = vlan + ns->vlan;
        vlan_qinq = vlan_qinq + ns->vlan_qinq;
        teredo = teredo + ns->teredo;
        ipv4_in_ipv6 = ipv4_in_ipv6 + ns->ipv4_in_ipv6;
        ipv6_in_ipv6 = ipv6_in_ipv6 + ns->ipv6_in_ipv6;
        mpls = mpls + ns->mpls;
    }
    
    Netstat () {
        Reset();
    }
    
    ~Netstat () {
        Reset();
    }
};

extern boost::lockfree::spsc_queue<Netstat> q_netstat;

#endif /* NETSTAT_H */

