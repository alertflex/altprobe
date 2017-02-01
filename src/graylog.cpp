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

#include "graylog.h"

int GrayLog::flag = 0;
int GrayLog::status = 0;
int GrayLog::port = 0;
char GrayLog::host[OS_HEADER_SIZE];


int GrayLog::Open() {
    
    if ( (s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {     // create a client socket
        SysLog("failed open socket for GrayLog");
        return 0;
    }
    
    
    memset((char *) &srv_in, 0, sizeof(srv_in));
    slen=sizeof(srv_in);
    srv_in.sin_family = AF_INET;
    srv_in.sin_port = htons(port);
    srv_in.sin_addr.s_addr = inet_addr(host);
    if (srv_in.sin_addr.s_addr == -1) {
        SysLog("wrong host address for GrayLog - ");
        SysLog(host);
        return 0;
    }
    
    return 1;
}

int GrayLog::GetConfig(config_t cfg) {
    
    const char *base = NULL;
    
    if (!flag) {
        
        if (config_lookup_string(&cfg, "destinations.graylog.host", &base)) {
            if (!strcmp(base, "none")) return 0;
            else strncpy (host, base,  OS_HEADER_SIZE);
        } 
        else goto return_with_error;    
        
        if (!config_lookup_int(&cfg, "destinations.graylog.port", &port)) 
            goto return_with_error;
                
        status = 1;
    } 
    
    return status;
    
return_with_error:
    SysLog("AltProbe config error - GrayLog configuration.");
    return 0;
}

int GrayLog::SendMessage(char* msg) {
    
    if (sendto(s, msg, strlen(msg) , 0 , (struct sockaddr *) &srv_in, slen) == -1) {
        SysLog(strerror(errno));
        return 0;
    }
    return 1;
}

void GrayLog::Close() {
    close(s);
}


