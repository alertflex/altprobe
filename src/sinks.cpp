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

#include "sinks.h"

int Sinks::GetConfig(config_t cfg) {
    //get probe_id name
    if(!ProbeObject::GetConfig(cfg)) return 0; 
                        
    
    mysql.GetConfig(cfg);
    graylog.GetConfig(cfg);
    
    //get status configuration
    if(!mysql.status && !graylog.status) return 0;
    
    return 1;
}


int Sinks::Open() {
    if(mysql_state == 1) 
        if(!mysql.Open()) return 0;
        
    if(graylog_state == 1) 
        if(!graylog.Open()) return 0;
    
    return 1;
}


void Sinks::Close() {
    
    mysql.Close();
    mysql_state = 0;
        
    graylog.Close();
    graylog_state = 0;
}
