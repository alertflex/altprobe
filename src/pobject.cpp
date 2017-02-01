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

#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <libdaemon/dexec.h>

#include "pobject.h"

int ProbeObject::flag = 0;

char ProbeObject::probe_id[OS_UUID_SIZE];

int ProbeObject::GetConfig(config_t cfg) {
    
    const char *base = NULL;
    
    if (!flag) {
    
        if (!config_lookup_string(&cfg, "probe.probe_id", &base)) {
            SysLog("AltProbe config error - can't read probe_id.");
            return 0;
        }
    
        strncpy (probe_id, base, OS_UUID_SIZE);
        
        flag = 1;
    }
    
    return 1;
}


void ProbeObject::SysLog(char* info) {
    
    //If info equael NULL fuction send var SysLogInfo as String to SysLog
    if (info == NULL) daemon_log(LOG_ERR, "%s", SysLogInfo);
    else daemon_log(LOG_ERR, "%s", info);
}

string ProbeObject::GetCollectorTimeGraylogFormat() {
    time_t rawtime;
    struct tm * timeinfo;
        
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(collector_time,sizeof(collector_time),"%Y-%m-%dT%H:%M:%S.000Z",timeinfo);
    
    return string(collector_time);
}

