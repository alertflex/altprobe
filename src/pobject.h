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

#ifndef POBJECT_H
#define	POBJECT_H

#include "main.h"

using namespace std;

class ProbeObject {
public:
    // var to check is x_id already loaded or not
    static int flag;
    //
    static char probe_id[OS_UUID_SIZE];
        
    //Syslog info string
    char SysLogInfo[OS_LONG_HEADER_SIZE];
    
    char collector_time[OS_DATETIME_SIZE]; 
    
    char* GetProbeId()  { return probe_id; }
    virtual int GetConfig(config_t cfg);
    //Send info to SysLog 
    void SysLog(char* info);
    string GetCollectorTimeGraylogFormat();
};

#endif	/* POBJECT_H */

