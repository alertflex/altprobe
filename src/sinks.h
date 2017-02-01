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

#ifndef SINKS_H
#define	SINKS_H

#include "mysql.h"
#include "graylog.h"


class Sinks : public ProbeObject {
public:
    // 0 - mysql isn't in use; -1 - mysql has error; 1 - mysql in use
    int mysql_state;
    // 0 - udplog isn't in use; -1 - udplog has error; 1 - udplog in use
    int graylog_state;
    
    
    // DB operations
    Mysql mysql;
    
    // Log operations
    GrayLog graylog;
    
    Sinks () {
        mysql_state = 0;
        graylog_state = 0;
    }
    
   int Open();
    void Close();
    
    virtual int GetConfig(config_t cfg);
    
    int GetStateMysql() { return mysql_state; }
    int GetStateGraylog() { return graylog_state; }
    
    void SetStateMysql(int s) {
        
        if (!mysql.status) return;
        
        if ((mysql_state == 1) && (s == 1)) return;
        
        mysql_state = s; 
    }
    
    void SetStateGraylog(int s) { 
        
        if (!graylog.status) return;
        
        if ((graylog_state == 1) && (s == 1)) return;
        
        graylog_state = s; 
        
    }
    
};

#endif	/* SINKS_H */

