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

#ifndef MYSQL_H
#define	MYSQL_H


#include "pobject.h"

class Mysql : public ProbeObject {
public:
    
    static int flag;
    static int status;
    
    // DB parameters
    static char host[OS_HEADER_SIZE];
    static char user[OS_HEADER_SIZE];
    static char pwd[OS_HEADER_SIZE];
    static char db[OS_HEADER_SIZE];
    
    MYSQL* conn, mysql;
    
    //usedid is keeping the indicator of last SQL request
    int usedid; 
    
    int Open();
    virtual int GetConfig(config_t cfg);
    int GetStatus() { return status; }
    int Query(char* sql_query);
    void Close() {
        mysql_close(conn);
    }
    
};

#endif	/* MYSQL_H */

