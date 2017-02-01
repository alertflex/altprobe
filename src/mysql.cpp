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

#include "mysql.h"

int Mysql::flag = 0;
int Mysql::status = 0;
char Mysql::host[OS_HEADER_SIZE];
char Mysql::user[OS_HEADER_SIZE];
char Mysql::pwd[OS_HEADER_SIZE];
char Mysql::db[OS_HEADER_SIZE];

int Mysql::Open() {
    
    conn = mysql_init(NULL);
    
    if (conn) 
        if (!mysql_real_connect(conn, host, user, pwd, db, 0, NULL, 0)) {
             sprintf(SysLogInfo, "Failed to connect to MySQL database - %s", mysql_error(&mysql));
             SysLog(NULL);
             return 0;
        }
    
    return 1;
}

int Mysql::Query(char* sql_query) {
    
    if(mysql_query(conn, sql_query) != 0) {
        sprintf(SysLogInfo, "MySQL database query error: %s\n for sql: %s", mysql_error(conn), sql_query);
        SysLog(NULL);
        return 0;
    }
    
    if (mysql_store_result(conn) == 0 && mysql_field_count(conn) == 0 && mysql_insert_id(conn) != 0)
        usedid = mysql_insert_id(conn);
        
    return 1;
}


int Mysql::GetConfig(config_t cfg) {
    
    const char *base = NULL;
    
    if (!flag) {
        if (config_lookup_string(&cfg, "destinations.mysql.host", &base)) {
            if (!strcmp(base, "none")) return 0;
            else strncpy (host, base,  OS_HEADER_SIZE);
        }   
        else goto return_with_error;
        
        if (config_lookup_string(&cfg, "destinations.mysql.user", &base))
            strncpy (user, base,  OS_HEADER_SIZE);
        else goto return_with_error;
    
        if (config_lookup_string(&cfg, "destinations.mysql.password", &base))
            strncpy (pwd, base,  OS_HEADER_SIZE);
        else goto return_with_error;
    
        if (config_lookup_string(&cfg, "destinations.mysql.db_name", &base))
            strncpy (db, base,  OS_HEADER_SIZE);
        else goto return_with_error;
        
        status = 1;
    } 
    
    return status;
    
return_with_error:
    SysLog("AltProbe config error - MySQL database configuration.");
    return 0;
}



