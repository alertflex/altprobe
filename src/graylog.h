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

#ifndef GRAY_LOG_H
#define	GRAY_LOG_H


#include "pobject.h"

class GrayLog : public ProbeObject {
public:
    static int flag;
    static int status;
    
    static char host[OS_HEADER_SIZE];
    static int port;
       
    //Socket parameters
    int s, slen;
    struct sockaddr_in srv_in;
     
    int Open();
    virtual int GetConfig(config_t cfg);
    int GetStatus() { return status; }
    int SendMessage(char* msg);
    void Close();
};

#endif	/* GRAY_LOG_H */

