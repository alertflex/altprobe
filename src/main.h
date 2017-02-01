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

#ifndef MAIN_H
#define	MAIN_H

#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <execinfo.h>
#include <wait.h>
#include <wchar.h>
#include <pthread.h> 
#include <semaphore.h> 
#include <signal.h>
#include <libconfig.h>
#include <mysql/mysql.h>
#include <zmq.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BOOST_SPIRIT_THREADSAFE
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>


/* Size limit control */
#define OS_PAYLOAD_SIZE      8192    /* Size for logs, sockets, etc */
#define OS_MAXSTR_SIZE       4096    /* Size for logs, sockets, etc */
#define OS_LONG_BUFFER_SIZE  2048    /* Size of long  buffers */
#define OS_BUFFER_SIZE       1024    /* Size of general buffers */
#define OS_LONG_HEADER_SIZE  256     /* Maximum log header size */
#define OS_HEADER_SIZE       128     /* Maximum header size */
#define OS_UUID_SIZE         36      /* DATETIME size */
#define OS_DATETIME_SIZE     32      /* DATETIME size */
#define MAC_SIZE             20      /* MAC size */
#define IP_SIZE              32      /* IP Address size */
#define PORT_SIZE            8       /* Port Address size */

#define BLACKLIST_SIZE       100

#define CONFIG_FILE "/etc/altprobe/altprobe.conf\0"
#define PID_FILE "/var/run/altprobe.pid"
#define DAEMON_NAME "altprobe"

#define MSG_VERSION 0

struct zmq_msg_hdr {
  char url[32];
  u_int32_t version;
  u_int32_t size;
};


#endif	/* MAIN_H */