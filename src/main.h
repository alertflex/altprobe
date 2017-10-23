/* 
 * File:   main.h
 * Author: Oleg Zharkov
 *
 */

#ifndef MAIN_H
#define	MAIN_H

#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>
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
#include <zmq.h>
#include <yaml.h>
#include <netdb.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <activemq/library/ActiveMQCPP.h>
#include <decaf/lang/Thread.h>
#include <decaf/lang/Runnable.h>
#include <decaf/lang/Integer.h>
#include <decaf/lang/Long.h>
#include <decaf/lang/System.h>
#include <activemq/core/ActiveMQConnectionFactory.h>
#include <activemq/util/Config.h>
#include <cms/Connection.h>
#include <cms/Session.h>
#include <cms/TextMessage.h>
#include <cms/BytesMessage.h>
#include <cms/MapMessage.h>
#include <cms/ExceptionListener.h>
#include <cms/MessageListener.h>

#define BOOST_SPIRIT_THREADSAFE
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <boost/asio.hpp>
#include <cassert>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <list>
#include <vector>
#include <memory>

/* Size limit control */
#define OS_PAYLOAD_SIZE      20480    /* Size for logs, sockets, etc */
#define OS_MAXSTR_SIZE       10240    /* Size for logs, sockets, etc */
#define OS_LONG_BUFFER_SIZE  2048    /* Size of long  buffers */
#define OS_BUFFER_SIZE       1024    /* Size of general buffers */
#define OS_STRING_SIZE       512     /* Comment */
#define OS_LONG_HEADER_SIZE  256     /* Maximum log header size */
#define OS_HEADER_SIZE       128     /* Maximum header size */
#define OS_UUID_SIZE         37      /* DATETIME size */
#define OS_DATETIME_SIZE     32      /* DATETIME size */
#define MAC_SIZE             20      /* MAC size */
#define IP_SIZE              32      /* IP Address size */
#define PORT_SIZE            8       /* Port Address size */

#define BLACKLIST_SIZE       100

#define LOG_QUEUE_SIZE 10000
#define NETFLOW_QUEUE_SIZE 5000
#define IDS_QUEUE_SIZE 1000

#define DELIM "."

#define CONFIG_FILE "/etc/alertflex/alertflex.yaml"
#define FILTERS_FILE "/etc/alertflex/filters.json"
#define PID_FILE "/var/run/alertflex.pid"
#define DAEMON_NAME "alertflex"

#define MSG_VERSION 0

struct zmq_msg_hdr {
  char url[32];
  u_int32_t version;
  u_int32_t size;
};

#define ZDATALEN 1024 * 1024

#endif	/* MAIN_H */