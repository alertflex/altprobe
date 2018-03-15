/* 
 * File:   main.cpp
 * Author: Oleg Zharkov
 *
 */


#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <libdaemon/dexec.h>

#include "statflows.h"
#include "statids.h"
#include "hids.h"
#include "metric.h"
#include "nids.h"
#include "collector.h"
#include "remlog.h"
#include "remstat.h"
#include "updates.h"

StatIds statids;
pthread_t pthread_statids;

void* exit_thread_statids_arg;
void exit_thread_statids(void* arg) { statids.Close(); }

void * thread_statids(void *arg) {
    
    pthread_cleanup_push(exit_thread_statids, exit_thread_statids_arg);
    
    while (statids.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

StatFlows statflows;
pthread_t pthread_statflows;

void* exit_thread_statflows_arg;
void exit_thread_statflows(void* arg) { statflows.Close(); }

void * thread_statflows(void *arg) {
    
    pthread_cleanup_push(exit_thread_statflows, exit_thread_statflows_arg);
    
    while (statflows.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Metric met("metricbeat");
pthread_t pthread_met;

void* exit_thread_met_arg;
void exit_thread_met(void* arg) { met.Close(); }

void * thread_met(void *arg) {
    
    pthread_cleanup_push(exit_thread_met, exit_thread_met_arg);
    
    while (met.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Hids hids("ossec");
pthread_t pthread_hids;

void* exit_thread_hids_arg;
void exit_thread_hids(void* arg) { hids.Close(); }

void * thread_hids(void *arg) {
    
    pthread_cleanup_push(exit_thread_hids, exit_thread_hids_arg);
    
    while (hids.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Nids nids("suricata");
pthread_t pthread_nids;

void* exit_thread_nids_arg;
void exit_thread_nids(void* arg) { nids.Close(); }

void * thread_nids(void *arg) {
    
    pthread_cleanup_push(exit_thread_nids, exit_thread_nids_arg);
    
    while (nids.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

RemLog remlog;
pthread_t pthread_remlog;

void* exit_thread_remlog_arg;
void exit_thread_remlog(void* arg) { remlog.Close(); }

void * thread_remlog(void *arg) {
    
    pthread_cleanup_push(exit_thread_remlog, exit_thread_remlog_arg);
    
    while (remlog.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

RemStat remstat;
pthread_t pthread_remstat;

void* exit_thread_remstat_arg;
void exit_thread_remstat(void* arg) { remstat.Close(); }

void * thread_remstat(void *arg) {
    
    pthread_cleanup_push(exit_thread_remstat, exit_thread_remstat_arg);
    
    while (remstat.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Updates updates;
pthread_t pthread_updates;

void* exit_thread_updates_arg;
void exit_thread_updates(void* arg) { updates.Close(); }

void * thread_updates(void *arg) {
    
    pthread_cleanup_push(exit_thread_updates, exit_thread_updates_arg);
    
    while (updates.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}


Collector collr(&hids, &nids, &met, &remlog, &remstat, &statflows, &statids);
pthread_t pthread_collr;

void* exit_thread_collr_arg;
void exit_thread_collr(void* arg) { collr.Close(); }

void * thread_collr(void *arg) {
    
    pthread_cleanup_push(exit_thread_collr, exit_thread_collr_arg);
    
    while (collr.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

int LoadConfig(void)
{
    //statids
    if (!statids.GetConfig()) return 0;
    
    //statflow
    if (!statflows.GetConfig()) return 0;
    
    //metrics
    if (!met.GetConfig()) return 0;
    
    //hids
    if (!hids.GetConfig()) return 0;
    
    //nids
    if (!nids.GetConfig()) return 0;
    
    //remlog
    if (!remlog.GetConfig()) return 0;
    
    //remstat
    if (!remstat.GetConfig()) return 0;
    
    // updates
    if (!updates.GetConfig()) return 0;
    
    //collector
    if (!collr.GetConfig()) return 0;
    
    return 1;
}

       
int InitThreads(void)
{
    int arg = 1;
    
    //statids
    if (statids.GetStatus()) {
        if (!statids.Open()) {
            daemon_log(LOG_ERR,"cannot open ids stat service");
            return 0;
        }
            
        if (pthread_create(&pthread_statids, NULL, thread_statids, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for ids stat");
            return 0;
        }
    }
    
    //traffic
    if (statflows.GetStatus()) {
        if (!statflows.Open()) {
            daemon_log(LOG_ERR,"cannot open statflow service");
            return 0;
        }
            
        if (pthread_create(&pthread_statflows, NULL, thread_statflows, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for statflow");
            return 0;
        }
    }
    
    //metrics
    if (met.GetStatus()) {
        if (!met.Open()) {
            daemon_log(LOG_ERR,"cannot open Metrics server");
            return 0;
        }
            
        if (pthread_create(&pthread_met, NULL, thread_met, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for metrics");
            return 0;
        }
    }
    
    //hids
    if (hids.GetStatus()) {
        if (!hids.Open()) {
            daemon_log(LOG_ERR,"cannot open OSSEC server");
            return 0;
        }
            
        if (pthread_create(&pthread_hids, NULL, thread_hids, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for OSSEC");
            return 0;
        }
    } 
    
    //nids
    if (nids.GetStatus()) {
        if (!nids.Open()) {
            daemon_log(LOG_ERR,"cannot open Suricata server");
            return 0;
        }
        
        if (pthread_create(&pthread_nids, NULL, thread_nids, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for Suricata.");
            return 0;
        } 
    }
    
    //remlog
    if (remlog.GetStatus()) {
        if (!remlog.Open()) {
            daemon_log(LOG_ERR,"cannot open RemLog service");
            return 0;
        }
    
        if (pthread_create(&pthread_remlog, NULL, thread_remlog, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for RemLog service");
            return 0;
        } 
    }
    
    //remstat
    if (remstat.GetStatus()) {
        if (!remstat.Open()) {
            daemon_log(LOG_ERR,"cannot open RemStat service");
            return 0;
        }
    
        if (pthread_create(&pthread_remstat, NULL, thread_remstat, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for RemStat service");
            return 0;
        } 
    }
    
    // updates
    if (updates.GetStatus()) {
        
        if (!updates.Open()) {
            daemon_log(LOG_ERR,"cannot open update service");
            return 0;
        }
        if (pthread_create(&pthread_updates, NULL, thread_updates, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for update service");
            return 0;
        } 
    }
    
    //collector
    if (collr.GetStatus()) {
        if (!collr.Open()) {
            daemon_log(LOG_ERR,"cannot open monitorint of Collector service");
            return 0;
        }
    
        if (pthread_create(&pthread_collr, NULL, thread_collr, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for monitoring collector service");
            return 0;
        } 
    }
    
    return 1;
}

void KillsThreads(void)
{
    //statids
    if (statids.GetStatus()) {
        pthread_cancel(pthread_statids);
        pthread_join(pthread_statids, NULL);
    }
    
    //traffic
    if (statflows.GetStatus()) {
        pthread_cancel(pthread_statflows);
        pthread_join(pthread_statflows, NULL);
    }
    
    //metrics
    if (met.GetStatus()) {
        pthread_cancel(pthread_met);
        pthread_join(pthread_met, NULL);
    }
    
    //hids
    if (hids.GetStatus()) {
        pthread_cancel(pthread_hids);
        pthread_join(pthread_hids, NULL);
    }
        
    //nids
    if (nids.GetStatus()) {
        pthread_cancel(pthread_nids);
        pthread_join(pthread_nids, NULL);
    }
    
    //remlog
    if (remlog.GetStatus()) {
        pthread_cancel(pthread_remlog);
        pthread_join(pthread_remlog, NULL); 
    }
    
    //remstat
    if (remstat.GetStatus()) {
        pthread_cancel(pthread_remstat);
        pthread_join(pthread_remstat, NULL); 
    }
    
    // updates
    if (updates.GetStatus()) {
        pthread_cancel(pthread_updates);
        pthread_join(pthread_updates, NULL); 
    }
    
    //collector
    if (collr.GetStatus()) {
        pthread_cancel(pthread_collr);
        pthread_join(pthread_collr, NULL); 
    }
}


int main(int argc, char *argv[]) {
    pid_t pid;
    int ret;
    
    

    /* Reset signal handlers */
    if (daemon_reset_sigs(-1) < 0) {
        daemon_log(LOG_ERR, "failed to reset all signal handlers: %s", strerror(errno));
        return 1;
    }

    /* Unblock signals */
    if (daemon_unblock_sigs(-1) < 0) {
        daemon_log(LOG_ERR, "failed to unblock all signals: %s", strerror(errno));
        return 1;
    }

    /* Set indetification string for the daemon for both syslog and PID file */
    daemon_pid_file_ident = daemon_log_ident = daemon_ident_from_argv0(argv[0]);
    
    /* Check if we are called with parameters */
    if (argc == 2) {
        if (!strcmp(argv[1], "start")) {
             if ((pid = daemon_pid_file_is_running()) >= 0)
                  // daemon_log(LOG_ERR, "AlertFlex collector is already running with PID %u.", pid);
                  printf( "alertflex collector is already running with PID %u\n", pid);
             else goto start;
             return 0;
        }
        
        if (!strcmp(argv[1], "stop")) {
             /* Kill daemon with SIGTERM */
             /* Check if the new function daemon_pid_file_kill_wait() is available, if it is, use it. */
             if ((ret = daemon_pid_file_kill_wait(SIGTERM, 5)) < 0)
                  // daemon_log(LOG_ERR, "Failed to kill AlertFlex collector: %s.", strerror(errno));
                  printf( "failed to kill alertflex collector: %s\n", strerror(errno));
             //else daemon_log(LOG_ERR, "AlertFlex collector is stopping.");
             else printf( "alertflex collector is stopping\n");
             return ret < 0 ? 1 : 0;
        }
        
        if (!strcmp(argv[1], "status")) {                        
             /* Check that the daemon is not rung twice a the same time */
             if ((pid = daemon_pid_file_is_running()) >= 0)
                  //daemon_log(LOG_ERR, "AlertFlex collector is running with PID %u.", pid);
                  printf( "alertflex collector is running, process %u\n", pid);
             //else daemon_log(LOG_ERR, "AlertFlex collector isn't running.");
             else printf( "alertflex collector isn't running\n");
             return 0;
        }
    }
    
    // daemon_log(LOG_ERR, "usage: ./afcollector {start|stop|status}");
    printf( "usage: ./alertflex {start|stop|status}\n");
    return 0;

start:    
    if (!LoadConfig()) return 1;
    int startup_timer = statids.GetStartupTimer();
        
    /* Prepare for return value passing from the initialization procedure of the daemon process */
    if (daemon_retval_init() < 0) {
        daemon_log(LOG_ERR, "failed to create pipe");
        return 1;
    }

    /* Do the fork */
    if ((pid = daemon_fork()) < 0) {

        /* Exit on error */
        daemon_retval_done();
        return 1;

    } else if (pid) { /* The parent */
        
        int ret;
        
        /* Wait for timeout in seconds for the return value passed from the daemon process */
        if ((ret = daemon_retval_wait(startup_timer)) < 0) {
            daemon_log(LOG_ERR, "could not receive return value from alertflex collector process: %s", strerror(errno));
            return 255;
        }

        daemon_log(ret != 0 ? LOG_ERR : LOG_INFO, "alertflex collector started with code %i", ret);
        return ret;

    } else { /* The daemon */
        int fd, quit = 0;
        fd_set fds;

        /* Close FDs */
        if (daemon_close_all(-1) < 0) {
            daemon_log(LOG_ERR, "failed to close all file descriptors: %s", strerror(errno));

            /* Send the error condition to the parent process */
            daemon_retval_send(1);
            goto finish;
        }

        /* Create the PID file */
        if (daemon_pid_file_create() < 0) {
            daemon_log(LOG_ERR, "could not create PID file (%s)", strerror(errno));
            daemon_retval_send(2);
            goto finish;
        }

        /* Initialize signal handling */
        if (daemon_signal_init(SIGINT, SIGTERM, SIGQUIT, SIGHUP, SIGUSR1, 0) < 0) {
            daemon_log(LOG_ERR, "could not register signal handlers (%s)", strerror(errno));
            daemon_retval_send(3);
            goto finish;
        }

        /*... do some further init work here */
        if (!InitThreads()) {
            daemon_retval_send(4);
            goto finish;
        }

        /* Send OK to parent process */
        daemon_retval_send(0);

        daemon_log(LOG_INFO, "alertflex collector has been successfully started");

        /* Prepare for select() on the signal fd */
        FD_ZERO(&fds);
        fd = daemon_signal_fd();
        FD_SET(fd, &fds);

        while (!quit) {
            fd_set fds2 = fds;

            /* Wait for an incoming signal */
            if (select(FD_SETSIZE, &fds2, 0, 0, 0) < 0) {

                /* If we've been interrupted by an incoming signal, continue */
                if (errno == EINTR)
                    continue;

                daemon_log(LOG_ERR, "select(): %s", strerror(errno));
                break;
            }

            /* Check if a signal has been recieved */
            if (FD_ISSET(fd, &fds2)) {
                int sig;

                /* Get signal */
                if ((sig = daemon_signal_next()) <= 0) {
                    daemon_log(LOG_ERR, "daemon_signal_next() failed: %s", strerror(errno));
                    break;
                }

                /* Dispatch signal */
                switch (sig) {
                    case SIGHUP:
                    case SIGINT:
                    case SIGQUIT:
                    case SIGTERM:
                        daemon_log(LOG_WARNING, "got SIGHUP, SIGINT, SIGQUIT or SIGTERM");
                        quit = 1;
                        break;

                }
            }
        }

        /* Do a cleanup */
finish:
        daemon_log(LOG_INFO, "exiting...");
        KillsThreads();
        daemon_retval_send(255);
        daemon_signal_done();
        daemon_pid_file_remove();

        return 0;
    }
}





