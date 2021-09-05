/*
 *   Copyright 2021 Oleg Zharkov
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <libdaemon/dexec.h>

#include "aggalerts.h"
#include "aggnet.h"
#include "aws.h"
#include "hids.h"
#include "crs.h"
#include "misc.h"
#include "nids.h"
#include "collector.h"
#include "remlog.h"
#include "remstat.h"
#include "updates.h"
#include "scanners.h"

AggAlerts aggalerts;
pthread_t pthread_aggalerts;

void* exit_thread_aggalerts_arg;
void exit_thread_aggalerts(void* arg) { aggalerts.Close(); }

void * thread_aggalerts(void *arg) {
    
    pthread_cleanup_push(exit_thread_aggalerts, exit_thread_aggalerts_arg);
    
    while (aggalerts.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

AggNet aggnet;
pthread_t pthread_aggnet;

void* exit_thread_aggnet_arg;
void exit_thread_aggnet(void* arg) { aggnet.Close(); }

void * thread_aggnet(void *arg) {
    
    pthread_cleanup_push(exit_thread_aggnet, exit_thread_aggnet_arg);
    
    while (aggnet.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Misc misc("misc_redis");
pthread_t pthread_misc;

void* exit_thread_misc_arg;
void exit_thread_misc(void* arg) { misc.Close(); }

void * thread_misc(void *arg) {
    
    pthread_cleanup_push(exit_thread_misc, exit_thread_misc_arg);
    
    while (misc.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

AwsWaf aws("aws_redis");
pthread_t pthread_aws;

void* exit_thread_aws_arg;
void exit_thread_aws(void* arg) { aws.Close(); }

void * thread_aws(void *arg) {
    
    pthread_cleanup_push(exit_thread_aws, exit_thread_aws_arg);
    
    while (aws.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Crs crs("falco_redis");
pthread_t pthread_crs;

void* exit_thread_crs_arg;
void exit_thread_crs(void* arg) { crs.Close(); }

void * thread_crs(void *arg) {
    
    pthread_cleanup_push(exit_thread_crs, exit_thread_crs_arg);
    
    while (crs.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Waf waf("modsec_redis");
pthread_t pthread_waf;

void* exit_thread_waf_arg;
void exit_thread_waf(void* arg) { waf.Close(); }

void * thread_waf(void *arg) {
    
    pthread_cleanup_push(exit_thread_waf, exit_thread_waf_arg);
    
    while (waf.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Nids nids("suri_redis");
pthread_t pthread_nids;

void* exit_thread_nids_arg;
void exit_thread_nids(void* arg) { nids.Close(); }

void * thread_nids(void *arg) {
    
    pthread_cleanup_push(exit_thread_nids, exit_thread_nids_arg);
    
    while (nids.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Hids hids("wazuh_redis");
pthread_t pthread_hids;

void* exit_thread_hids_arg;
void exit_thread_hids(void* arg) { hids.Close(); }

void * thread_hids(void *arg) {
    
    pthread_cleanup_push(exit_thread_hids, exit_thread_hids_arg);
    
    while (hids.Go()) { }
    
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

Scanners scanners;
pthread_t pthread_scanners;

void* exit_thread_scanners_arg;
void exit_thread_scanners(void* arg) { scanners.Close(); }

void * thread_scanners(void *arg) {
    
    pthread_cleanup_push(exit_thread_scanners, exit_thread_scanners_arg);
    
    while (scanners.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}


Collector collr(&aws, &crs, &hids, &nids, &waf, &remlog, &remstat);
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
    //aggalerts
    if (!aggalerts.GetConfig()) return 0;
    
    //aggnet
    if (!aggnet.GetConfig()) return 0;
    
    //misc
    if (!misc.GetConfig()) return 0;
    
    //aws
    if (!aws.GetConfig()) return 0;
    
    //hids
    if (!hids.GetConfig()) return 0;
    
    //nids
    if (!nids.GetConfig()) return 0;
    
    //crs
    if (!crs.GetConfig()) return 0;
    
    //waf
    if (!waf.GetConfig()) return 0;
    
    //remlog
    if (!remlog.GetConfig()) return 0;
    
    //remstat
    if (!remstat.GetConfig()) return 0;
    
    // updates
    if (!updates.GetConfig()) return 0;
    
    // scanners
    if (!scanners.GetConfig()) return 0;
    
    //collector
    if (!collr.GetConfig()) return 0;
    
    return 1;
}

       
int InitThreads(int mode, pid_t pid)
{
    int arg = 1;
    
    // aggalerts
    if (aggalerts.GetStatus() > 0) {
        
        if (!aggalerts.Open() > 0) {
            daemon_log(LOG_ERR,"cannot open Aggregation alerts module");
            return 0;
        }
            
        if (pthread_create(&pthread_aggalerts, NULL, thread_aggalerts, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for ids stat");
            return 0;
        }
    }
    
    //aggnet
    if (aggnet.GetStatus() > 0) {
        
        if (!aggnet.Open() > 0) {
            daemon_log(LOG_ERR,"cannot open Aggregation net module");
            return 0;
        }
            
        if (pthread_create(&pthread_aggnet, NULL, thread_aggnet, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for aggnet");
            return 0;
        }
    }
    
     //misc
    if (misc.GetStatus() > 0) {
        
        if (misc.Open() > 0) {
            
            if (pthread_create(&pthread_misc, NULL, thread_misc, &arg)) {
                daemon_log(LOG_ERR,"error creating thread for MISC module");
                return 0;
            }
            
        } else daemon_log(LOG_ERR,"MISC source is disabled");
            
    }
    
     //aws
    if (aws.GetStatus() > 0) {
        
        if (aws.Open() > 0) {
            
            if (pthread_create(&pthread_aws, NULL, thread_aws, &arg)) {
                daemon_log(LOG_ERR,"error creating thread for AWS module");
                return 0;
            }
            
        } else daemon_log(LOG_ERR,"AWS source is disabled");
            
    }
    
    //hids
    if (hids.GetStatus() > 0) {
        
        if (hids.Open() > 0) {
            
            if (pthread_create(&pthread_hids, NULL, thread_hids, &arg)) {
                daemon_log(LOG_ERR,"error creating thread for HIDS module");
                return 0;
            }
            
        } else daemon_log(LOG_ERR,"HIDS source is disabled");
    }
    
        
    //nids
    if (nids.GetStatus() > 0) {
        
        if (nids.Open() > 0) {
            
            if (pthread_create(&pthread_nids, NULL, thread_nids, &arg)) {
                daemon_log(LOG_ERR,"error creating thread for NIDS module");
                return 0;
            }
            
        } else daemon_log(LOG_ERR,"NIDS source is disabled");
    }
    
    //crs
    if (crs.GetStatus() > 0) {
        
        if (crs.Open() > 0) {
            
            if (pthread_create(&pthread_crs, NULL, thread_crs, &arg)) {
                daemon_log(LOG_ERR,"error creating thread for CRS module");
                return 0;
            }
        } else daemon_log(LOG_ERR,"CRS source is disabled");
    } 
    
    //waf
    if (waf.GetStatus() > 0) {
        
        if (waf.Open() > 0) {
            
            if (pthread_create(&pthread_waf, NULL, thread_waf, &arg)) {
                daemon_log(LOG_ERR,"error creating thread for WAF module");
                return 0;
            }
        } else daemon_log(LOG_ERR,"WAF source is disabled");
    } 
    
        
    //remlog
    if (remlog.GetStatus() > 0) {
        
        if (!remlog.Open() > 0) {
            daemon_log(LOG_ERR,"cannot open RemLog module");
            return 0;
        }
    
        if (pthread_create(&pthread_remlog, NULL, thread_remlog, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for RemLog module");
            return 0;
        } 
    }
    
    //remstat
    if (remstat.GetStatus() > 0) {
        
        if (!remstat.Open() > 0) {
            daemon_log(LOG_ERR,"cannot open RemStat module");
            return 0;
        }
    
        if (pthread_create(&pthread_remstat, NULL, thread_remstat, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for RemStat module");
            return 0;
        } 
    }
    
    // updates
    if (updates.GetStatus() > 0) {
        
        if (!updates.Open(mode,pid)) {
            daemon_log(LOG_ERR,"cannot open Update module");
            return 0;
        }
        
        if (pthread_create(&pthread_updates, NULL, thread_updates, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for Update module");
            return 0;
        } 
    }
    
    // scanners
    if (scanners.GetStatus() > 0) {
        
        if (!scanners.Open(mode,pid)) {
            daemon_log(LOG_ERR,"cannot open Scanners module");
            return 0;
        }
        
        if (pthread_create(&pthread_scanners, NULL, thread_scanners, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for Scanners module");
            return 0;
        } 
    }
    
    //collector
    if (collr.GetStatus() > 0) {
        
        if (!collr.Open() > 0) {
            daemon_log(LOG_ERR,"cannot open Collector module");
            return 0;
        }
    
        if (pthread_create(&pthread_collr, NULL, thread_collr, &arg)) {
            daemon_log(LOG_ERR,"error creating thread for Collector module");
            return 0;
        } 
    }
    
    return 1;
}

void KillsThreads(void)
{
    //aggalerts
    if (aggalerts.GetStatus()) {
        pthread_cancel(pthread_aggalerts);
        pthread_join(pthread_aggalerts, NULL);
    }
    
    //aggnet
    if (aggnet.GetStatus()) {
        pthread_cancel(pthread_aggnet);
        pthread_join(pthread_aggnet, NULL);
    }
    
    //misc
    if (misc.GetStatus()) {
        pthread_cancel(pthread_misc);
        pthread_join(pthread_misc, NULL);
    }
    
    //aws
    if (aws.GetStatus()) {
        pthread_cancel(pthread_aws);
        pthread_join(pthread_aws, NULL);
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
    
    //crs
    if (crs.GetStatus()) {
        pthread_cancel(pthread_crs);
        pthread_join(pthread_crs, NULL);
    }
    
    //waf
    if (waf.GetStatus()) {
        pthread_cancel(pthread_waf);
        pthread_join(pthread_waf, NULL);
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
    
    // scanners
    if (scanners.GetStatus()) {
        pthread_cancel(pthread_scanners);
        pthread_join(pthread_scanners, NULL); 
    }
    
    //collector
    if (collr.GetStatus()) {
        pthread_cancel(pthread_collr);
        pthread_join(pthread_collr, NULL); 
    }
}

void cleanup() {
    
    daemon_log(LOG_INFO, "exiting...");
    daemon_retval_send(255);
    daemon_signal_done();
    daemon_pid_file_remove();
    
}

int start(pid_t pid) {
    
    int ret;
    
    if (!LoadConfig()) return 1;
    
    int startup_timer = aggalerts.GetStartupTimer();
        
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
        
        /* Wait for timeout in seconds for the return value passed from the daemon process */
        if ((ret = daemon_retval_wait(startup_timer)) < 0) {
            
            daemon_log(LOG_ERR, "could not receive return value from altprobe collector process: %s", strerror(errno));
            
            return 255;
        }

        daemon_log(ret != 0 ? LOG_ERR : LOG_INFO, "collector started with code %i", ret);
        
        return ret;

    } else { /* The daemon */
        
        int fd, quit = 0;
        fd_set fds;

        /* Close FDs */
        if (daemon_close_all(-1) < 0) {
            daemon_log(LOG_ERR, "failed to close all file descriptors: %s", strerror(errno));

            /* Send the error condition to the parent process */
            daemon_retval_send(1);
            
            cleanup();
            return 1;
        }

        /* Create the PID file */
        if (daemon_pid_file_create() < 0) {
            daemon_log(LOG_ERR, "could not create PID file (%s)", strerror(errno));
            daemon_retval_send(2);
            
            cleanup();
            return 1;
        }

        /* Initialize signal handling */
        if (daemon_signal_init(SIGINT, SIGTERM, SIGQUIT, SIGHUP, SIGUSR1, 0) < 0) {
            daemon_log(LOG_ERR, "could not register signal handlers (%s)", strerror(errno));
            daemon_retval_send(3);
            
            cleanup();
            return 1;
        }

        /*... do some further init work here */
        if (!InitThreads(1,pid)) {
            
            daemon_retval_send(4);
            
            KillsThreads();
            cleanup();
            return 1;
        }

        /* Send OK to parent process */
        daemon_retval_send(0);

        daemon_log(LOG_INFO, "collector has been successfully started");

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
        
        KillsThreads();
        cleanup();
    }
    
    return 0;
}

static void sigHandler (int signo) {
    printf ("got SIGHUP, SIGINT, SIGQUIT or SIGTERM\n");
    KillsThreads();
    
    exit (EXIT_SUCCESS);
}

int startD() {
    
    if (!LoadConfig()) return 1;
    
    pid_t pid = getpid();
    
    if (!InitThreads(2,pid)) {
            
        KillsThreads();
        return 1;
    }
    
    if (signal (SIGINT, sigHandler) == SIG_ERR) {
        fprintf (stderr, "Cannot handle SIGINT!\n");
        KillsThreads();
        exit (EXIT_FAILURE);
    }
    
    if (signal (SIGHUP, sigHandler) == SIG_ERR) {
        fprintf (stderr, "Cannot handle SIGHUP!\n");
        KillsThreads();
        exit (EXIT_FAILURE);
    }
    
    if (signal (SIGQUIT, sigHandler) == SIG_ERR) {
        fprintf (stderr, "Cannot handle SIGQUIT!\n");
        KillsThreads();
        exit (EXIT_FAILURE);
    }
    
    if (signal (SIGTERM, sigHandler) == SIG_ERR) {
        fprintf (stderr, "Cannot handle SIGTERM!\n");
        KillsThreads();
        exit (EXIT_FAILURE);
    }
    
    for (;;) {
        pause ();
        return 0;
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
                printf( "altprobe collector is already running with PID %u\n", pid);
            
            else return start(pid);
            return 0;
        }
        
        if (!strcmp(argv[1], "startd")) {
            
            if ((pid = daemon_pid_file_is_running()) >= 0)
                
                // daemon_log(LOG_ERR, "AlertFlex collector is already running with PID %u.", pid);
                printf( "altprobe collector is already running with PID %u\n", pid);
            
            else return startD();
            
            return 0;
        }
        
        if (!strcmp(argv[1], "stop")) {
             /* Kill daemon with SIGTERM */
             /* Check if the new function daemon_pid_file_kill_wait() is available, if it is, use it. */
             if ((ret = daemon_pid_file_kill_wait(SIGTERM, 5)) < 0)
                  // daemon_log(LOG_ERR, "Failed to kill AlertFlex collector: %s.", strerror(errno));
                  printf( "failed to kill altprobe collector: %s\n", strerror(errno));
             //else daemon_log(LOG_ERR, "AlertFlex collector is stopping.");
             else printf( "altprobe collector is stopping\n");
             return ret < 0 ? 1 : 0;
        }
        
        if (!strcmp(argv[1], "status")) {                        
             /* Check that the daemon is not rung twice a the same time */
             if ((pid = daemon_pid_file_is_running()) >= 0)
                  //daemon_log(LOG_ERR, "AlertFlex collector is running with PID %u.", pid);
                  printf( "altprobe collector is running, process %u\n", pid);
             //else daemon_log(LOG_ERR, "AlertFlex collector isn't running.");
             else printf( "altprobe collector isn't running\n");
             return 0;
        }
    }
    
    // daemon_log(LOG_ERR, "usage: ./altprobe {start|stop|status}");
    printf( "usage: ./altprobe {start|startd|stop|status}\n");
    
    return 0;

}





