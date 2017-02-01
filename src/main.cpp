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

#include "ossec.h"
#include "suricata.h"
#include "ntop.h"


Ossec ossec;
pthread_t pthread_ossec;

void* exit_thread_ossec_arg;
void exit_thread_ossec(void* arg) { ossec.Close(); }

void * thread_ossec(void *arg) {
    
    pthread_cleanup_push(exit_thread_ossec, exit_thread_ossec_arg);
    
    while (ossec.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Suricata suri;
pthread_t pthread_suri;

void* exit_thread_suri_arg;
void exit_thread_suri(void* arg) { suri.Close(); }

void * thread_suri(void *arg) {
    
    pthread_cleanup_push(exit_thread_suri, exit_thread_suri_arg);
    
    while (suri.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}

Ntop ntop;
pthread_t pthread_ntop;

void* exit_thread_ntop_arg;
void exit_thread_ntop(void* arg) { ntop.Close(); }

void * thread_ntop(void *arg) {
    
    pthread_cleanup_push(exit_thread_ntop, exit_thread_ntop_arg);
    
    while (ntop.Go()) { }
    
    pthread_cleanup_pop(1);
    pthread_exit(0);
}


int LoadConfig(void)
{
    config_t cfg;
    
    
    
    // read configuration settings
    config_init(&cfg);
    
    if (!config_read_file(&cfg, CONFIG_FILE)) {
        daemon_log(LOG_ERR,"Altprobe config file error: %s, at line:%d.\n", config_error_text(&cfg), config_error_line(&cfg));
        config_destroy(&cfg);
        
        return 0;
    }
    //ossec
    if (!ossec.GetConfig(cfg)) {
        config_destroy(&cfg);
        return 0;
    }
    
    //suri
    if (!suri.GetConfig(cfg)) {
        config_destroy(&cfg);
        return 0;
    }
    
    //ntop
    if (!ntop.GetConfig(cfg)) {
        config_destroy(&cfg);
        return 0;
    }    
    
    config_destroy(&cfg);
    return 1;
}

       
void KillsThreads(void)
{
    //ossec
    if (ossec.GetState()) {
        pthread_cancel(pthread_ossec);
        pthread_join(pthread_ossec, NULL);
    }
        
    //suricata
    if (suri.GetState()) {
        pthread_cancel(pthread_suri);
        pthread_join(pthread_suri, NULL);
    }
    
    //ntop
    if (ntop.GetState()) {
        pthread_cancel(pthread_ntop);
        pthread_join(pthread_ntop, NULL); 
    }
    
}

int InitThreads(void)
{
    int arg = 1;
    
    //ossec
    if (ossec.GetState()) {
        if (!ossec.Open()) {
            daemon_log(LOG_ERR,"Cannot open OSSEC server.");
            return 0;
        }
            
        if (pthread_create(&pthread_ossec, NULL, thread_ossec, &arg)) {
            daemon_log(LOG_ERR,"Error creating thread for OSSEC.");
            return 0;
        }
    } 
    
    //suricata
    if (suri.GetState()) {
        if (!suri.Open()) {
            daemon_log(LOG_ERR,"Cannot open Suricata server.");
            return 0;
        }
        
        if (pthread_create(&pthread_suri, NULL, thread_suri, &arg)) {
            daemon_log(LOG_ERR,"Error creating thread for Suricata.");
            return 0;
        } 
    }
    
    //ntop
    if (ntop.GetState()) {
        if (!ntop.Open()) {
            daemon_log(LOG_ERR,"Cannot open Ntop server.");
            return 0;
        }
    
        if (pthread_create(&pthread_ntop, NULL, thread_ntop, &arg)) {
            daemon_log(LOG_ERR,"Error creating thread for Ntop.");
            return 0;
        } 
    }
    
    return 1;
}


int main(int argc, char *argv[]) {
    pid_t pid;
    int ret;

    /* Reset signal handlers */
    if (daemon_reset_sigs(-1) < 0) {
        daemon_log(LOG_ERR, "Failed to reset all signal handlers: %s", strerror(errno));
        return 1;
    }

    /* Unblock signals */
    if (daemon_unblock_sigs(-1) < 0) {
        daemon_log(LOG_ERR, "Failed to unblock all signals: %s", strerror(errno));
        return 1;
    }

    /* Set indetification string for the daemon for both syslog and PID file */
    daemon_pid_file_ident = daemon_log_ident = daemon_ident_from_argv0(argv[0]);
    
    /* Check if we are called with parameters */
    if (argc == 2) {
        if (!strcmp(argv[1], "start")) {
             if ((pid = daemon_pid_file_is_running()) >= 0)
                  daemon_log(LOG_ERR, "altprobe is already running with PID file %u", pid);
             else goto start;
             return 0;
        }
        
        if (!strcmp(argv[1], "stop")) {
             /* Kill daemon with SIGTERM */
             /* Check if the new function daemon_pid_file_kill_wait() is available, if it is, use it. */
             if ((ret = daemon_pid_file_kill_wait(SIGTERM, 5)) < 0)
                  daemon_log(LOG_ERR, "failed to kill altprobe: %s", strerror(errno));
             else daemon_log(LOG_ERR, "altprobe is stopping");
             return ret < 0 ? 1 : 0;
        }
        
        if (!strcmp(argv[1], "status")) {                        
             /* Check that the daemon is not rung twice a the same time */
             if ((pid = daemon_pid_file_is_running()) >= 0)
                  daemon_log(LOG_ERR, "altprobe is running with PID file %u", pid);
             else daemon_log(LOG_ERR, "altprobe isn't running");
             return 0;
        }
    }
    
    daemon_log(LOG_ERR, "usage: ./altprobe {start|stop|status}");
    return 0;

start:    
    if (!LoadConfig()) return 1;
    
    
    /* Prepare for return value passing from the initialization procedure of the daemon process */
    if (daemon_retval_init() < 0) {
        daemon_log(LOG_ERR, "Failed to create pipe.");
        return 1;
    }

    /* Do the fork */
    if ((pid = daemon_fork()) < 0) {

        /* Exit on error */
        daemon_retval_done();
        return 1;

    } else if (pid) { /* The parent */
        int ret;

        /* Wait for 20 seconds for the return value passed from the daemon process */
        if ((ret = daemon_retval_wait(20)) < 0) {
            daemon_log(LOG_ERR, "Could not receive return value from altprobe process: %s", strerror(errno));
            return 255;
        }

        daemon_log(ret != 0 ? LOG_ERR : LOG_INFO, "altprobe returned %i as return value", ret);
        return ret;

    } else { /* The daemon */
        int fd, quit = 0;
        fd_set fds;

        /* Close FDs */
        if (daemon_close_all(-1) < 0) {
            daemon_log(LOG_ERR, "Failed to close all file descriptors: %s", strerror(errno));

            /* Send the error condition to the parent process */
            daemon_retval_send(1);
            goto finish;
        }

        /* Create the PID file */
        if (daemon_pid_file_create() < 0) {
            daemon_log(LOG_ERR, "Could not create PID file (%s)", strerror(errno));
            daemon_retval_send(2);
            goto finish;
        }

        /* Initialize signal handling */
        if (daemon_signal_init(SIGINT, SIGTERM, SIGQUIT, SIGHUP, SIGUSR1, 0) < 0) {
            daemon_log(LOG_ERR, "Could not register signal handlers (%s)", strerror(errno));
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

        daemon_log(LOG_INFO, "Altprobe sucessfully started.");

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

                daemon_log(LOG_ERR, "Select(): %s", strerror(errno));
                break;
            }

            /* Check if a signal has been recieved */
            if (FD_ISSET(fd, &fds2)) {
                int sig;

                /* Get signal */
                if ((sig = daemon_signal_next()) <= 0) {
                    daemon_log(LOG_ERR, "Daemon_signal_next() failed: %s", strerror(errno));
                    break;
                }

                /* Dispatch signal */
                switch (sig) {
                    case SIGHUP:
                    case SIGINT:
                    case SIGQUIT:
                    case SIGTERM:
                        daemon_log(LOG_WARNING, "Got SIGHUP, SIGINT, SIGQUIT or SIGTERM.");
                        quit = 1;
                        break;

                }
            }
        }

        /* Do a cleanup */
finish:
        daemon_log(LOG_INFO, "Exiting...");
        KillsThreads();
        daemon_retval_send(255);
        daemon_signal_done();
        daemon_pid_file_remove();

        return 0;
    }
}




