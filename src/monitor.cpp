/* 
 * File:   monitor.cpp
 * Author: Oleg Zharkov
 *
 */

#include "monitor.h"

int Monitor::GetConfig() {
    
    //Read sinks config
    if(!sk.GetConfig()) return 0;
    
    if (sk.GetReportsPeriod() != 0 && sk.GetStateCtrl()) monitor_status = 1;
    
    return 1;
    
}


int  Monitor::Open() {
    
    if (!sk.Open()) return 0;
    
    m_stat_file.exceptions(ifstream::eofbit|ifstream::failbit|ifstream::badbit);
    
    ref_id = hids->fs.filter.ref_id;
    
    return 1;
}

void  Monitor::Close() {
    
    if(m_stat_file.is_open())
        m_stat_file.close();
    
    sk.Close();
    
}


int Monitor::Go(void) {
    
    struct timeval start, end;
    long seconds = 0;
            
    while(1) {    
        gettimeofday(&start, NULL);
        while (sk.GetReportsPeriod() > seconds) {
            gettimeofday(&end, NULL);
            seconds  = end.tv_sec  - start.tv_sec;
            
            usleep(GetGosleepTimer());
        }
        RoutineJob();
        seconds = 0;
    }
    
    return 1;
}

void Monitor::RoutineJob() {
    stringstream ss;
    
    if (sk.GetStateCtrl()) {
        
        GetMemoryStatus();
        
        unsigned long chids = hids->ResetEventsCounter();
        unsigned long cnids = nids->ResetEventsCounter();
        unsigned long cnet = nids->ResetNetEventsCounter();
        unsigned long clog = logs->ResetEventsCounter();               
        
        ss << "{ \"node_monitor\" : [ { \"ref_id\": \"";
        ss << ref_id;
        
        ss << "\", \"cpu\": ";
        ss << GetCpuStatus();
        
        ss << ", \"mem_free\": ";
        ss << to_string(status.total_mem - status.used_mem);
        
        ss << ", \"hids\": ";
        ss << to_string(chids);
        
        ss << ", \"nids\": ";
        ss << to_string(cnids);
        
        ss << ", \"net\": ";
        ss << to_string(cnet);
        
        ss << ", \"log\": ";
        ss << to_string(clog);
        
        ss << ", \"time_of_survey\": \"";
        ss << GetNodeTime();
        ss << "\" } ] }";
        
        report.info = ss.str();
        
        report.SetEventType(et_node_monitor);
        
        sk.SendMessage(&report);
        
        report.info.clear();
    }
}

float& Monitor::GetCpuStatus() {
    
    m_stat_file.open("/proc/stat");
    getline(m_stat_file, m_stat_line);
    m_stat_file.close();

    // skip "cpu"
    m_line_start_pos = m_stat_line.find_first_not_of(" ", 3);
    m_line_end_pos = m_stat_line.find_first_of(' ', m_line_start_pos);
    m_line_end_pos = m_stat_line.find_first_of(' ', m_line_end_pos + 1);
    m_line_end_pos = m_stat_line.find_first_of(' ', m_line_end_pos + 1);
    m_line_end_pos = m_stat_line.find_first_of(' ', m_line_end_pos + 1);
    m_iss.str(m_stat_line.substr(m_line_start_pos, m_line_end_pos - m_line_start_pos));
    m_iss >> m_next_user >> m_next_nice >> m_next_system >> m_next_idle;
    m_iss.clear();

    m_diff_user   = m_next_user - m_current_user;
    m_diff_system = m_next_system - m_current_system;
    m_diff_nice   = m_next_nice - m_current_nice;
    m_diff_idle   = m_next_idle - m_current_idle;
    m_percentage = static_cast<float>(m_diff_user + m_diff_system + m_diff_nice)/static_cast<float>(m_diff_user + m_diff_system + m_diff_nice + m_diff_idle)*100.0;

    m_current_user = m_next_user;
    m_current_system = m_next_system;
    m_current_nice = m_next_nice;
    m_current_idle = m_next_idle;

    return m_percentage;
}


void Monitor::GetMemoryStatus() {
    
    string line;
    string substr;
    size_t substr_start;
    size_t substr_len;

    unsigned int total_mem;
    unsigned int used_mem;

    ifstream memory_info("/proc/meminfo");

    while( getline( memory_info, line ) ) {
        
        substr_start = 0;
        substr_len = line.find_first_of( ':' );
        substr = line.substr( substr_start, substr_len );
        substr_start = line.find_first_not_of( " ", substr_len + 1 );
        substr_len = line.find_first_of( 'k' ) - substr_start;
    
        if( substr.compare( "MemTotal" ) == 0 ) {
            // get total memory
            total_mem = stoi( line.substr( substr_start, substr_len ) );
        } else if( substr.compare( "MemFree" ) == 0 ) {
            used_mem = total_mem - stoi( line.substr( substr_start, substr_len ) );
        } else if( substr.compare( "Buffers" ) == 0 || substr.compare( "Cached" ) == 0 ) {
            used_mem -= stoi( line.substr( substr_start, substr_len ) );
        }
    }
    
    status.used_mem = used_mem;
    status.total_mem = total_mem;
}





