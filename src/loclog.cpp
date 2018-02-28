/* 
 * File:  loclog.cpp
 * Author: Oleg Zharkov
 *
 */

#include "config.h"
#include "loclog.h"

string LocLog::log_path = "/var/log/alertflex/";
string LocLog::file_template = "alerts";
bool LocLog::state = false;

std::mutex LocLog::write_lock;

int LocLog::Open() {
    
    if (!state) {
    
        index = OpenDir(log_path);  // avoid repeated path construction below
    
        index = index + 1;
    
        stringstream new_index; 
        new_index << index;
    
        string file_name = log_path + file_template + "." + new_index.str();
    
        open_file_path = path(file_name);
    
        try {        
            ostream.open(file_name.c_str(), ios_base::app);
        } catch (std::ostream::failure e) {
            SysLog("Exception opening local log file.");
            return 0;
        }
        
        state = true;
        return 1;
    } 
    
    return 0;
}

void LocLog::Close() {
    if (state) ostream.close();
}

int LocLog::WriteLog(string msg) {
    
    if (state) {
    
        std::lock_guard<std::mutex> lock(write_lock);
    
        try { 
            long fileSize = file_size(open_file_path);
            long limitSize =  1048576*log_size;        
            if(fileSize > limitSize) {
                Close();
                Open();
            }
        
        } catch (std::ostream::failure e) {
            SysLog("Exception reopen local log file.");
            return 0;
        }
        
        try { 
            ostream << msg << endl;
        } catch (std::ostream::failure e) {
            SysLog("Exception writing to local log file.");
            return 0;
        }
    
        return 1;
    } 
    
    return Open();
}

int LocLog::GetNewIndex(int index, string fileName) {
    
    typedef boost::tokenizer<boost::char_separator<char> > tokenizer;
    tokenizer tokens(fileName, boost::char_separator<char> ("."));
    string strArray[2];
    copy(tokens.begin(), tokens.end(), strArray);
   
    int i = stoi(strArray[1]);
   
    string file_path = log_path + file_template;
   
    if (file_path.compare(strArray[0]) != 0) return -1;
    
    if (i < index) return index;
   
    return i;
}

int LocLog::OpenDir(string p) {
    
    vector<directory_entry> v; // To save the file names in a vector.
    int index = 0;

    if(is_directory(p)) {
        copy(directory_iterator(p), directory_iterator(), back_inserter(v));
                
        for ( vector<directory_entry>::const_iterator it = v.begin(); it != v.end();  ++ it ) {
            string fn = (*it).path().string();
            int res = GetNewIndex(index, fn);
            if (res == -1) continue;
            index = res;
        }
    
    } else create_directory(p);
    
    return index;
}


