/* 
 * File:  loclog.h
 * Author: Oleg Zharkov
 *
 */

#ifndef LOCLOG_H
#define	LOCLOG_H

#include <fstream>  
#include <iostream>
#include <sstream>
#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>
#include <mutex>
#include "cobject.h"

using namespace boost::filesystem;

class LocLog : public CollectorObject {
public:
    static string file_template;
    static std::mutex write_lock;
    
    static bool state;
    
    int index;
    int counter;
    path open_file_path;
    std::ofstream ostream;
    
    LocLog () {
        index = 0;
        counter = 0;
    }
    
    int Open();
    void Close();
    
    bool GetState() { return state; }
    void SetState(bool s) { state = s; }
    
    int WriteLog(string msg);
        
    int GetNewIndex(int index, string fileName);
    int OpenDir(string p);
    
};

#endif	/* LOCLOG_H */

