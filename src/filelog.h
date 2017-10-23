/* 
 * File:  filelog.h
 * Author: Oleg Zharkov
 *
 */

#ifndef FILELOG_H
#define	FILELOG_H

#include <fstream>  
#include <iostream>
#include <sstream>
#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>
#include "cobject.h"

using namespace std;
using namespace boost::filesystem;

class FileLog : public CollectorObject {
public:
    static string log_path;
    static string file_template;
    
    int index;
    int counter;
    path open_file_path;
    ofstream ostream;
    
    FileLog () {
        index = 0;
        counter = 0;
    }
    
    int Open();
    void Close();
    int WriteLog(string msg);
        
    int GetNewIndex(int index, string fileName);
    int OpenDir(string p);
    
};

extern boost::lockfree::spsc_queue<string> q_log;

#endif	/* FILELOG_H */

