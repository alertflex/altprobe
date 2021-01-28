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

