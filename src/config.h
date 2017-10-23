/* 
 * File:   config.h
 * Author: Oleg Zharkov
 *
 * Created on August 18, 2016, 2:35 PM
 */

#ifndef CONFIG_H
#define	CONFIG_H

#include "main.h"

using namespace std;

class Parameters {
public:
    string parameter;
    bool flag;
    
    Parameters() {
        this->parameter = "";
        this->flag = false;
    }
};

class ConfigYaml {
public:
    FILE *fh;
    yaml_parser_t parser;
    yaml_token_t token;

    int init;
    int state_map;
    int state_key;
    int state;

    string scalar_token;
    map <string, Parameters*> config;

    ConfigYaml(string st) {

        scalar_token = st;

        state_map = 0;
        state_key = 0;
        state = 0;

        fh = fopen(CONFIG_FILE, "r");
        if (!fh) {
            init = 0;
            return;
        }

        /* Initialize parser */
        if (!yaml_parser_initialize(&parser)) {
            init = 0;
            return;
        }

        /* Set input file */
        yaml_parser_set_input_file(&parser, fh);
        init = 1;
    }

    ~ConfigYaml() {
        /* Cleanup */
        yaml_token_delete(&token);
        yaml_parser_delete(&parser);
        fclose(fh);
    }

    int GetInitStatus() {
        return init;
    }
    
    void addKey(string key) {
        Parameters* p = new Parameters();
        config.insert(make_pair(key, p));
    }
    
    bool testKey(string key) {
        if (config.find(key) == config.end()) return false;
        return true;
    }
    
    void setParameter(string key, string p) {
        Parameters* ptr = (Parameters*) config[key];
        ptr->parameter = p;
    }
    
    void setFlag(string key, bool f) {
        Parameters* ptr = (Parameters*) config[key];
        ptr->flag = f;
    }
    
    string getParameter(string key) {
        Parameters* ptr = (Parameters*) config[key];
        return ptr->parameter;
    }
    
    bool getFlag(string key) {
        Parameters* ptr = (Parameters*) config[key];
        return ptr->flag;
    }
    
    void ParsConfig();
};

#endif	/* CONFIG_H */