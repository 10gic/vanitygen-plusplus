#ifndef VANITYGEN_PLUSPLUS_SIMPLEVANITYGEN_H
#define VANITYGEN_PLUSPLUS_SIMPLEVANITYGEN_H

#include "pattern.h"

typedef struct _vg_context_simplevanitygen_s vg_context_simplevanitygen_t;

#define simplevanitygen_max_threads 1024

/* Application-level context. parameters and global pattern store */
struct _vg_context_simplevanitygen_s {
    int vc_addrtype;
    int vc_privtype;
    const char *vc_result_file;
    int vc_numpairs;
    char *pattern;
    int match_location; // 0: any, 1: begin, 2: end
    int vc_verbose;
    enum vg_format vc_format;
    int vc_halt;
    int vc_found_num;
    unsigned long vc_start_time;
    int vc_thread_num;
    unsigned long long vc_check_count[simplevanitygen_max_threads];
};

int start_threads_simplevanitygen(vg_context_simplevanitygen_t *);

#endif //VANITYGEN_PLUSPLUS_SIMPLEVANITYGEN_H
