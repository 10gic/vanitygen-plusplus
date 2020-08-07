#ifndef VANITYGEN_PLUSPLUS_ED25519_H
#define VANITYGEN_PLUSPLUS_ED25519_H

typedef struct _vg_context_ed25519_s vg_context_ed25519_t;

#define ed25519_max_threads 1024

/* Application-level context. parameters and global pattern store */
struct _vg_context_ed25519_s {
    int			vc_addrtype;
    int			vc_privtype;
    const char  *vc_result_file;
    int         vc_numpairs;
    char        *pattern;
    int         match_location; // 0: any, 1: begin, 2: end
    int			vc_verbose;
    int			vc_halt;
    int         vc_found_num;
    unsigned long vc_start_time;
    int               vc_thread_num;
    unsigned long long vc_check_count[ed25519_max_threads];
};

int start_threads_ed25519(vg_context_ed25519_t * vc_ed25519);

#endif //VANITYGEN_PLUSPLUS_ED25519_H
