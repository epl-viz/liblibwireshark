#ifndef LIBLIBWIRESHARK_CAPTURE_INTERNAL_H_
#define LIBLIBWIRESHARK_CAPTURE_INTERNAL_H_

#include "cfile.h"
/** handle identifying a online or offline capture */
struct ws_capture_t {
    capture_file cfile;
    epan_dissect_t *edt;
    Buffer buf;
#if 0
    struct {
        struct wtap_pkthdr phdr;
        Buffer buf;
    } seekinfo;
#endif
};

#define PROVIDE_ERRORS \
    do { \
        if (err) \
            *err = _err; \
        if (err_info) \
            *err_info = _err_info; \
        else \
            g_free(_err_info); \
    } while(0)


#endif
