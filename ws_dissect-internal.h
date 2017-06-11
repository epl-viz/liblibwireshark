#ifndef LIBLIBWIRESHARK_WS_DISSECT_INTERNAL_H_
#define LIBLIBWIRESHARK_WS_DISSECT_INTERNAL_H_

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
#include <WinSock2.h>
#endif

struct ws_dissect_t {
    ws_capture_t *cap;
    epan_dissect_t *edt;
};

#endif
