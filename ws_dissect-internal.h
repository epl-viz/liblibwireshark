#ifndef LIBLIBWIRESHARK_WS_DISSECT_INTERNAL_H_
#define LIBLIBWIRESHARK_WS_DISSECT_INTERNAL_H_

struct ws_dissect_t {
    ws_capture_t *cap;
    epan_dissect_t *edt;
};

#endif
