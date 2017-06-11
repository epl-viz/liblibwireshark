#ifndef LIBLIBWIRESHARK_CAPTURE_INTERNAL_H_
#define LIBLIBWIRESHARK_CAPTURE_INTERNAL_H_

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
#include <WinSock2.h>
#endif

#include "cfile.h"
#include "ws_capture.h"
#include "capchild/capture_session.h"
#include <capture_info.h>
#include <glib.h>

typedef struct pipe_input_tag pipe_input_t;
extern pipe_input_t *pipe_input;
typedef gboolean (*pipe_input_cb_t) (gint source, gpointer user_data);

/** handle identifying an online or offline capture */
struct ws_capture_t {
    /* XXX cfile *MUST* be first element. don't move! XXX */
    capture_file cfile;
    epan_dissect_t *edt;
    Buffer buf;
#if 0
    struct {
        struct wtap_pkthdr phdr;
        Buffer buf;
    } seekinfo;
#endif
    unsigned is_live           :1;
    unsigned is_running        :1;
    struct {
        int err;
        char *err_info;

        capture_options opts;
        capture_session session;
        info_data_t info_data;
        struct ws_capture_callback cb;

        struct pipe_input_tag {
            gint             source;
            gpointer         user_data;
            ws_process_id   *child_process;
            pipe_input_cb_t  input_cb;
            guint            pipe_input_id;
        } pipe_input;
    } dumpcap[];
};



gboolean ws_capture_await_data(ws_capture_t *);
void ws_capture_live_close(ws_capture_t *cap);

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
