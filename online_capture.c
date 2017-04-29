#include "config.h"
#include "ws_capture.h"
#include "assert.h"
#include <stdio.h>
#include "ws_dissect.h"
#include "ws_capture-internal.h"
#include "ws_capture.h"
#include "ws_dissect-internal.h"
#include "frame_tvbuff.h"
#include <capture_opts.h>
#include "capchild/capture_session.h"
#include "capchild/capture_sync.h"
#include <epan/epan.h>
#include <epan/timestamp.h>
#include <epan/epan-int.h>
#include <capture_info.h>
#include <errno.h>
#include <sys/select.h>
#include <glib.h>
/**
 * capchild deps:
 *  "append_extcap_interface_list", available in:
 *    extcap.c
 *  "capture_input_cfilter_error_message", available in:
 *    tshark.c
 *    ui/capture.c
 *  "capture_input_closed", available in:
 *    tshark.c
 *    ui/capture.c
 *  "capture_input_drops", available in:
 *    tshark.c
 *    ui/capture.c
 *  "capture_input_error_message", available in:
 *    tshark.c
 *    ui/capture.c
 *  "capture_input_new_file", available in:
 *    tshark.c
 *    ui/capture.c
 *  "capture_input_new_packets", available in:
 *    tshark.c
 *    ui/capture.c
 *  "capture_opts_log", available in:
 *    capture_opts.c
 *  "capture_opts_print_interfaces", referenced from: _main in 09-online-print.c.o, available in:
 *    capture_opts.c
 *  "extcap_get_if_dlts", available in:
 *    extcap.c
 *  "extcap_if_cleanup", available in:
 *    extcap.c
 *  "extcap_init_interfaces", available in:
 *    extcap.c
 *  "free_interface_list", referenced from: _main in 09-online-print.c.o, available in:
 *    caputils/capture-pcap-util.c
 *  "linktype_val_to_name", available in:
 *    caputils/capture-pcap-util.c
 *  "pipe_input_set_handler", available in:
 *    tshark.c
 *  "sync_pipe_errmsg_to_parent", available in:
 *    sync_pipe_write.c
**/

#define CAPTURE_OPT(opts, tshark_flag, argument, error) do { \
        gboolean _start_capture = FALSE; \
        int status = capture_opts_add_opt(&(opts), (tshark_flag), (argument), &_start_capture); \
        if (status != 0) { \
            _err = __LINE__; \
            _err_info = (error); \
            PROVIDE_ERRORS; \
            return NULL; \
        } \
    } while(0)

epan_t *
tshark_epan_new(capture_file *cf);
ws_capture_t *ws_capture_open_live(const char *interface, int flags, struct ws_capture_callback *cb, int *err, char **err_info) {
    int _err = 0;
    char *_err_info = NULL;
    /*if ((flags & WS_CAPTURE_SEQUENTIAL) == WS_CAPTURE_SEQUENTIAL) {*/

    ws_capture_t *cap = g_malloc0(sizeof *cap + sizeof *cap->dumpcap);

    pipe_input = &cap->dumpcap->pipe_input;
    cap->dumpcap->session.cf = &cap->cfile;
    cap_file_init(&cap->cfile);
    cap->cfile.frames = new_frame_data_sequence();
    ws_buffer_init(&cap->buf, 1500);
    cap->cfile.wth = NULL;

    if (cb) {
        memcpy(&cap->dumpcap->cb, cb, sizeof cap->dumpcap->cb);
    }

    capture_opts_init(&cap->dumpcap->opts);
    if (interface)
        CAPTURE_OPT(cap->dumpcap->opts, 'i', interface, "Invalid interface specified");
    if (flags & WS_CAPTURE_FLAG_MONITOR_MODE)
        CAPTURE_OPT(cap->dumpcap->opts, 'I', NULL, "Invalid option specified");

    capture_session_init(&cap->dumpcap->session, &cap->cfile);

    epan_free(cap->cfile.epan);
    cap->cfile.epan = tshark_epan_new(&cap->cfile);


    cap->dumpcap->session.state = CAPTURE_PREPARING;

    _err = sync_pipe_start(&cap->dumpcap->opts, &cap->dumpcap->session, &cap->dumpcap->info_data, NULL);

    if (!_err) {
        _err = __LINE__;
        _err_info = strdup("Capture couldn't be started by sync_pipe_start");
        g_free(cap);
        PROVIDE_ERRORS;
        return NULL;
    }


    timestamp_set_precision(TS_PREC_AUTO);

    cap->is_live      = 1;

    ws_capture_await_data(cap);

    if (cap->dumpcap->err) {
        _err = cap->dumpcap->err;
        _err_info = cap->dumpcap->err_info;

        PROVIDE_ERRORS;
        epan_free(cap->cfile.epan);
        ws_capture_close(cap);
        return NULL;
    }

    return cap;
}

void ws_capture_live_close(ws_capture_t *cap) {
    sync_pipe_stop(&cap->dumpcap->session);
}

gboolean ws_capture_await_data(ws_capture_t *cap) {
    fd_set readfds;
    FD_ZERO(&readfds);
    pipe_input_t *pipe_input = &cap->dumpcap->pipe_input;
    FD_SET(pipe_input->source, &readfds);

    int ret = select(pipe_input->source+1, &readfds, NULL, NULL, NULL);

    if (ret == -1)
    {
        fprintf(stderr, "%s: %s\n", "select()", g_strerror(errno));
        return TRUE;
    } else if (ret == 1) {
        /*capture_input_new_packets2(&global_capture_session, 1);*/

        /* Call the real handler */
        if (!pipe_input->input_cb(pipe_input->source, pipe_input->user_data)) {
            g_log(NULL, G_LOG_LEVEL_DEBUG, "input pipe closed");
            return FALSE;
        }
    }
    return TRUE;
}

const nstime_t * tshark_get_frame_ts(void *data, guint32 frame_num);

epan_t *
tshark_epan_new(capture_file *cf)
{
  epan_t *epan = epan_new();

  epan->data = cf;
  epan->get_frame_ts = tshark_get_frame_ts;
  /* TODO: This crashes in the GUI only when we are using cap_file_get_interface_name */
  epan->get_interface_name = NULL;
  epan->get_user_comment = NULL;

  return epan;
}

