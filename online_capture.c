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
#include <capchild/capture_session.h>
#include <capchild/capture_sync.h>
#include <epan/epan.h>
#include <epan/timestamp.h>
#include <epan/epan-int.h>
#include <capture_info.h>
#include <errno.h>
#include <sys/select.h>
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
    cap->is_wtap_open = 0;

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

#ifdef USE_TSHARK_SELECT
    int ret = select(pipe_input->source+1, &readfds, NULL, NULL, NULL);

    if (ret == -1)
    {
        fprintf(stderr, "%s: %s\n", "select()", g_strerror(errno));
        return TRUE;
    } else if (ret == 1) {
#endif
        /*capture_input_new_packets2(&global_capture_session, 1);*/

        /* Call the real handler */
        if (!pipe_input->input_cb(pipe_input->source, pipe_input->user_data)) {
            g_log(NULL, G_LOG_LEVEL_DEBUG, "input pipe closed");
            return FALSE;
        }
    }
    return TRUE;
}

#if 0
gboolean ws_dissect_next_online(ws_dissect_t *src, struct ws_dissection *dst, int *err, char **err_info) {
    assert(src);
    int _err = 0;
    char *_err_info = NULL;

    static guint32 cum_bytes = 0;
    static gint64 data_offset = 0;
    capture_file *cfile = &src->cap->cfile;
    struct wtap_pkthdr *whdr = wtap_phdr(cfile->wth);
    unsigned char      *buf = wtap_buf_ptr(cfile->wth);
    static frame_data ref_frame;


    // clear last dissected buffer
    if (src->edt) epan_dissect_free(src->edt);

    // dissect anew
    src->edt = epan_dissect_new(cfile->epan, TRUE, TRUE);

    if (!wtap_read(cfile->wth, &_err, &_err_info, &data_offset)) {
        /* reached end */
        PROVIDE_ERRORS;
        return FALSE;
    }
    cfile->count++;

    frame_data fdlocal;
    frame_data_init(&fdlocal, cfile->count, whdr, data_offset, cum_bytes);

    frame_data_set_before_dissect(&fdlocal, &cfile->elapsed_time, &cfile->ref, cfile->prev_dis);

    // TODO understand this code
    if (cfile->ref == &fdlocal) {
        ref_frame = fdlocal;
        cfile->ref = &ref_frame;
    }

    epan_dissect_run_with_taps(src->edt, cfile->cd_t, whdr, frame_tvbuff_new(&fdlocal, buf), &fdlocal, NULL);

    frame_data_set_after_dissect(&fdlocal, &cum_bytes);
    cfile->prev_cap = cfile->prev_dis = frame_data_sequence_add(cfile->frames, &fdlocal);

    assert(dst);
    dst->edt = src->edt;
    dst->offset = data_offset;
    dst->timestamp = fdlocal.abs_ts;

    frame_data_destroy(&fdlocal);
    return TRUE;
}
#endif

const nstime_t * tshark_get_frame_ts(void *data, guint32 frame_num);

epan_t *
tshark_epan_new(capture_file *cf)
{
  epan_t *epan = epan_new();

  epan->data = cf;
  epan->get_frame_ts = tshark_get_frame_ts;
  epan->get_interface_name = cap_file_get_interface_name;
  epan->get_user_comment = NULL;

  return epan;
}

#if 0
static gboolean 
dumpcap_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    gboolean          ret;
    guint             i;
#ifdef USE_TSHARK_SELECT
    fd_set            readfds;
#endif

    (void)wth;

    capture_opts_init(&global_capture_opts);
    capture_session_init(&global_capture_session, &cfile);

    /* Create new dissection section. */
    epan_free(cfile.epan);
    cfile.epan = tshark_epan_new(&cfile);


    global_capture_session.state = CAPTURE_PREPARING;

    /* Let the user know which interfaces were chosen. */
    for (i = 0; i < global_capture_opts.ifaces->len; i++) {
        interface_options interface_opts;

        interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, i);
        /*interface_opts.descr = get_interface_descriptive_name(interface_opts.name);*/
        global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, i);
        g_array_insert_val(global_capture_opts.ifaces, i, interface_opts);
    }
    /*str = get_iface_list_string(&global_capture_opts, IFLIST_QUOTE_IF_DESCRIPTION);*/
    /*if (really_quiet == FALSE)*/
    /*fprintf(stderr, "Capturing on %s\n", str->str);*/
    /*fflush(stderr);*/
    /*g_string_free(str, TRUE);*/

    ret = sync_pipe_start(&global_capture_opts, &global_capture_session, &global_info_data, NULL);

    if (!ret)
        return FALSE;


#ifdef USE_TSHARK_SELECT
    FD_ZERO(&readfds);
    FD_SET(pipe_input.source, &readfds);
#endif

    /*while (1)*/
    {
#ifdef USE_TSHARK_SELECT
        ret = select(pipe_input.source+1, &readfds, NULL, NULL, NULL);

        if (ret == -1)
        {
            fprintf(stderr, "%s: %s\n", "select()", g_strerror(errno));
            return TRUE;
        } else if (ret == 1)
#endif
        {
            /* Call the real handler */
            if (!pipe_input.input_cb(pipe_input.source, pipe_input.user_data)) {
                g_log(NULL, G_LOG_LEVEL_DEBUG, "input pipe closed");
                return FALSE;
            }
        }
    }
    return TRUE;
}

#endif
