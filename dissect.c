#include "ws_dissect.h"
#include <epan/epan.h>
#include <wsutil/plugins.h>
#include <epan/disabled_protos.h>
#include <epan/proto.h>
#include <epan/epan_dissect.h>
#include <epan/epan-int.h>
#include <wsutil/nstime.h>
#include <wsutil/privileges.h>
#include <frame_tvbuff.h>
#include <assert.h>
#include <stdio.h>

#include <glib.h>

#include "ws_capture-internal.h"
#include "ws_dissect-internal.h"

#include "ws_dissect.h"

void ws_dissect_proto_disable(const char *string) {
    proto_disable_proto_by_name(string);
}

static gboolean dissect_initialized = FALSE;

gboolean ws_dissect_plugin_dir(const char *dir) {
    if (dissect_initialized)
        return FALSE;
    init_process_policies();
    if (started_with_special_privs() ||  running_with_special_privs())
        return FALSE;

    return g_setenv("WIRESHARK_PLUGIN_DIR", dir, FALSE);
}

int ws_dissect_init(void) {
    epan_register_plugin_types(); /* Types known to libwireshark */
    scan_plugins(/*REPORT_LOAD_FAILURE*/);
    if (!epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL)) {
        /*fprintf(stderr, "Error at epan_init\n");*/
        return 2;
    }

    /*set_disabled_protos_list();*/
    // TODO: this one here closes stdin for whatever reason, y tho?
    proto_initialize_all_prefixes();
    //FIXME: do this properly
#if _WIN32
#else
    freopen("/dev/tty", "r", stdin);
#endif
    
    
    
    dissect_initialized = TRUE;
    return 0;
}
void ws_dissect_finalize(void) {
    epan_cleanup();
    dissect_initialized = FALSE;
}

epan_t *tshark_epan_new(capture_file *cf);

ws_dissect_t *ws_dissect_capture(ws_capture_t *capture) {
    epan_free(capture->cfile.epan);
    capture->cfile.epan = tshark_epan_new(&capture->cfile);
    ws_dissect_t *handle = g_malloc0(sizeof *handle);
    handle->cap = capture;
    return handle;
}

ws_capture_t *ws_dissect_get_capture(ws_dissect_t *handle) {
    return handle->cap;
}

gboolean ws_dissect_next(ws_dissect_t *src, struct ws_dissection *dst, int *err, char **err_info) {
    assert(src);
    int _err = 0;
    char *_err_info = NULL;

    static guint32 cum_bytes = 0;
    static gint64 data_offset = 0;
    capture_file *cfile = &src->cap->cfile;
    static frame_data ref_frame;

    if (src->cap->is_live /* && !NON_BLOCKING */) {
        ws_capture_await_data(src->cap);
        assert(cfile->wth);
        wtap_cleareof(cfile->wth);
    }
    if (!src->cap->is_wtap_open) {
        _err = -1;
        _err_info = g_strdup("WTAP file not open yet");
        PROVIDE_ERRORS;
        return FALSE;
    }

    struct wtap_pkthdr *whdr = wtap_phdr(cfile->wth);
    unsigned char      *buf = wtap_buf_ptr(cfile->wth);

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

gboolean ws_dissect_seek(ws_dissect_t *src, struct ws_dissection *dst, int64_t data_offset, int *err, char **err_info) {
    int _err = 0;
    char *_err_info = NULL;

    static guint32 cum_bytes = 0;
    capture_file *cfile = &src->cap->cfile;
    Buffer *buf = &src->cap->buf;
    epan_dissect_t *edt = NULL;
    struct wtap_pkthdr phdr;
    static frame_data ref_frame;
    wtap_phdr_init(&phdr);

    src->edt = NULL; // XXX remove dependency on src->edt
    edt = epan_dissect_new(cfile->epan, TRUE, TRUE);

    if (!wtap_seek_read(cfile->wth, data_offset, &phdr, buf, &_err, &_err_info)) {
        PROVIDE_ERRORS;
        return FALSE;
    }

    cfile->count++;

    frame_data fdlocal;
    frame_data_init(&fdlocal, cfile->count, &phdr, data_offset, cum_bytes);

    frame_data_set_before_dissect(&fdlocal, &cfile->elapsed_time, &cfile->ref, cfile->prev_dis);

    if (cfile->ref == &fdlocal) {
        ref_frame = fdlocal;
        cfile->ref = &ref_frame;
    }

    epan_dissect_run_with_taps(edt, cfile->cd_t, &phdr, frame_tvbuff_new_buffer(&fdlocal, buf), &fdlocal, NULL);

    frame_data_set_after_dissect(&fdlocal, &cum_bytes);
    cfile->prev_cap = cfile->prev_dis = frame_data_sequence_add(cfile->frames, &fdlocal);

    assert(dst);
    dst->edt = edt;
    dst->offset = data_offset;
    dst->timestamp = fdlocal.abs_ts;

    frame_data_destroy(&fdlocal);
    return TRUE;
}
char *ws_dissect_tostr(struct ws_dissection *dissection, char **buf) {
    assert(buf);
    assert(*buf == NULL);
    print_args_t    print_args   = {0};
    GString *gstr = g_string_new(NULL);
    print_stream_t *print_stream = ws_dissect_print_stream_gstring_new(gstr);

    print_args.print_hex         = FALSE;
    print_args.print_dissections = print_dissections_expanded;

    proto_tree_print(&print_args, dissection->edt, NULL, print_stream);

    *buf = g_string_free(gstr, FALSE);

    destroy_print_stream(print_stream);
    return *buf;
}

void ws_dissect_free(ws_dissect_t *handle) {
    epan_free(handle->cap->cfile.epan);
    if (handle->edt)
        epan_dissect_free(handle->edt);
    g_free(handle);
}

char *ws_nstime_tostr(char iso8601[restrict static WS_ISO8601_LEN], unsigned precision, const nstime_t * restrict nst) {
    struct tm tm;
    if (!gmtime_r(&nst->secs, &tm))
        return memcpy(iso8601, "Error: Year overflow", sizeof "Error: Year overflow");

    tm.tm_year %= 10*1000*1000;
    char *frac = iso8601 + strftime(iso8601, sizeof "1970-01-01T23:59:59.", "%Y-%m-%dT%H:%M:%SZ", &tm);

    if (precision) {
        unsigned long nsecs = nst->nsecs;
        for (int i = precision; i < 9; i++) nsecs /= 10;
        char *spaces = frac + sprintf(frac - 1, ".%-*luZ", precision, nsecs) - 3;
        if (spaces > frac) while (*spaces == ' ') *spaces-- = '0';
    }

    return iso8601;
}


const nstime_t * tshark_get_frame_ts(void *data, guint32 frame_num)
{
    capture_file *cf = (capture_file *) data;

    if (cf->ref && cf->ref->num == frame_num)
        return &(cf->ref->abs_ts);

    if (cf->prev_dis && cf->prev_dis->num == frame_num)
        return &(cf->prev_dis->abs_ts);

    if (cf->prev_cap && cf->prev_cap->num == frame_num)
        return &(cf->prev_cap->abs_ts);

    if (cf->frames) {
        frame_data *fd = frame_data_sequence_find(cf->frames, frame_num);

        return (fd) ? &fd->abs_ts : NULL;
    }

    return NULL;
}

