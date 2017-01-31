#include "ws_dissect.h"
#include <epan/epan.h>
#include <wsutil/plugins.h>
#include <epan/disabled_protos.h>
#include <epan/proto.h>
#include <epan/epan_dissect.h>
#include <epan/epan-int.h>
#include <wsutil/nstime.h>
#include <frame_tvbuff.h>
#include <assert.h>

#include "ws_capture-internal.h"


/*** Opaque handle for dissections */
struct ws_dissect_t {
    ws_capture_t *cap;
    epan_dissect_t *edt;
};

/*** Initializes dissection capability */
int ws_dissect_init(void) {
    epan_register_plugin_types(); /* Types known to libwireshark */
    scan_plugins(/*REPORT_LOAD_FAILURE*/);
    if (!epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL)) {
        /*fprintf(stderr, "Error at epan_init\n");*/
        return 2;
    }

    /*proto_disable_proto_by_name("tcp");*/
    /*set_disabled_protos_list();*/
    proto_initialize_all_prefixes();


    return 0;
}
void ws_dissect_finalize(void) {
    epan_cleanup();
}

static const nstime_t * tshark_get_frame_ts(void *data, guint32 frame_num);

/**
 * \param capture to dissect packets from
 * \returns handle for ws_dissect_* operations
 */
ws_dissect_t *ws_dissect_capture(ws_capture_t *capture) {
    epan_free(capture->cfile.epan);
    capture->cfile.epan = epan_new();
    capture->cfile.epan->data = &capture->cfile;

    capture->cfile.epan->get_frame_ts = tshark_get_frame_ts;
    
    ws_dissect_t *handle = g_malloc0(sizeof *handle);
    handle->cap = capture;
    return handle;
}

/**
 * \param [in]  src The dissector to operate on
 * \param [out] dst A pointer to a valid struct dissection
 * \returns a negative error code at failure
 *
 * \brief Dissects the next packet in order
 */
int ws_dissect_next(ws_dissect_t *src, struct ws_dissection *dst) {
    assert(src);
    int err = 0;
    char *err_info = NULL;
    static guint32 cum_bytes = 0;
    static gint64 data_offset = 0;
    capture_file *cfile = &src->cap->cfile;
    struct wtap_pkthdr *whdr = wtap_phdr(cfile->wth);
    unsigned char      *buf = wtap_buf_ptr(cfile->wth);


    // clear last dissected buffer
    if (src->edt) epan_dissect_free(src->edt);

    // dissect anew
    src->edt = epan_dissect_new(cfile->epan, TRUE, TRUE);

    if (!wtap_read(cfile->wth, &err, &err_info, &data_offset)) {
        /* reached end */
        return 0;
    }
    cfile->count++;

    frame_data fdlocal;
    frame_data_init(&fdlocal, cfile->count, whdr, data_offset, cum_bytes);

    frame_data_set_before_dissect(&fdlocal, &cfile->elapsed_time, &cfile->ref, cfile->prev_dis);

    epan_dissect_run_with_taps(src->edt, cfile->cd_t, whdr, frame_tvbuff_new(&fdlocal, buf), &fdlocal, NULL);

    frame_data_set_after_dissect(&fdlocal, &cum_bytes);
    cfile->prev_cap = cfile->prev_dis = frame_data_sequence_add(cfile->frames, &fdlocal);

    assert(dst);
    dst->tree = src->edt->tree;

    frame_data_destroy(&fdlocal);
    return 1;
}

epan_ws_dissect_t *ws_dissect_epan_get_np(ws_dissect_t *handle) {
    return handle->edt;
}

/**
 * \param dissector The dissector handle
 * \param cycle_num cycle number to seek to
 *
 * \brief Seeks to a specific poisition in the capture handle
 *        May dissect preceeding packets in order to establish cycle bondaries
 */
int ws_dissect_seek(ws_dissect_t *dissector, unsigned cycle_num);
/**
 * \param handle dissector handle
 *
 * \brief Frees the dissector. The capture file remain open though
 */
void ws_dissect_free(ws_dissect_t *handle) {
    epan_free(handle->cap->cfile.epan);
    if (handle->edt)
        epan_dissect_free(handle->edt);
    g_free(handle);
}

static const nstime_t * tshark_get_frame_ts(void *data, guint32 frame_num)
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
