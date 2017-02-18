#include "ws_capture.h"
#include <stddef.h>
#include <assert.h>
#include <epan/epan.h>
#include <epan/print.h>
#include <epan/timestamp.h>
#include <epan/epan-int.h>
#include <epan/epan_dissect.h>
#include <epan/disabled_protos.h>
#include <epan/proto.h>
#include <epan/ftypes/ftypes.h>
#include <epan/asm_utils.h>
#include <wsutil/privileges.h>
#include <wsutil/plugins.h>
#include <wiretap/wtap.h>

#include "ws_capture-internal.h"

#if 0 // error: ‘tshark_get_frame_ts’ defined but not used [-Werror=unused-function]
static const nstime_t * tshark_get_frame_ts(void *data, guint32 frame_num);
#endif

int ws_capture_init(void) {
	init_process_policies();
    wtap_init();
    /* Register all libwiretap plugin modules. */
    register_all_wiretap_modules();
    /*wtap_register_plugin_types(); [> Types known to libwiretap <]*/


    return 0;
}

/**
 * \param path to file to open
 * \param flags must be zero
 * \returns a handle identifying the capture or NULL on failure
 *
 * \brief Opens a packet capture file (*.pcap)
 */
ws_capture_t *ws_capture_open_offline(const char *path, int flags) {
    assert(flags == 0);
    int err = 0;
    char *err_info = NULL;
    Buffer buf;
    capture_file cfile;
    cap_file_init(&cfile);
    cfile.filename = g_strdup(path);
    /*if ((flags & WS_CAPTURE_SEQUENTIAL) == WS_CAPTURE_SEQUENTIAL) {*/
    ws_buffer_init(&buf, 1500);


    cfile.wth = wtap_open_offline(cfile.filename, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
    if (cfile.wth == NULL) {
        return NULL;
    }

    cfile.count = 0;
    timestamp_set_precision(TS_PREC_AUTO);

    cfile.frames = new_frame_data_sequence();

    ws_capture_t *cap = g_malloc(sizeof *cap);
    cap->cfile = cfile;
    cap->buf = buf;

    return cap;
}

void ws_capture_close(ws_capture_t *cap) {
    if (!cap) return;
//     free_frame_data_sequence(cap->cfile.frames); // FIXME: leaks memory
    cap->cfile.frames = NULL;

    wtap_close(cap->cfile.wth);
    cap->cfile.wth = NULL;
    ws_buffer_free(&cap->buf);
    g_free(cap->cfile.filename);


    g_free(cap);
}

void ws_capture_finalize(void) {
}

#if 0 // error: ‘tshark_get_frame_ts’ defined but not used [-Werror=unused-function]
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
#endif
