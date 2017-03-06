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
#include <wsutil/filesystem.h>
#include <epan/asm_utils.h>

#include <caputils/capture_ifinfo.h>

#include <wsutil/privileges.h>
#include <wsutil/plugins.h>
#include <wiretap/wtap.h>

#include "ws_capture-internal.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static WSADATA wsaData;
#endif /* _WIN32 */

int ws_capture_init(void) {
    init_process_policies();
    wtap_init();
    /* Register all libwiretap plugin modules. */
    register_all_wiretap_modules();
    /*wtap_register_plugin_types(); [> Types known to libwiretap <]*/

#ifdef _WIN32
    /* Start windows sockets */
    WSAStartup( MAKEWORD( 1, 1 ), &wsaData );
#endif /* _WIN32 */

#ifdef WITH_ONLINE_CAPTURE
    char *progfile = init_progfile_dir(NULL, NULL);
    (void)progfile;
#endif

    return 0;
}

ws_capture_t *ws_capture_open_offline(const char *path, int flags, int *err, char **err_info) {
    assert(flags == 0);
    int _err = 0;
    char *_err_info = NULL;
    Buffer buf;
    capture_file cfile;
    cap_file_init(&cfile);
    cfile.filename = g_strdup(path);
    /*if ((flags & WS_CAPTURE_SEQUENTIAL) == WS_CAPTURE_SEQUENTIAL) {*/
    ws_buffer_init(&buf, 1500);


    cfile.wth = wtap_open_offline(cfile.filename, WTAP_TYPE_AUTO, &_err, &_err_info, TRUE);
    if (cfile.wth == NULL) {
        PROVIDE_ERRORS;
        return NULL;
    }


    cfile.count = 0;
    timestamp_set_precision(TS_PREC_AUTO);

    cfile.frames = new_frame_data_sequence();

    ws_capture_t *cap = g_malloc0(sizeof *cap);
    cap->cfile = cfile;
    cap->buf = buf;
    cap->is_wtap_open = 1;

    return cap;
}

void ws_capture_close(ws_capture_t *cap) {
    if (!cap) return;
    if (cap->cfile.frames) {
        // FIXME: crashes in some instances, for now it only leaks memory
        /*free_frame_data_sequence(cap->cfile.frames);*/
        cap->cfile.frames = NULL;
    }
    cap->cfile.frames = NULL;

    wtap_close(cap->cfile.wth);
    if (cap->is_live)
        ws_capture_live_close(cap);
    /*if (cf->is_tempfile) ws_unlink(cf->filename);*/
    g_free(cap->cfile.filename);

    wtap_phdr_cleanup(&cap->cfile.phdr);
    ws_buffer_free(&cap->cfile.buf);
    cap->cfile.wth = NULL;
    dfilter_free(cap->cfile.rfcode);
    ws_buffer_free(&cap->buf);


    g_free(cap);
}

const char *ws_capture_filename(ws_capture_t *cap)
{
    return cap->cfile.filename;
}

GList *ws_capture_interface_list(int *err, char **err_info) {
    int _err = 0;
    char *_err_info = NULL;
    /*
     * XXX capchild isn't member of libwireshark
     * I could use pcap_findalldevs to implement this though.
     * hmm...
     */
    /*GList *ifs = capture_interface_list(&_err, &_err_info, NULL);*/

    PROVIDE_ERRORS;

    /*return ifs;*/
    return NULL; // TODO: implement this
}


void ws_capture_finalize(void) {

#ifdef _WIN32
    WSACleanup();
#endif
}

