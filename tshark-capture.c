#include "config.h"
#include <stddef.h>

#include <stdio.h>
#include <capture_opts.h>
#include "capchild/capture_session.h"
#include "capchild/capture_sync.h"
#include <epan/epan.h>
#include <epan/epan-int.h>
#include <unistd.h>
#include <glib.h>
#include <log.h>
#include <file.h>
#include <wsutil/filesystem.h>
#include "ws_dissect.h"
#include "ws_capture.h"
#include "ws_capture-internal.h"

#include "frame_tvbuff.h"
#include <epan/epan_dissect.h>
#include <capture_info.h>

#define CAPTURE_OF(session) container_of(session->cf, ws_capture_t, cfile)

#define CAPTURE_CALLBACK(session, func, ...) do {                           \
    ws_capture_t *_ws = CAPTURE_OF(session);                                  \
    if (_ws->dumpcap->cb.func) {_ws->dumpcap->cb.func(_ws, __VA_ARGS__);}     \
} while (0)

#define TL_REQUIRES_PROTO_TREE 0

/* XXX racy */
pipe_input_t *pipe_input;

#include <cfile.h>
// FIXME we don't use dfilter
#include <epan/dfilter/dfilter.h>
#define cmdarg_err(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    putchar('\n'); \
} while (0)
#define cmdarg(...) do { \
    printf(__VA_ARGS__); \
    putchar("\n"); \
} while (0)
#define cmdarg_err_cont cmdarg_err

#undef SIGINFO


const nstime_t * tshark_get_frame_ts(void *data, guint32 frame_num);

void
capture_input_error_message(capture_session *cap_session, char *error_msg, char *secondary_error_msg)
{
    cmdarg_err("%s", error_msg);
    cmdarg_err_cont("%s", secondary_error_msg);

    CAPTURE_CALLBACK(cap_session, input_error_message, error_msg, secondary_error_msg);

    CAPTURE_OF(cap_session)->dumpcap->err = -1;
    CAPTURE_OF(cap_session)->dumpcap->err_info = g_strdup_printf("%s\n%s", error_msg, secondary_error_msg);
}

extern epan_t * tshark_epan_new(capture_file *cf);


void
capture_input_cfilter_error_message(capture_session *cap_session, guint i, char *error_message)
{
    capture_options *capture_opts = cap_session->capture_opts;
    dfilter_t         *rfcode = NULL;
    interface_options  interface_opts;

    g_assert(i < capture_opts->ifaces->len);
    interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);

    if (dfilter_compile(interface_opts.cfilter, &rfcode, NULL) && rfcode != NULL) {
        cmdarg_err(
                "Invalid capture filter \"%s\" for interface '%s'.\n"
                "\n"
                "That string looks like a valid display filter; however, it isn't a valid\n"
                "capture filter (%s).\n"
                "\n"
                "Note that display filters and capture filters don't have the same syntax,\n"
                "so you can't use most display filter expressions as capture filters.\n"
                "\n"
                "See the User's Guide for a description of the capture filter syntax.",
                interface_opts.cfilter, interface_opts.descr, error_message);
        dfilter_free(rfcode);
    } else {
        cmdarg_err(
                "Invalid capture filter \"%s\" for interface '%s'.\n"
                "\n"
                "That string isn't a valid capture filter (%s).\n"
                "See the User's Guide for a description of the capture filter syntax.",
                interface_opts.cfilter, interface_opts.descr, error_message);
    }
    CAPTURE_CALLBACK(cap_session, input_cfilter_error_message, i, error_message);
}

/* capture child detected any packet drops? */
void
capture_input_drops(capture_session *cap_session, guint32 dropped)
{
    if (dropped != 0) {
        /* We're printing packet counts to stderr.
           Send a newline so that we move to the line after the packet count. */
        fprintf(stderr, "%u packet(s) dropped\n", dropped);
    }
    CAPTURE_CALLBACK(cap_session, input_drops, dropped);
}


/*
 * Capture child closed its side of the pipe, report any error and
 * do the required cleanup.
 */
void
capture_input_closed(capture_session *cap_session, gchar *msg)
{
    capture_file *cf = (capture_file *) cap_session->cf;

    if (msg != NULL)
        fprintf(stderr, "tshark: %s\n", msg);

    if (cf != NULL && cf->wth != NULL) {
        wtap_close(cf->wth);
        if (cf->is_tempfile) {
            unlink(cf->filename);
        }
    }

    //FIXME!
    /*loop_running = FALSE;*/
    CAPTURE_CALLBACK(cap_session, input_closed, msg);
}

gboolean
capture_input_new_file(capture_session *cap_session, gchar *new_file)
{
    capture_options *capture_opts = cap_session->capture_opts;
    capture_file *cf = (capture_file *) cap_session->cf;

    gboolean is_tempfile;
    int      err;

    if (cap_session->state == CAPTURE_PREPARING) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture started.");
    }
    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "File: \"%s\"", new_file);

    g_assert(cap_session->state == CAPTURE_PREPARING || cap_session->state == CAPTURE_RUNNING);

    /* free the old filename */
    if (capture_opts->save_file != NULL) {

        /* we start a new capture file, close the old one (if we had one before) */
        if (cf->state != FILE_CLOSED) {
            if (cf->wth != NULL) {
                wtap_close(cf->wth);
                cf->wth = NULL;
            }
            cf->state = FILE_CLOSED;
        }

        g_free(capture_opts->save_file);
        is_tempfile = FALSE;

        epan_free(cf->epan);
        cf->epan = epan_new();
        cf->epan->data = cf;
        cf->epan->get_frame_ts = tshark_get_frame_ts;
        cf->epan->get_interface_name = cap_file_get_interface_name;
        cf->epan->get_user_comment = NULL;
    } else {
        /* we didn't had a save_file before, must be a tempfile */
        is_tempfile = TRUE;
    }

    /* save the new filename */
    capture_opts->save_file = g_strdup(new_file);

    /* if we are in real-time mode, open the new file now */
    /* this is probably unecessary, but better safe than sorry */
    ((capture_file *)cap_session->cf)->open_type = WTAP_TYPE_AUTO;
    /* Attempt to open the capture file and set up to read from it. */
    switch(cf_open((capture_file *)cap_session->cf, capture_opts->save_file, WTAP_TYPE_AUTO, is_tempfile, &err)) {
        case CF_OK:
            break;
        case CF_ERROR:
            /* Don't unlink (delete) the save file - leave it around,
               for debugging purposes. */
            g_free(capture_opts->save_file);
            capture_opts->save_file = NULL;
            return FALSE;
    }

    cap_session->state = CAPTURE_RUNNING;

    CAPTURE_CALLBACK(cap_session, input_new_file, new_file);

    CAPTURE_OF(cap_session)->dumpcap->err = 0;
    CAPTURE_OF(cap_session)->dumpcap->err_info = NULL;
    return TRUE;
}



static const char *
cf_open_error_message(int err, gchar *err_info, gboolean for_writing,
        int file_type)
{
    const char *errmsg = "";
    static char errmsg_errno[1024+1];

    if (err < 0) {
        /* Wiretap error. */
        switch (err) {

            case WTAP_ERR_NOT_REGULAR_FILE:
                errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
                break;

            case WTAP_ERR_RANDOM_OPEN_PIPE:
                /* Seen only when opening a capture file for reading. */
                errmsg = "The file \"%s\" is a pipe or FIFO; TShark can't read pipe or FIFO files in two-pass mode.";
                break;

            case WTAP_ERR_FILE_UNKNOWN_FORMAT:
                /* Seen only when opening a capture file for reading. */
                errmsg = "The file \"%s\" isn't a capture file in a format TShark understands.";
                break;

            case WTAP_ERR_UNSUPPORTED:
                /* Seen only when opening a capture file for reading. */
                g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                        "The file \"%%s\" contains record data that TShark doesn't support.\n"
                        "(%s)",
                        err_info != NULL ? err_info : "no information supplied");
                g_free(err_info);
                errmsg = errmsg_errno;
                break;

            case WTAP_ERR_CANT_WRITE_TO_PIPE:
                /* Seen only when opening a capture file for writing. */
                g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                        "The file \"%%s\" is a pipe, and \"%s\" capture files can't be "
                        "written to a pipe.", wtap_file_type_subtype_short_string(file_type));
                errmsg = errmsg_errno;
                break;

            case WTAP_ERR_UNWRITABLE_FILE_TYPE:
                /* Seen only when opening a capture file for writing. */
                errmsg = "TShark doesn't support writing capture files in that format.";
                break;

            case WTAP_ERR_UNWRITABLE_ENCAP:
                /* Seen only when opening a capture file for writing. */
                g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                        "TShark can't save this capture as a \"%s\" file.",
                        wtap_file_type_subtype_short_string(file_type));
                errmsg = errmsg_errno;
                break;

            case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
                if (for_writing) {
                    g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                            "TShark can't save this capture as a \"%s\" file.",
                            wtap_file_type_subtype_short_string(file_type));
                    errmsg = errmsg_errno;
                } else
                    errmsg = "The file \"%s\" is a capture for a network type that TShark doesn't support.";
                break;

            case WTAP_ERR_BAD_FILE:
                /* Seen only when opening a capture file for reading. */
                g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                        "The file \"%%s\" appears to be damaged or corrupt.\n"
                        "(%s)",
                        err_info != NULL ? err_info : "no information supplied");
                g_free(err_info);
                errmsg = errmsg_errno;
                break;

            case WTAP_ERR_CANT_OPEN:
                if (for_writing)
                    errmsg = "The file \"%s\" could not be created for some unknown reason.";
                else
                    errmsg = "The file \"%s\" could not be opened for some unknown reason.";
                break;

            case WTAP_ERR_SHORT_READ:
                errmsg = "The file \"%s\" appears to have been cut short"
                    " in the middle of a packet or other data.";
                break;

            case WTAP_ERR_SHORT_WRITE:
                errmsg = "A full header couldn't be written to the file \"%s\".";
                break;

            case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
                errmsg = "This file type cannot be written as a compressed file.";
                break;

            case WTAP_ERR_DECOMPRESS:
                /* Seen only when opening a capture file for reading. */
                g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                        "The compressed file \"%%s\" appears to be damaged or corrupt.\n"
                        "(%s)",
                        err_info != NULL ? err_info : "no information supplied");
                g_free(err_info);
                errmsg = errmsg_errno;
                break;

            default:
                g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                        "The file \"%%s\" could not be %s: %s.",
                        for_writing ? "created" : "opened",
                        wtap_strerror(err));
                errmsg = errmsg_errno;
                break;
        }
    } else {}

    //FIXME
    /*errmsg = file_open_error_message(err, for_writing);*/
    return errmsg;
}

cf_status_t
cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
    wtap  *wth;
    gchar *err_info;
    char   err_msg[2048+1];

    wth = wtap_open_offline(fname, type, err, &err_info, TRUE);
    if (wth == NULL)
        goto fail;

    /* The open succeeded.  Fill in the information for this file. */

    /* Create new epan session for dissection. */
    epan_free(cf->epan);
    cf->epan = tshark_epan_new(cf);

    cf->wth = wth;
    cf->f_datalen = 0; /* not used, but set it anyway */

    /* Set the file name because we need it to set the follow stream filter.
       XXX - is that still true?  We need it for other reasons, though,
       in any case. */
    cf->filename = g_strdup(fname);

    /* Indicate whether it's a permanent or temporary file. */
    cf->is_tempfile = is_tempfile;

    /* No user changes yet. */
    cf->unsaved_changes = FALSE;

    cf->cd_t      = wtap_file_type_subtype(cf->wth);
    cf->open_type = type;
    cf->count     = 0;
    cf->drops_known = FALSE;
    cf->drops     = 0;
    cf->snap      = wtap_snapshot_length(cf->wth);
    if (cf->snap == 0) {
        /* Snapshot length not known. */
        cf->has_snap = FALSE;
        cf->snap = WTAP_MAX_PACKET_SIZE;
    } else
        cf->has_snap = TRUE;
    nstime_set_zero(&cf->elapsed_time);

    cf->state = FILE_READ_IN_PROGRESS;

#if 0
    wtap_set_cb_new_ipv4(cf->wth, add_ipv4_name);
    wtap_set_cb_new_ipv6(cf->wth, (wtap_new_ipv6_callback_t) add_ipv6_name);
#endif

    return CF_OK;

fail:
    g_snprintf(err_msg, sizeof err_msg,
            cf_open_error_message(*err, err_info, FALSE, cf->cd_t), fname);
    cmdarg_err("%s", err_msg);
    return CF_ERROR;
}

void
capture_input_new_packets(capture_session *cap_session, int to_read)
{
    CAPTURE_CALLBACK(cap_session, input_new_packets, to_read);
}

void
pipe_input_set_handler(gint source, gpointer user_data, ws_process_id *child_process, pipe_input_cb_t input_cb)
{

    pipe_input->source         = source;
    pipe_input->child_process  = child_process;
    pipe_input->user_data      = user_data;
    pipe_input->input_cb       = input_cb;

}

