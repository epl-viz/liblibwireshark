#include "config.h"
#include <stddef.h>

#include <stdio.h>
#include <capture_opts.h>
#include <capchild/capture_session.h>
#include <capchild/capture_sync.h>
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

static gboolean process_packet(capture_file *cf, epan_dissect_t *edt, gint64 offset,
        struct wtap_pkthdr *whdr, const guchar *pd,
        guint tap_flags);

static gboolean
print_packet(capture_file *cf, epan_dissect_t *edt);

static guint32 cum_bytes;
static const frame_data *ref;
static frame_data ref_frame;
static frame_data *prev_dis;
static frame_data prev_dis_frame;
static frame_data *prev_cap;
static frame_data prev_cap_frame;

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
capture_input_error_message(capture_session *cap_session _U_, char *error_msg, char *secondary_error_msg)
{
    cmdarg_err("%s", error_msg);
    cmdarg_err_cont("%s", secondary_error_msg);

    CAPTURE_CALLBACK(cap_session, input_error_message, error_msg, secondary_error_msg);
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
    if (1) {
        /* We're printing packet counts to stderr.
           Send a newline so that we move to the line after the packet count. */
        fprintf(stderr, "\n");
    }

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

    /*report_counts();*/

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
    if (1 /*do_dissection */) {
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
    }

    cap_session->state = CAPTURE_RUNNING;

    CAPTURE_OF(cap_session)->is_wtap_open = 1;
    CAPTURE_CALLBACK(cap_session, input_new_file, new_file);
    return TRUE;
}



#if 0
#ifdef HAVE_PCAP
#ifdef _WIN32
    static BOOL WINAPI
capture_cleanup(DWORD ctrltype _U_)
{
    /* CTRL_C_EVENT is sort of like SIGINT, CTRL_BREAK_EVENT is unique to
       Windows, CTRL_CLOSE_EVENT is sort of like SIGHUP, CTRL_LOGOFF_EVENT
       is also sort of like SIGHUP, and CTRL_SHUTDOWN_EVENT is sort of
       like SIGTERM at least when the machine's shutting down.

       For now, we handle them all as indications that we should clean up
       and quit, just as we handle SIGINT, SIGHUP, and SIGTERM in that
       way on UNIX.

       We must return TRUE so that no other handler - such as one that would
       terminate the process - gets called.

       XXX - for some reason, typing ^C to TShark, if you run this in
       a Cygwin console window in at least some versions of Cygwin,
       causes TShark to terminate immediately; this routine gets
       called, but the main loop doesn't get a chance to run and
       exit cleanly, at least if this is compiled with Microsoft Visual
       C++ (i.e., it's a property of the Cygwin console window or Bash;
       it happens if TShark is not built with Cygwin - for all I know,
       building it with Cygwin may make the problem go away). */

    /* tell the capture child to stop */
    sync_pipe_stop(&global_capture_session);

    /* don't stop our own loop already here, otherwise status messages and
     * cleanup wouldn't be done properly. The child will indicate the stop of
     * everything by calling capture_input_closed() later */

    return TRUE;
}
#else
    static void
capture_cleanup(int signum _U_)
{
    /* tell the capture child to stop */
    sync_pipe_stop(&global_capture_session);

    /* don't stop our own loop already here, otherwise status messages and
     * cleanup wouldn't be done properly. The child will indicate the stop of
     * everything by calling capture_input_closed() later */
}
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */
#endif

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
    } else
        ;
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
    gboolean perform_two_pass_analysis = TRUE;

    wth = wtap_open_offline(fname, type, err, &err_info, perform_two_pass_analysis);
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
    ref = NULL;
    prev_dis = NULL;
    prev_cap = NULL;

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
    puts("new packets!");
    CAPTURE_CALLBACK(cap_session, input_new_packets, to_read);
}

    void
capture_input_new_packets2(capture_session *cap_session, int to_read)
{
    gboolean      ret;
    int           err;
    gchar        *err_info;
    gint64        data_offset;
    capture_file *cf = (capture_file *)cap_session->cf;
    gboolean      filtering_tap_listeners;
    guint         tap_flags;
    gboolean print_details = TRUE;

#ifdef SIGINFO
    /*
     * Prevent a SIGINFO handler from writing to the standard error while
     * we're doing so or writing to the standard output; instead, have it
     * just set a flag telling us to print that information when we're done.
     */
    infodelay = TRUE;
#endif /* SIGINFO */

    /* Do we have any tap listeners with filters? */
    filtering_tap_listeners = FALSE;

    /* Get the union of the flags for all tap listeners. */
    tap_flags = 0;

    if (1 /*do_dissection*/) {
        gboolean create_proto_tree;
        epan_dissect_t *edt;

        if (cf->rfcode || cf->dfcode || print_details || filtering_tap_listeners ||
                (tap_flags & TL_REQUIRES_PROTO_TREE) || have_custom_cols(&cf->cinfo))
            create_proto_tree = TRUE;
        else
            create_proto_tree = FALSE;

        /* The protocol tree will be "visible", i.e., printed, only if we're
           printing packet details, which is true if we're printing stuff
           ("print_packet_info" is true) and we're in verbose mode
           ("packet_details" is true). */
        edt = epan_dissect_new(cf->epan, create_proto_tree, TRUE /*print_packet_info && print_details*/);

        while (to_read-- && cf->wth) {
            wtap_cleareof(cf->wth);
            ret = wtap_read(cf->wth, &err, &err_info, &data_offset);
            if (ret == FALSE) {
                /* read from file failed, tell the capture child to stop */
                sync_pipe_stop(cap_session);
                wtap_close(cf->wth);
                cf->wth = NULL;
            } else {
                ret = process_packet(cf, edt, data_offset, wtap_phdr(cf->wth),
                        wtap_buf_ptr(cf->wth),
                        tap_flags);
            }
            if (ret != FALSE) {
                /* packet successfully read and gone through the "Read Filter" */
                /*packet_count++;*/
            }
        }

        epan_dissect_free(edt);

    } else {
        /*
         * Dumpcap's doing all the work; we're not doing any dissection.
         * Count all the packets it wrote.
         */
        /*packet_count += to_read;*/
    }

#if 0
    if (print_packet_counts) {
        /* We're printing packet counts. */
        if (packet_count != 0) {
            fprintf(stderr, "\r%u ", packet_count);
            /* stderr could be line buffered */
            fflush(stderr);
        }
    }
#endif

#ifdef SIGINFO
    /*
     * Allow SIGINFO handlers to write.
     */
    infodelay = FALSE;

    /*
     * If a SIGINFO handler asked us to write out capture counts, do so.
     */
    if (infoprint)
        report_counts();
#endif /* SIGINFO */

    puts("==================================================");

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

    static gboolean
process_packet(capture_file *cf, epan_dissect_t *edt, gint64 offset, struct wtap_pkthdr *whdr,
        const guchar *pd, guint tap_flags)
{
    frame_data      fdata;
    column_info    *cinfo;
    gboolean        passed;

    /* Count this packet. */
    cf->count++;

    /* If we're not running a display filter and we're not printing any
       packet information, we don't need to do a dissection. This means
       that all packets can be marked as 'passed'. */
    passed = TRUE;

    frame_data_init(&fdata, cf->count, whdr, offset, cum_bytes);

    /* If we're going to print packet information, or we're going to
       run a read filter, or we're going to process taps, set up to
       do a dissection and do so. */
    if (edt) {
#if 0
        if (print_packet_info && (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
                    gbl_resolv_flags.transport_name))
            /* Grab any resolved addresses */
            host_name_lookup_process();
#endif

        /* If we're running a filter, prime the epan_dissect_t with that
           filter. */
        if (cf->dfcode)
            epan_dissect_prime_dfilter(edt, cf->dfcode);

        /*col_custom_prime_edt(edt, &cf->cinfo);*/

#if 0
        /* We only need the columns if either
           1) some tap needs the columns
           or
           2) we're printing packet info but we're *not* verbose; in verbose
           mode, we print the protocol tree, not the protocol summary.
           or
           3) there is a column mapped as an individual field */
        if ((tap_flags & TL_REQUIRES_COLUMNS) || (print_packet_info && print_summary) || output_fields_has_cols(output_fields))
            cinfo = &cf->cinfo;
        else
#endif
            cinfo = NULL;

        frame_data_set_before_dissect(&fdata, &cf->elapsed_time,
                &ref, prev_dis);
        if (ref == &fdata) {
            ref_frame = fdata;
            ref = &ref_frame;
        }

        epan_dissect_run_with_taps(edt, cf->cd_t, whdr, frame_tvbuff_new(&fdata, pd), &fdata, cinfo);

        /* Run the filter if we have it. */
        if (cf->dfcode)
            passed = dfilter_apply_edt(cf->dfcode, edt);
    }

    if (passed) {
        frame_data_set_after_dissect(&fdata, &cum_bytes);

        /* Process this packet. */
        if (1 /*print_packet_info*/) {
            /* We're printing packet information; print the information for
               this packet. */
            print_packet(cf, edt);

            /* The ANSI C standard does not appear to *require* that a line-buffered
               stream be flushed to the host environment whenever a newline is
               written, it just says that, on such a stream, characters "are
               intended to be transmitted to or from the host environment as a
               block when a new-line character is encountered".

               The Visual C++ 6.0 C implementation doesn't do what is intended;
               even if you set a stream to be line-buffered, it still doesn't
               flush the buffer at the end of every line.

               So, if the "-l" flag was specified, we flush the standard output
               at the end of a packet.  This will do the right thing if we're
               printing packet summary lines, and, as we print the entire protocol
               tree for a single packet without waiting for anything to happen,
               it should be as good as line-buffered mode if we're printing
               protocol trees.  (The whole reason for the "-l" flag in either
               tcpdump or TShark is to allow the output of a live capture to
               be piped to a program or script and to have that script see the
               information for the packet as soon as it's printed, rather than
               having to wait until a standard I/O buffer fills up. */
#if 0
            if (line_buffered)
                fflush(stdout);

            if (ferror(stdout)) {
                show_print_file_io_error(errno);
                exit(2);
            }
#endif
        }

        /* this must be set after print_packet() [bug #8160] */
        prev_dis_frame = fdata;
        prev_dis = &prev_dis_frame;
    }

    prev_cap_frame = fdata;
    prev_cap = &prev_cap_frame;

    if (edt) {
        epan_dissect_reset(edt);
        frame_data_destroy(&fdata);
    }
    return passed;
}

    static gboolean
process_packet_first_pass(capture_file *cf, epan_dissect_t *edt,
        gint64 offset, struct wtap_pkthdr *whdr,
        const guchar *pd)
{
    frame_data     fdlocal;
    guint32        framenum;
    gboolean       passed;

    /* The frame number of this packet is one more than the count of
       frames in this packet. */
    framenum = cf->count + 1;

    /* If we're not running a display filter and we're not printing any
       packet information, we don't need to do a dissection. This means
       that all packets can be marked as 'passed'. */
    passed = TRUE;

    frame_data_init(&fdlocal, framenum, whdr, offset, cum_bytes);

    /* If we're going to print packet information, or we're going to
       run a read filter, or display filter, or we're going to process taps, set up to
       do a dissection and do so. */
    if (edt) {
#if 0
        if (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
                gbl_resolv_flags.transport_name)
            /* Grab any resolved addresses */
            host_name_lookup_process();
#endif

        /* If we're running a read filter, prime the epan_dissect_t with that
           filter. */
        if (cf->rfcode)
            epan_dissect_prime_dfilter(edt, cf->rfcode);

        if (cf->dfcode)
            epan_dissect_prime_dfilter(edt, cf->dfcode);

        frame_data_set_before_dissect(&fdlocal, &cf->elapsed_time,
                &ref, prev_dis);
        if (ref == &fdlocal) {
            ref_frame = fdlocal;
            ref = &ref_frame;
        }

        epan_dissect_run(edt, cf->cd_t, whdr, frame_tvbuff_new(&fdlocal, pd), &fdlocal, NULL);

        /* Run the read filter if we have one. */
        if (cf->rfcode)
            passed = dfilter_apply_edt(cf->rfcode, edt);
    }

    if (passed) {
        frame_data_set_after_dissect(&fdlocal, &cum_bytes);
        prev_cap = prev_dis = frame_data_sequence_add(cf->frames, &fdlocal);

        /* If we're not doing dissection then there won't be any dependent frames.
         * More importantly, edt.pi.dependent_frames won't be initialized because
         * epan hasn't been initialized.
         * if we *are* doing dissection, then mark the dependent frames, but only
         * if a display filter was given and it matches this packet.
         */
        if (edt && cf->dfcode) {
            if (dfilter_apply_edt(cf->dfcode, edt)) {
                g_slist_foreach(edt->pi.dependent_frames, find_and_mark_frame_depended_upon, cf->frames);
            }
        }

        cf->count++;
    } else {
        /* if we don't add it to the frame_data_sequence, clean it up right now
         * to avoid leaks */
        frame_data_destroy(&fdlocal);
    }

    if (edt)
        epan_dissect_reset(edt);

    return passed;
}

    static gboolean
print_packet(capture_file *cf, epan_dissect_t *edt)
{

#if 0
    if (print_summary || output_fields_has_cols(output_fields)) {
        /* Just fill in the columns. */
        epan_dissect_fill_in_columns(edt, FALSE, TRUE);

        if (print_summary) {
            /* Now print them. */
            switch (output_action) {

                case WRITE_TEXT:
                    if (!print_columns(cf))
                        return FALSE;
                    break;

                case WRITE_XML:
                    write_psml_columns(edt, stdout);
                    return !ferror(stdout);
                case WRITE_FIELDS: /*No non-verbose "fields" format */
                case WRITE_JSON:
                case WRITE_EK:
                    g_assert_not_reached();
                    break;
            }
        }
    }
#endif
    if (1 /*print_details*/) {
        /* Print the information in the protocol tree. */
#if 0
        switch (output_action) {

            case WRITE_TEXT:
#endif
                /* Only initialize the fields that are actually used in proto_tree_print.
                 * This is particularly important for .range, as that's heap memory which
                 * we would otherwise have to g_free().
                 print_args.to_file = TRUE;
                 print_args.format = print_format;
                 print_args.print_summary = print_summary;
                 print_args.print_formfeed = FALSE;
                 packet_range_init(&print_args.range, &cfile);
                 */

                struct ws_dissection dissection;
                dissection.edt = edt;
                char *buf = NULL;
                ws_dissect_tostr(&dissection, &buf);
                puts(buf);
#if 0
                break;

            case WRITE_XML:
                write_pdml_proto_tree(output_fields, protocolfilter, edt, stdout);
                printf("\n");
                return !ferror(stdout);
            case WRITE_FIELDS:
                write_fields_proto_tree(output_fields, edt, &cf->cinfo, stdout);
                printf("\n");
                return !ferror(stdout);
            case WRITE_JSON:
                print_args.print_hex = print_hex;
                write_json_proto_tree(output_fields, &print_args, protocolfilter, edt, stdout);
                printf("\n");
                return !ferror(stdout);
            case WRITE_EK:
                print_args.print_hex = print_hex;
                write_ek_proto_tree(output_fields, &print_args, protocolfilter, edt, stdout);
                printf("\n");
                return !ferror(stdout);
        }
    }
    if (print_hex) {
        if (print_summary || print_details) {
            if (!print_line(print_stream, 0, ""))
                return FALSE;
        }
        if (!print_hex_data(print_stream, edt))
            return FALSE;
        if (!print_line(print_stream, 0, separator))
            return FALSE;
#endif
    }
    return TRUE;
}

#if 0
    gboolean
capture(void)
{
    gboolean          ret;
    guint             i;
    GString          *str;
#ifdef USE_TSHARK_SELECT
    fd_set            readfds;
#endif
#ifndef _WIN32
    struct sigaction  action, oldaction;
#endif
    gboolean really_quiet = FALSE;

    capture_opts_init(&global_capture_opts);
    capture_session_init(&global_capture_session, &cfile);

    /* Create new dissection section. */
    epan_free(cfile.epan);
    cfile.epan = tshark_epan_new(&cfile);

#if 0
#ifdef _WIN32
    /* Catch a CTRL+C event and, if we get it, clean up and exit. */
    SetConsoleCtrlHandler(capture_cleanup, TRUE);
#else /* _WIN32 */
    /* Catch SIGINT and SIGTERM and, if we get either of them,
       clean up and exit.  If SIGHUP isn't being ignored, catch
       it too and, if we get it, clean up and exit.

       We restart any read that was in progress, so that it doesn't
       disrupt reading from the sync pipe.  The signal handler tells
       the capture child to finish; it will report that it finished,
       or will exit abnormally, so  we'll stop reading from the sync
       pipe, pick up the exit status, and quit. */
    memset(&action, 0, sizeof(action));
    action.sa_handler = capture_cleanup;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGHUP, NULL, &oldaction);
    if (oldaction.sa_handler == SIG_DFL)
        sigaction(SIGHUP, &action, NULL);

#ifdef SIGINFO
    /* Catch SIGINFO and, if we get it and we're capturing to a file in
       quiet mode, report the number of packets we've captured.

       Again, restart any read that was in progress, so that it doesn't
       disrupt reading from the sync pipe. */
    action.sa_handler = report_counts_siginfo;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINFO, &action, NULL);
#endif /* SIGINFO */
#endif /* _WIN32 */
#endif

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

    /* the actual capture loop
     *
     * XXX - glib doesn't seem to provide any event based loop handling.
     *
     * XXX - for whatever reason,
     * calling g_main_loop_new() ends up in 100% cpu load.
     *
     * But that doesn't matter: in UNIX we can use select() to find an input
     * source with something to do.
     *
     * But that doesn't matter because we're in a CLI (that doesn't need to
     * update a GUI or something at the same time) so it's OK if we block
     * trying to read from the pipe.
     *
     * So all the stuff in USE_TSHARK_SELECT could be removed unless I'm
     * wrong (but I leave it there in case I am...).
     */

#ifdef USE_TSHARK_SELECT
    FD_ZERO(&readfds);
    FD_SET(pipe_input.source, &readfds);
#endif

    gboolean loop_running = TRUE;

    /*TRY*/
    {
        while (loop_running)
        {
#ifdef USE_TSHARK_SELECT
            ret = select(pipe_input.source+1, &readfds, NULL, NULL, NULL);

            if (ret == -1)
            {
                fprintf(stderr, "%s: %s\n", "select()", g_strerror(errno));
                return TRUE;
            } else if (ret == 1) {
#endif
                capture_input_new_packets2(&global_capture_session, 1);
                /* Call the real handler */
                if (!pipe_input.input_cb(pipe_input.source, pipe_input.user_data)) {
                    g_log(NULL, G_LOG_LEVEL_DEBUG, "input pipe closed");
                    return FALSE;
                }
#ifdef USE_TSHARK_SELECT
            }
#endif
        }
    }
#if 0
    CATCH(OutOfMemoryError) {
        fprintf(stderr,
                "Out Of Memory.\n"
                "\n"
                "Sorry, but TShark has to terminate now.\n"
                "\n"
                "More information and workarounds can be found at\n"
                "https://wiki.wireshark.org/KnownBugs/OutOfMemory\n");
        exit(1);
    }
    ENDTRY;
#endif
    return TRUE;
}
#endif

