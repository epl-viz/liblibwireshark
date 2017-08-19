#ifndef LIBLIBWIRESHARK_WS_CAPTURE_H_
#define LIBLIBWIRESHARK_WS_CAPTURE_H_

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
#include <WinSock2.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include <stdint.h>

/**
 * \brief initializes capturing capability
 * \note On Windows this could do thing like loading winsock
 * \returns 0 on success, negative error code otherwise
 */
int ws_capture_init(void);

/** handle identifying an online or offline capture */
typedef struct ws_capture_t ws_capture_t;

enum { WS_CAPTURE_SEQUENTIAL = 1 };

/* callbacks that can be registered for when doing a live capture */
struct ws_capture_callback {
    /** cfilter errors **/
    void (*input_cfilter_error_message)(ws_capture_t *cap, unsigned i, char *error_msg);
    /** A capture was closed **/
    void (*input_closed)(ws_capture_t *cap, char *error_msg);
    /** Frames dropped **/
    void (*input_drops) (ws_capture_t *cap, uint32_t dropped);
    /** Error messages from the dumpcap **/
    void (*input_error_message)(ws_capture_t *cap_session, char *error_msg, char *secondary_error_msg);
    /** New file openend **/
    void (*input_new_file)(ws_capture_t *cap, char *new_file);
    /** Got a packet **/
    void (*input_new_packets)(ws_capture_t *cap_session, int to_read);
};

/**
 * \param path to file to open
 * \param flags must be zero
 * \param [out] err integer to store error code to or NULL
 * \param [out] err_info pointer to store error string to or NULL. must be freed with g_free
 * \returns a handle identifying the capture or NULL on failure
 *
 * \brief Opens a packet capture file (*.pcap)
 */
ws_capture_t *ws_capture_open_offline(const char *path, int flags, int *err, char **err_info);

enum {
    WS_CAPTURE_FLAG_MONITOR_MODE = 1,
    WS_CAPTURE_TSTAMP_HOST = 2, WS_CAPTURE_TSTAMP_HOST_LOWPREC = 4, WS_CAPTURE_TSTAMP_HOST_HIPREC = 8,
    WS_CAPTURE_TSTAMP_ADAPTER = 16, WS_CAPTURE_TSTAMP_ADAPTER_UNSYNCED = 32
};

#define WS_CAPTURE_TSTAMP_BITMASK (WS_CAPTURE_TSTAMP_HOST | WS_CAPTURE_TSTAMP_HOST_LOWPREC | WS_CAPTURE_TSTAMP_HOST_HIPREC | \
    WS_CAPTURE_TSTAMP_ADAPTER | WS_CAPTURE_TSTAMP_ADAPTER_UNSYNCED )

/**
 * \param interface name retrieved with \sa ws_capture_list_interfaces
 * \param flags must be zero
 * \param callbacks Callbacks for events relating to the live capture. May be NULL
 * \param [out] err integer to store error code to or NULL
 * \param [out] err_info pointer to store error string to or NULL. must be freed with g_free
 * \returns a handle identifying the capture
 *
 * \brief Starts sniffing on a network interface or NULL on failure
 */
ws_capture_t *ws_capture_open_live(const char *interface_str, int flags, struct ws_capture_callback *callbacks, int *err, char **err_info);


/**
 * \param cap capture object
 * \returns file path
 *
 * \brief Fetches name associated with a capture. Might be a temporary file
 *        when doing a live capture
 */
const char *ws_capture_filename(ws_capture_t *cap);

/**
 * \param cap capture object
 * \returns the current size of the capture files
 *
 * \brief Returns the size of the capture files
 */
uint64_t ws_capture_file_size(ws_capture_t *cap);

/**
 * \param cap capture object
 * \returns approximate location inside the file
 *
 * \NOTE Use this when dealing with gzipped files
 */
uint64_t ws_capture_read_so_far(ws_capture_t *cap);

/**
 * \param capture valid \sa ws_capture_t instance
 *
 * \brief closes capture
 */
void ws_capture_close(ws_capture_t *capture);

/**
 * \brief free "static" capture helper data
 */
void ws_capture_finalize(void);


/**
 * \brief Set Timestamping method. e.g. "host" for default
 *        or "adapter_unsynced" for hardware timestamps
 * \see PCAP_SET_TSTAMP_TYPE(3PCAP)
 */
void ws_capture_set_tstamp_type(const char *type);

#ifdef __cplusplus
}
#endif
#endif

