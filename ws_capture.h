#ifndef LIBLIBWIRESHARK_WS_CAPTURE_H_
#define LIBLIBWIRESHARK_WS_CAPTURE_H_

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

enum { WS_CAPTURE_FLAG_MONITOR_MODE = 1 };

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
ws_capture_t *ws_capture_open_live(const char *interface, int flags, struct ws_capture_callback *callbacks, int *err, char **err_info);


/**
 * \param cap capture object
 * \returns file path
 *
 * \brief Fetches name associated with a capture. Might be a temporary file
 *        when doing a live capture
 */
const char *ws_capture_filename(ws_capture_t *cap);

/**
 * \param [out] head a pointer by reference
 * \returns the number of interfaces, negative error code otherwise
 *
 * \brief Populates the pointer argument with a singly linked list
 * of interfaces which can be sniffed
 */
GList *ws_capture_interface_list(int *err, char **err_info);

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

#ifdef __cplusplus
}
#endif
#endif

