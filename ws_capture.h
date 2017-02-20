#ifndef LIBLIBWIRESHARK_CAPTURE_H_
#define LIBLIBWIRESHARK_CAPTURE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

/**
 * \brief initializes capturing capability
 * \note On Windows this could do thing like loading winsock
 * \returns 0 on success, negative error code otherwise
 */
int ws_capture_init(void);

/** handle identifying an online or offline capture */
typedef struct ws_capture_t ws_capture_t;

enum { WS_CAPTURE_SEQUENTIAL = 1 };
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

/**
 * \param interface name retrieved with \sa ws_capture_list_interfaces
 * \param flags must be zero
 * \param [out] err integer to store error code to or NULL
 * \param [out] err_info pointer to store error string to or NULL. must be freed with g_free
 * \returns a handle identifying the capture
 *
 * \brief Starts sniffing on a network interface or NULL on failure
 */
ws_capture_t *ws_capture_open_live(const char *interface, int flags, int *err, char **err_info);

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

