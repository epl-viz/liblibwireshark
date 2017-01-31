#ifndef LIBLIBWIRESHARK_CAPTURE_H_
#define LIBLIBWIRESHARK_CAPTURE_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief initializes capturing capability
 * \note On Windows this would do thing like loading winsock
 * \returns 0 on success, negative error code otherwise
 */
int ws_capture_init(void);

/** handle identifying a online or offline capture */
typedef struct ws_capture_t ws_capture_t;

/**
 * \param path to file to open
 * \param flags must be zero
 * \returns a handle identifying the capture or NULL on failure
 *
 * \brief Opens a packet capture file (*.pcap)
 */
ws_capture_t *ws_capture_open_offline(const char *path, int flags);

/**
 * \param interface name retrieved with \sa capture_list_interfaces
 * \param flags must be zero
 * \returns a handle identifying the capture
 *
 * \brief Starts sniffing on a network interface or NULL on failure
 */
ws_capture_t *ws_capture_open_live(const char *interface, int flags);

/*** container for information about an interface */
struct ws_capture_interface {
    /** A pointer to the next entry */
    struct ws_capture_interface *next;
    /** the interface name as a string, e.g. eth0 */
    const char *interface;
    /** a description of the interface */
    const char *description;

    struct ws_capture_addr{
        /** a pointer to the next entry */
        struct ws_capture_addr *next;
        /** The interface's address */
        struct sockaddr *addr;
        /** The netmask of the interface */
        struct sockaddr *netmask;
        /** The broadcast address of the interface */
        struct sockaddr *broadcast_addr;
        /** The destination address if applicable */
        struct sockaddr *dst_addr;
    } addrs;

    struct {
        /** is it a loopback interface? */
        unsigned loopback :1;
    } flags;
};
/**
 * \param [out] head a pointer by reference
 * \returns the number of interfaces, negative error code otherwise
 *
 * \brief Populates the pointer argument with a singly linked list
 * of interfaces which can be sniffed
 */
int ws_capture_list_interfaces(struct ws_capture_interface **head);

/**
 * \param [in] inteface pointer acquired by \sa capture_list_interfaces
 * 
 * \brief free the space utilized by the \sa struct capture_interface list
 */
void ws_capture_free_interfaces(struct ws_capture_interface *interface);

/**
 * \param capture a valid \sa capture_t instance
 * \returns string to error or NULL
 *
 * \brief returns string representation of last error, NULL otherwise
 */
const char *ws_capture_error(ws_capture_t *capture);

/**
 * \param capture valid \sa capture_t instance
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

