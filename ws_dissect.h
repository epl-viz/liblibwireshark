#ifndef LIBLIBWIRESHARK_ws_dissect_H_
#define LIBLIBWIRESHARK_ws_dissect_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "ws_capture.h"

/*** Opaque handle for dissections */
typedef struct ws_dissect_t ws_dissect_t;

/*** Initializes dissection capability */
int ws_dissect_init(void);

/*** cleans up dissection capability */
void ws_dissect_finalize(void);

/**
 * \param capture to dissect packets from
 * \returns handle for ws_dissect_* operations
 */
ws_dissect_t *ws_dissect_capture(ws_capture_t *capture);

typedef struct _proto_node proto_tree;

struct ws_dissection {
    /** Cycle number */
    int cycle_num;
    
    /** profiles in use for this packet */
    struct profile_vec *profiles;

    /** Wireshark protocol tree */
    proto_tree *tree;


    /** A buffer containing the packet */
    unsigned char *packet;
};

typedef struct epan_dissect epan_ws_dissect_t;
/**
 * \param [in]  handle The dissector to operate on
 * \returns the epan_ws_dissect_t of the last dissected packet
 *
 * \note Direct operation on the epan_ws_dissect_t may not be portable
 * \brief provides the underlying epan_ws_dissect_t
 */
epan_ws_dissect_t *ws_dissect_epan_get_np(ws_dissect_t *handle);

/**
 * \param [in]  src The dissector to operate on
 * \param [out] dst A pointer to a valid struct dissection
 * \returns a negative error code at failure
 *
 * \brief Dissects the next packet in order
 */
int ws_dissect_next(ws_dissect_t *src, struct ws_dissection *dst);

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
void ws_dissect_free(ws_dissect_t *handle);



#ifdef __cplusplus
}
#endif
#endif

