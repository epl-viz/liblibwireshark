#ifndef LIBLIBWIRESHARK_ws_dissect_H_
#define LIBLIBWIRESHARK_ws_dissect_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "ws_capture.h"
#include <stdint.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/print.h>
#include <glib.h>
#include <time.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#define gmtime_r(ptime,ptm) (gmtime_s((ptm),(ptime)), (ptm))
#else
#include <sys/time.h>
#endif

#if defined(__STDC__) && __STDC_VERSION__ >= 199901L
#define WS_IF_C99(x) x
#else
#define WS_IF_C99(x)
#endif


/*** Opaque handle for dissections */
typedef struct ws_dissect_t ws_dissect_t;

/*** Initializes dissection capability */
int ws_dissect_init(void);

/*** cleans up dissection capability */
void ws_dissect_finalize(void);

/*** error handling ***/
enum ws_dissect_error {
    WS_DISSECT_OK = 0,
};
/**
 * \returns a thread-local error code
 *
 * The returned value is valid iff it's the first ws_dissect_*
 * function called after another ws_dissect_* function failed
 * in the same thread
 * It's analog to C's errno
 */
enum ws_dissect_error ws_dissect_error(void);


const char *ws_dissect_strerror(enum ws_dissect_error);

/**
 * \param capture to dissect packets from
 * \returns handle for ws_dissect_* operations
 */
ws_dissect_t *ws_dissect_capture(ws_capture_t *capture);

struct ws_dissection {
    /** offset of packet in file **/
    int64_t offset;

    /** time **/
    nstime_t timestamp;
    
    /** profiles in use for this packet */
    struct profile_vec *profiles;

    /** Wireshark protocol tree */
    epan_dissect_t *edt;
};


/**
 * \param [in]  src The dissector to operate on
 * \param [out] dst A pointer to a valid struct dissection
 * \returns a negative error code at failure
 *
 * \brief Dissects the next packet in order
 */
int ws_dissect_next(ws_dissect_t *src, struct ws_dissection *dst);

#define WS_ISO8601_LEN (sizeof "1970-01-01T23:59:59.123456789Z")
char *ws_nstime_tostr(char iso8601[WS_IF_C99(restrict static) WS_ISO8601_LEN], unsigned precision, const nstime_t * WS_IF_C99(restrict) nst);


/**
 * \param   dissector The dissector handle
 * \param   offset    Packet offset to dissect to
 * \returns the new offset if successful or -1 if the underlying capture source
 *          is unseekable
 *
 * \brief Seeks to a specific poisition in the capture handle
 *        May dissect preceeding packets in order to establish cycle bondaries
 */
int ws_dissect_seek(ws_dissect_t *src, struct ws_dissection *dst, int64_t offset /*, int whence*/);

print_stream_t *ws_dissect_print_stream_gstring_new(GString *str);

int ws_dissect_tostr(struct ws_dissection *dissection, char **);
/**
 * \param   dissector The dissector handle
 * \returns the current seek offset if successful or -1 if the underlying capture source
 *          is unseekable
 *
 */
long ws_dissect_tell(ws_dissect_t *dissector);

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

