#ifndef LIBLIBWIRESHARK_WS_DISSECT_H_
#define LIBLIBWIRESHARK_WS_DISSECT_H_

#ifdef __cplusplus
extern "C" {
#endif

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
#include <WinSock2.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define gmtime_r(ptime,ptm) (gmtime_s((ptm),(ptime)), (ptm))
#else
#include <sys/time.h>
#endif

#include "ws_capture.h"
#include <stdint.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/print.h>
#include <glib.h>
#include <time.h>
#include <string.h>

#if defined(__STDC__) && __STDC_VERSION__ >= 199901L
#define WS_IF_C99(x) x
#else
#define WS_IF_C99(x)
#endif


/*** Opaque handle for dissections */
typedef struct ws_dissect_t ws_dissect_t;

/**
 * \param dir new plugin directory
 * \returns TRUE on success, FALSE on failure
 *
 * \brief Globally set a directory to load plugins from.
 *        This is achieved quite crudely by setting an environment variable
 *        This function may fail if setting the environment variable failed,
 *        if it was executed before dropping root privileges,
 *        or \sa ws_dissect_init was already called.
 * \note Call this before starting _any_ threads, lest demons fly out of noses
 * \note Plugins have priority over built-in dissectors this way, so no need to disable
 */
gboolean ws_dissect_plugin_dir(const char *dir);

/*** Initializes dissection capability */
int ws_dissect_init(void);

/*** cleans up dissection capability */
void ws_dissect_finalize(void);

/**
 * \param name name of dissector
 *
 * \brief Globally Disable a dissector by name.
 * \note Must be called _after_ \sa ws_dissect_init
 */
void ws_dissect_proto_disable(const char *name);


/**
 * \param capture to dissect packets from
 * \returns handle for ws_dissect_* operations
 */
ws_dissect_t *ws_dissect_capture(ws_capture_t *capture);

/**
 * \param handle dissection handle
 * \returns capture handle
 */
ws_capture_t *ws_dissect_get_capture(ws_dissect_t *handle);

struct ws_dissection {
    /** offset of packet in file **/
    int64_t offset;

    /** time **/
    nstime_t timestamp;
    
    /** Wireshark protocol tree */
    epan_dissect_t *edt;
};


/**
 * \param [in]  src The dissector to operate on
 * \param [out] dst A pointer to a valid struct dissection
 * \param [out] err integer to store error code to or NULL
 * \param [out] err_info pointer to store error string to or NULL. must be freed with g_free
 * \returns TRUE if the dissection was successful. FALSE otherwise. On failure check *err to determine whether you reached EOF or whether a proper failure occured
 *
 * \brief Dissects the next packet in order
 */
gboolean ws_dissect_next(ws_dissect_t *src, struct ws_dissection *dst, int *err, char **err_info);

/** The buffer size for a nanosecond precision timestamp **/
#define WS_ISO8601_LEN (sizeof "1970-01-01T23:59:59.123456789Z")

/**
 * \param [out] iso8601 The buffer to store to
 * \param [in] precision How many decimal places. 0 removes the dot
 * \param [in] nst The nanosecond struct used in wireshark
 * \returns iso8601, the first argument
 *
 * \brief Turns a nstime_t timestamp since the epoch into its ISO8601 UTC representation
 */
char *ws_nstime_tostr(char iso8601[WS_IF_C99(restrict static) WS_ISO8601_LEN], unsigned precision, const nstime_t * WS_IF_C99(restrict) nst);


/**
 * \param [in]  src The dissector to operate on
 * \param [out] dst A pointer to a valid struct dissection
 * \param [in]  offset The offset to seek to
 * \param [out] err integer to store error code to or NULL
 * \param [out] err_info pointer to store error string to or NULL. must be freed with g_free
 * \returns TRUE if the seek was successful, FALSE otherwise
 *
 * \brief Does a positional read at the specified offset in the file. Offsets are returned ws_dissection and can be obtained e.g. by doing a first pass with ws_dissect_next
 */
gboolean ws_dissect_seek(ws_dissect_t *src, struct ws_dissection *dst, int64_t offset, int *err, char **err_info);

/**
 * \param [out]  An initialized GString to append to
 * \returns a stream printer for use with proto_tree_print and friends
 *
 * \brief A memory buffer stream printer. \sa ws_dissect_tostr for a client example
 */
print_stream_t *ws_dissect_print_stream_gstring_new(GString *str);

/**
 * \param [in]  dissection as returned by another ws_dissect_* function
 * \param [out] ptr A non-null pointer to a pointer equalling NULL. Will contain a pointer to the string representation afterwards
 * \returns NULL on failure, *ptr if successful
 *
 * \brief Provides a string representation of what would be shown in tshark for the dissection
 */
char *ws_dissect_tostr(struct ws_dissection *dissection, char **ptr);

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

