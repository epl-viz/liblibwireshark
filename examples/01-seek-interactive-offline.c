#include "ws_capture.h"
#include "ws_dissect.h"

#include <assert.h>
#include <epan/proto.h>
#include <epan/print.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>

#include "defs.h"


static void print_usage(char *argv[]) {
    printf("Usage: %s <input_file>\n", argv[0]);
}

int main(int argc, char *argv[]) {
    char *filename   = NULL;
    int err_code;
    char *err_info;
    
    if (argc != 2) {
        print_usage(argv);
        return 1;
    }
    filename = argv[1];

    if (access(filename, F_OK) == -1) {
        fprintf(stderr, "File '%s' doesn't exist.\n", filename);
        return 2;
    }

    ws_capture_init();
    ws_capture_t *cap = ws_capture_open_offline(filename, 0, &err_code, &err_info);
    my_assert(cap, "Error %d: %s\n", err_code, err_info);

    ws_dissect_init();
    ws_dissect_t *dissector = ws_dissect_capture(cap);
    assert(dissector);

    GArray *frames = g_array_new(FALSE, FALSE, sizeof(int64_t));
    g_array_append_val(frames, (int64_t){0});

    char timestamp[WS_ISO8601_LEN];
    struct ws_dissection packet;
    while (ws_dissect_next(dissector, &packet, &err_code, &err_info)) {
        ws_nstime_tostr(timestamp, 6, &packet.timestamp);

        printf("%s %s\n", timestamp, packet.edt->tree->first_child->finfo->rep->representation);
        g_array_append_val(frames, packet.offset);
    }
    /* Did we exit due to EOF and not some error? */
    my_assert(!err_code, "Error %d: %s\n", err_code, err_info);

    char buf[32];
    printf("Seek to frame: ");
    // FIXME: some init function closes standard input
    freopen("/dev/tty", "r", stdin);

    while (fgets(buf, sizeof buf, stdin)) {
        char *endptr;
        unsigned long framenum = strtol(buf, &endptr, 0);
        if ((1 <= framenum && framenum <= frames->len) && endptr != buf) {
            struct ws_dissection packet;
            int64_t offset = g_array_index(frames, int64_t, framenum);
            if (ws_dissect_seek(dissector, &packet, offset, NULL, NULL)) {
                char *buf = NULL;
                ws_dissect_tostr(&packet, &buf);
                puts(buf);
            } else {
                fprintf(stderr, "Seeking to frame %lu (offset=%" PRId64 ") failed with code=%d (%s)\n",
                        framenum, offset, err_code, err_info);
            }
            printf("%lld\n", offset);
        } else {
            fprintf(stderr, "Invalid frame number (must be in [1, %u]\n", frames->len - 1);
        }
        printf("Seek to: ");
    }



    ws_dissect_free(dissector);
    ws_capture_close(cap);

    ws_dissect_finalize();
    ws_capture_finalize();
    return 0;
}

