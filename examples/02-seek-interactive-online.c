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



static void print_usage(char *argv[]) {
    printf("Usage: %s <input_file>\n", argv[0]);
}

int main(int argc, char *argv[]) {
    char *filename   = NULL;
    
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
    // TODO: better diagnostics
    ws_capture_t *cap = ws_capture_open_offline(filename, 0, NULL, NULL);
    assert(cap);

    ws_dissect_init();
    ws_dissect_t *dissector = ws_dissect_capture(cap);
    assert(dissector);

    GArray *frames = g_array_new(FALSE, FALSE, sizeof(int64_t));
    g_array_append_val(frames, (int64_t){0});

    char timestamp[WS_ISO8601_LEN];
    struct ws_dissection packet;
    while (ws_dissect_next(dissector, &packet, NULL, NULL)) {
        ws_nstime_tostr(timestamp, 9, &packet.timestamp);

        printf("%s %s\n", timestamp, packet.edt->tree->first_child->finfo->rep->representation);
        g_array_append_val(frames, packet.offset);
    }

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
                fprintf(stderr, "Seeking to frame %lu (offset=%" PRId64 ") failed\n",
                        framenum, offset);
            }
            printf("%lld\n", offset);
        } else {
            fprintf(stderr, "Invalid frame number (must be in [1, %u]\n", frames->len);
        }
        printf("Seek to: ");
    }



    ws_dissect_free(dissector);
    ws_capture_close(cap);

    ws_dissect_finalize();
    ws_capture_finalize();
    return 0;
}

