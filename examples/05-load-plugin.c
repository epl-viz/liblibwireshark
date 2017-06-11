#include "ws_capture.h"
#include "ws_dissect.h"

#include <assert.h>
#include <epan/proto.h>
#include <epan/print.h>
#include <stdio.h>
#include <string.h>

#include "defs.h"

static void print_each_packet_text(ws_dissect_t *handle);

static void print_usage(char *argv[]) {
    printf("Usage: %s -p <plugin_dir> -d <dissector_to_disable> <input_file>\n", argv[0]);
}

int main(int argc, char *argv[]) {
    char *          filename   = NULL;
    int             opt;
    GArray *disabled = g_array_new(FALSE, FALSE, sizeof(const char *));

    while ((opt = getopt(argc, argv, "p:d:")) != -1) {
        switch (opt) {
            case 'p':
                assert(ws_dissect_plugin_dir(optarg));
                break;
            case 'd':
                g_array_append_val(disabled, optarg);
                break;
            default: print_usage(argv); return 1;
        }
    }


    if (argc == optind) {
        print_usage(argv);
        fprintf(stderr, "Filename is a required argument\n");
        return 1;
    }

    filename = g_strdup(argv[optind]);

    if (access(filename, F_OK) == -1) {
        fprintf(stderr, "File '%s' doesn't exist.\n", filename);
        return 1;
    }

    ws_capture_init();
    ws_dissect_init();

    for (unsigned int i = 0; i < disabled->len; i++) {
        const char *dissector = g_array_index(disabled, const char *, i);
        ws_dissect_proto_disable(dissector);
    }



    int err_code;
    char *err_info;

    ws_capture_t *cap = ws_capture_open_offline(filename, 0, &err_code, &err_info);
    my_assert(cap, "Error %d: %s\n", err_code, err_info);

    ws_dissect_t *dissector = ws_dissect_capture(cap);
    assert(dissector);

    print_each_packet_text(dissector);

    ws_dissect_free(dissector);
    ws_capture_close(cap);

    ws_dissect_finalize();
    ws_capture_finalize();
    return 0;
}


static void print_each_packet_text(ws_dissect_t *handle) {
    struct ws_dissection packet;

    while (ws_dissect_next(handle, &packet, NULL, NULL)) {
        char *buf = NULL;
        ws_dissect_tostr(&packet, &buf);
        puts(buf);
        puts("\n===================");
    }
}

