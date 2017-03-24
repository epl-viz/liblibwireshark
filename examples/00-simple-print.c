#include "ws_capture.h"
#include "ws_dissect.h"

#include <assert.h>
#include <epan/proto.h>
#include <epan/print.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "defs.h"

enum print_type {
    PRINT_MANUAL,
    PRINT_TEXT,
};

static void print_each_packet_text(ws_dissect_t *handle);
static void print_each_packet_manual(ws_dissect_t *handle);

static void print_usage(char *argv[]) {
    printf("Usage: %s [-t <manual|text> (default text)] <input_file>\n", argv[0]);
}

int main(int argc, char *argv[]) {
    char *          filename   = NULL;
    enum print_type print_type = PRINT_TEXT;
    int             opt;


    while ((opt = getopt(argc, argv, "t:")) != -1) {
        switch (opt) {
            case 't':
                      if (strcmp(optarg, "manual") == 0) {
                          print_type = PRINT_MANUAL;
                      } else if (strcmp(optarg, "text") == 0) {
                          print_type = PRINT_TEXT;
                      }
                      break;
            default: print_usage(argv); return 1;
        }
    }


    if (argc == optind) {
        print_usage(argv);
        fprintf(stderr, "Filename is a required argument\n");
        return 1;
    }

    filename = strdup(argv[optind]);

    if (access(filename, F_OK) == -1) {
        fprintf(stderr, "File '%s' doesn't exist.\n", filename);
        return 1;
    }

    int err_code;
    char *err_info;

    ws_capture_init();
    ws_capture_t *cap = ws_capture_open_offline(filename, 0, &err_code, &err_info);
    my_assert(cap, "Error %d: %s\n", err_code, err_info);

    printf("File size: %" PRIu64 " B\n", ws_capture_file_size(cap));

    ws_dissect_init();
    ws_dissect_t *dissector = ws_dissect_capture(cap);
    assert(dissector);

    printf("Reading file: %s\n", ws_capture_filename(cap));

    switch (print_type) {
        case PRINT_MANUAL: print_each_packet_manual(dissector); break;
        case PRINT_TEXT: print_each_packet_text(dissector); break;
    }

    ws_dissect_free(dissector);
    ws_capture_close(cap);

    ws_dissect_finalize();
    ws_capture_finalize();
    return 0;
}

static void visit(proto_tree *node, gpointer data) {
    field_info *fi = PNODE_FINFO(node);
    if (!fi || !fi->rep)
        return;

    printf("***\t%s\n", node->finfo->rep->representation);

    g_assert((fi->tree_type >= -1) && (fi->tree_type < num_tree_types));
    if (node->first_child != NULL) {
        proto_tree_children_foreach(node, visit, data);
    }
}

static void print_each_packet_manual(ws_dissect_t *handle) {
    struct ws_dissection packet;
    while (ws_dissect_next(handle, &packet, NULL, NULL)) {
        proto_tree_children_foreach(packet.edt->tree, visit, NULL);
        puts("\n===================");
    }
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

