#include "ws_capture.h"
#include "ws_dissect.h"

#include <assert.h>
#include <epan/proto.h>
#include <epan/print.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void visit(proto_tree *node, gpointer data);
static void print_usage(char *argv[]) {
    printf("Usage: %s <input_file> ", argv[0]);
}

int main(int argc, char *argv[]) {
    char *          filename   = NULL;
    int             opt;
    
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
    ws_capture_t *cap = ws_capture_open_offline(filename, 0);
    assert(cap);

    ws_dissect_init();
    ws_dissect_t *dissector = ws_dissect_capture(cap);
    assert(dissector);

    struct ws_dissection packet;
    while (ws_dissect_next(dissector, &packet)) {
        proto_tree_children_foreach(packet.edt->tree, visit, NULL);
        puts("\n===================");
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
    while (ws_dissect_next(handle, &packet)) {
        proto_tree_children_foreach(packet.edt->tree, visit, NULL);
        puts("\n===================");
    }
}


static void print_each_packet_text(ws_dissect_t *handle) {
    struct ws_dissection packet;

    while (ws_dissect_next(handle, &packet)) {
        char *buf = NULL;
        ws_dissect_tostr(&packet, &buf);
        puts(buf);
        puts("\n===================");
    }
}

