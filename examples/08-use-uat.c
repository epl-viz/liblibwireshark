#include "ws_capture.h"
#include "ws_dissect.h"
#include <epan/prefs.h>

#include <assert.h>
#include <epan/proto.h>
#include <epan/print.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "defs.h"

static void print_each_packet_text(ws_dissect_t *handle);

static void print_usage(char *argv[]) {
    printf("Usage: %s -p <plugin_dir> <input_file>\n", argv[0]);
}

int main(int argc, char *argv[]) {
    char *          filename      = "../samples/EPL-IdentResponse.pcapng";
    char            default_xdd[] = "/Users/a3f/pse/resources/profiles/00000000_POWERLINK_CiA401_CN_1.xdc\"";
    int             opt;
    /*GArray *disabled = g_array_new(FALSE, FALSE, sizeof(const char *));*/

    while ((opt = getopt(argc, argv, "p:d:")) != -1) {
        switch (opt) {
            case 'p':
                assert(ws_dissect_plugin_dir(optarg));
                break;
            default: print_usage(argv); return 1;
        }
    }


    if (argc != optind) {
        filename = g_strdup(argv[optind]);
    }

    if (access(filename, F_OK) == -1) {
        fprintf(stderr, "File '%s' doesn't exist.\n", filename);
        return 1;
    }

    ws_capture_init();
    ws_dissect_init();
    static char pref[1024] = "uat:epl_nodeid_profiles:\"1\",\"";
    size_t pref_len = strlen(pref);
    printf("Enter Profile 401 XDD path (default: \"%s): ",
            default_xdd);
    fflush(stdout);
    fgets(pref + pref_len, sizeof pref - pref_len - 2, stdin);
    if (pref[pref_len] == '\n')
        memcpy(pref + pref_len, default_xdd, sizeof default_xdd);
    else {
        pref_len = strlen(pref);
        pref[pref_len-1]   = '\"';
        pref[pref_len] = '\0';
    }
    printf("Calling prefs_set_pref(\"%s\")\n", pref);

    char *err;
    switch(prefs_set_pref(pref, &err)) {
        case PREFS_SET_SYNTAX_ERR:
            printf("Syntax error%s%s\n", err ? ": " : "", err ? err : "");
            return 1;
        case PREFS_SET_NO_SUCH_PREF:
            printf("Preference doesn't exist%s%s\n", err ? ": " : "", err ? err : "");
            return 2;
        case PREFS_SET_OBSOLETE:
            printf("Preference is obsolete%s%s\n" , err ? ": " : "", err ? err : "");
            break;
        case PREFS_SET_OK:
            printf("Preferences set!\n");
            break;
    }
    prefs_apply_all();

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
#if 0
        char *buf = NULL;
        ws_dissect_tostr(&packet, &buf);
        puts(buf);
#endif
    }
}

