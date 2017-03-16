#include "ws_capture.h"
#include "ws_dissect.h"

#include <assert.h>
#include <epan/proto.h>
#include <epan/print.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <capchild/capture_session.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "defs.h"

static void print_each_packet_text(ws_dissect_t *handle);
static void print_each_packet_manual(ws_dissect_t *handle);

static void print_usage(char *argv[]) {
    printf("Usage: %s [-I] <input_file>\n", argv[0]);
}

int main(int argc, char *argv[]) {
#ifdef __APPLE__
    char           *interface   = "en0";
#elif defined(__unix__)
    char           *interface   = "eth0";
#else
    char           *interface   = NULL;
#endif

    int             opt;

    ws_capture_init();
    ws_dissect_init();

    int err_code;
    char *err_info;

    while ((opt = getopt(argc, argv, "Ii:")) != -1) {
        switch (opt) {
            GList *if_list;
            case 'I':
            if_list = capture_interface_list(&err_code, &err_info, NULL);
            if (if_list == NULL) {
                if (err_code == 0)
                    puts("There are no interfaces on which a capture can be done");
                else {
                    printf("%s\n", err_info);
                    g_free(err_info);
                }
                return 2;
            }

            puts("# Interfaces #");

            do {
                if_info_t *if_info = (if_info_t*)if_list->data;

                printf("%s: %s%s, %s\nAddresses: (\n",
                        if_info->name ?:"", if_info->friendly_name ?:"",
                        if_info->loopback ? " (loopback)" : "",
                        if_info->vendor_description ?:"");

                for (GSList *node = if_info->addrs; node; node = node->next) {
                    if_addr_t *if_addr = (if_addr_t*)node->data;
                    if (if_addr->ifat_type == IF_AT_IPv4) {
                        char ip[INET_ADDRSTRLEN];
                        struct sockaddr_in sa = { .sin_addr.s_addr = if_addr->addr.ip4_addr };
                        putchar('\t');
                        puts(inet_ntop(AF_INET, &sa, ip, INET6_ADDRSTRLEN));
                    } else if (if_addr->ifat_type == IF_AT_IPv6) {
                        char ip[INET6_ADDRSTRLEN];
                        struct sockaddr_in6 sa = {0};
                        memcpy(sa.sin6_addr.s6_addr, if_addr->addr.ip6_addr, sizeof if_addr->addr.ip6_addr);
                        putchar('\t');
                        puts(inet_ntop(AF_INET6, &sa, ip, INET6_ADDRSTRLEN));
                    }
                }
                puts(")");

            } while ((if_list = if_list->next));

            free_interface_list(if_list);
            return 0;
            case 'i':
            interface = optarg;
            break;
            default: print_usage(argv); return 1;
        }
    }



    ws_capture_t *cap = ws_capture_open_live(interface, 0, NULL, &err_code, &err_info);
    my_assert(cap, "Error %d: %s\n", err_code, err_info);

    ws_dissect_t *dissector = ws_dissect_capture(cap);
    assert(dissector);

    sleep(1);

    printf("Reading file: %s\n", ws_capture_filename(cap));

    print_each_packet_text(dissector);

    ws_dissect_free(dissector);
    ws_capture_close(cap);

    ws_dissect_finalize();
    ws_capture_finalize();
    return 0;
}

static void print_each_packet_text(ws_dissect_t *handle) {
    int err;
    char *err_msg;
    struct ws_dissection packet;
    while (ws_dissect_next(handle, &packet, &err, &err_msg)) {
        char *buf = NULL;
        ws_dissect_tostr(&packet, &buf);
        puts(buf);
        puts("\n===================");
    }
    printf("dissect exited with %s (%d)\n", err_msg, err);
}


