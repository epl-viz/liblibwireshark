#include "ws_dissect.h"
#include <glib.h>
#include <epan/print_stream.h>
struct output_mem {
    print_stream_t stream;

    char *buf;
    GString *gstr;
};
static gboolean destroy_mem(print_stream_t *self)
{
    struct output_mem *output = (struct output_mem *)self;
    (void)output;
    g_free(self);
    return TRUE;
}
static gboolean print_line_mem(print_stream_t *self, int indent, const char *line) {
    struct output_mem *output = (struct output_mem*)self;
    GString *gstr = output->gstr;
    while (indent --> 0)
        gstr = g_string_append_c(gstr, '\t');

    gstr = g_string_append(gstr, line);
    gstr = g_string_append_c(gstr, '\n');

    return TRUE;
}
static gboolean new_page_mem(print_stream_t *self) {
    struct output_mem *output = (struct output_mem*)self;
    GString *gstr = output->gstr;
    gstr = g_string_append(gstr, "\n\n");

    return TRUE;
}

static const print_stream_ops_t print_mem_ops = {
    NULL,            /* preamble */
    print_line_mem,
    NULL,            /* bookmark */
    new_page_mem,
    NULL,            /* finale */
    destroy_mem
};

print_stream_t *ws_dissect_print_stream_gstring_new(GString *gstr) {
    struct output_mem *output;
    print_stream_t *stream;
    stream = (print_stream_t *)g_malloc0(sizeof*output);
    stream->ops = &print_mem_ops;
    output = stream->data = stream;
    output->gstr = gstr;
    

    return stream;
}

