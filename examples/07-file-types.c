#include <wiretap/wtap.h>
#include <stdio.h>
int main(void) {
    puts("Supported datatypes:");
    for (GSList *type = wtap_get_all_file_extensions_list(); type; type = type->next) {
        fputs(type->data, stdout);
        putchar('\t');
    }

}

