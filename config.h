#ifndef LIBLIBWIRESHARK_CONFIG_H_
#define LIBLIBWIRESHARK_CONFIG_H_

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#ifdef __GNUC__
#define _U_ __attribute__((unused))
#else
#define _U_
#endif

#define HAVE_FCNTL_H
#define HAVE_UNISTD_H
#define HAVE_SYS_STAT_H

#define HAVE_PCAP_CREATE

#endif
