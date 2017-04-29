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
#define HAVE_SYS_WAIT_H
#define HAVE_SYS_IOCTL_H
#define HAVE_SYS_SOCKET_H
#define HAVE_SYS_TYPES_H

/* Define if pcap_breakloop is known */
#define HAVE_PCAP_BREAKLOOP 1

/* Define to 1 if you have the `pcap_create' function. */
#define HAVE_PCAP_CREATE 1

/* Define to 1 if the capture buffer size can be set. */
#define CAN_SET_CAPTURE_BUFFER_SIZE 1

/* Define to 1 if you have the `pcap_datalink_name_to_val' function. */
#define HAVE_PCAP_DATALINK_NAME_TO_VAL 1

/* Define to 1 if you have the `pcap_datalink_val_to_description' function. */
#define HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION 1

/* Define to 1 if you have the `pcap_datalink_val_to_name' function. */
#define HAVE_PCAP_DATALINK_VAL_TO_NAME 1

/* Define to 1 if you have the `pcap_findalldevs' function and a pcap.h that
   declares pcap_if_t. */
#define HAVE_PCAP_FINDALLDEVS 1

/* Define to 1 if you have the `pcap_freecode' function. */
#define HAVE_PCAP_FREECODE 1

/* Define to 1 if you have the `pcap_free_datalinks' function. */
#define HAVE_PCAP_FREE_DATALINKS 1

/* Define to 1 if you have the `pcap_get_selectable_fd' function. */
#define HAVE_PCAP_GET_SELECTABLE_FD 1

/* Define to 1 if you have the `pcap_lib_version' function. */
#define HAVE_PCAP_LIB_VERSION 1

/* Define to 1 if you have the `pcap_list_datalinks' function. */
#define HAVE_PCAP_LIST_DATALINKS 1

#endif
