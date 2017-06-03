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

#if WIN32

/* cmakeconfig.h.in */

/* Note: You cannot use earlier #defines in later #cmakedefines (cmake 2.6.2). */

/* Name of package */
#define PACKAGE "wireshark"

#define VERSION_EXTRA ""

/* Version number of package */
#define VERSION "2.3.0"
#define VERSION_MAJOR 2
#define VERSION_MINOR 3
#define VERSION_MICRO 0

#define VERSION_FLAVOR "Development Build"

/* FIXME: Move the path stuff to the CMakeInstallDirs.cmake file */
/* Directory for data */
#define DATAFILE_DIR "C:/Users/danie/projects/install/share/Wireshark"

/* Build wsutil with SIMD optimization */
#define HAVE_SSE4_2 1

/* Directory where extcap hooks reside */
#define EXTCAP_DIR "extcap"

/* Define to 1 if we want to enable extcap */
#define HAVE_EXTCAP 1

/* Define to 1 if we want to enable plugins */
#define HAVE_PLUGINS 1

/*  Define to 1 if we check hf conflict */
/* #undef ENABLE_CHECK_FILTER */

/* Link plugins statically into Wireshark */
/* #undef ENABLE_STATIC */

/* Enable AirPcap */
#define HAVE_AIRPCAP 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
/* #undef HAVE_ARPA_INET_H */

/* Define to 1 if you have the <arpa/nameser.h> header file. */
/* #undef HAVE_ARPA_NAMESER_H */

/* Define to 1 if you have the `bpf_image' function. */
#define HAVE_BPF_IMAGE 1

/* Define to use c-ares library */
#define HAVE_C_ARES 1

/* Define to 1 if you have the `dladdr' function. */
/* #undef HAVE_DLADDR */

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to use GeoIP library */
#define HAVE_GEOIP 1

/* Define if GeoIP supports IPv6 (GeoIP 1.4.5 and later) */
#define HAVE_GEOIP_V6 1

/* Define if GeoIP has GeoIP_free (not available upstream with 1.6.10 or earlier) */
#define HAVE_GEOIP_FREE 1

/* Define to 1 if you have the <ifaddrs.h> header file. */
/* #undef HAVE_IFADDRS_H */

/* Define to 1 if you have the `getifaddrs' function. */
/* #undef HAVE_GETIFADDRS */

/* Define if LIBSSH support is enabled */
#define HAVE_LIBSSH 1

/* Define if LIBSSH has ssh_userauth_agent() function */
/* #undef HAVE_SSH_USERAUTH_AGENT */

/* Define if you have the 'floorl' function. */
#define HAVE_FLOORL 1

/* Define if you have the 'lrint' function. */
#define HAVE_LRINT 1

/* Define to 1 if you have the getopt_long function. */
/* #undef HAVE_GETOPT_LONG */

/* Define to 1 if you have the <getopt.h> header file. */
/* #undef HAVE_GETOPT_H */

/* Define if GLib's printf functions support thousands grouping. */
/* #undef HAVE_GLIB_PRINTF_GROUPING */

/* Define to 1 if you have the `getprotobynumber' function. */
/* #undef HAVE_GETPROTOBYNUMBER */

/* Define to 1 if you have the <grp.h> header file. */
/* #undef HAVE_GRP_H */

/* Define to use heimdal kerberos */
/* #undef HAVE_HEIMDAL_KERBEROS */

/* Define to 1 if you have the `inet_aton' function. */
/* #undef HAVE_INET_ATON */

/* Define to 1 if you have the `inet_ntop' function. */
/* #undef HAVE_INET_NTOP */

/* Define to 1 if you have the `inet_pton' function. */
/* #undef HAVE_INET_PTON */

/* Define to 1 if you have the `inflatePrime' function. */
/* #undef HAVE_INFLATEPRIME */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `issetugid' function. */
/* #undef HAVE_ISSETUGID */

/* Define to use kerberos */
#define HAVE_KERBEROS 1

/* Define to use nghttp2 */
#define HAVE_NGHTTP2 1

/* Define to use the libcap library */
/* #undef HAVE_LIBCAP */

/* Define to use GnuTLS library */
#define HAVE_LIBGNUTLS 1

/* Enable libnl support */
/* #undef HAVE_LIBNL */

/* libnl version 1 */
/* #undef HAVE_LIBNL1 */

/* libnl version 2 */
/* #undef HAVE_LIBNL2 */

/* libnl version 3 */
/* #undef HAVE_LIBNL3 */

/* Define to use libpcap library */
#define HAVE_LIBPCAP 1

/* Define to use libportaudio library */
/* #undef HAVE_LIBPORTAUDIO */

/* Define to 1 if you have the `smi' library (-lsmi). */
#define HAVE_LIBSMI 1

/* Define to use zlib library */
#define HAVE_ZLIB 1

/* Define to use lz4 library */
#define HAVE_LZ4 1

/* Define to use snappy library */
#define HAVE_SNAPPY 1

/* Define to 1 if you have the <linux/sockios.h> header file. */
/* #undef HAVE_LINUX_SOCKIOS_H */

/* Define to 1 if you have the <linux/if_bonding.h> header file. */
/* #undef HAVE_LINUX_IF_BONDING_H */

/* Define to use Lua */
#define HAVE_LUA 1

/* Define to 1 if you have the <lua.h> header file. */
#define HAVE_LUA_H 1

/* Define to 1 if you have the <memory.h> header file. */
/* #undef HAVE_MEMORY_H */

/* Define to use MIT kerberos */
#define HAVE_MIT_KERBEROS 1

/* Define to 1 if you have the `mkdtemp' function. */
/* #undef HAVE_MKDTEMP */

/* Define to 1 if you have the `mkstemps' function. */
/* #undef HAVE_MKSTEMPS */

/* Define to 1 if you have the `mmap' function. */
/* #undef HAVE_MMAP */

/* Define to 1 if you have the `mprotect' function. */
/* #undef HAVE_MPROTECT */

/* Define to 1 if you have the <netdb.h> header file. */
/* #undef HAVE_NETDB_H */

/* Define to 1 if you have the <netinet/in.h> header file. */
/* #undef HAVE_NETINET_IN_H */

/* nl80211.h is new enough */
/* #undef HAVE_NL80211 */

/* SET_CHANNEL is supported */
/* #undef HAVE_NL80211_CMD_SET_CHANNEL */

/* SPLIT_WIPHY_DUMP is supported */
/* #undef HAVE_NL80211_SPLIT_WIPHY_DUMP */

/* VHT_CAPABILITY is supported */
/* #undef HAVE_NL80211_VHT_CAPABILITY */

/* Define to 1 if you have the <Ntddndis.h> header file. */
/* #undef HAVE_NTDDNDIS_H */

/* Define to 1 if you have macOS frameworks */
/* #undef HAVE_OS_X_FRAMEWORKS */

/* Define to 1 if you have the macOS CFPropertyListCreateWithStream function */
/* #undef HAVE_CFPROPERTYLISTCREATEWITHSTREAM */

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
/* #undef HAVE_PCAP_GET_SELECTABLE_FD */

/* Define to 1 if you have the `pcap_lib_version' function. */
#define HAVE_PCAP_LIB_VERSION 1

/* Define to 1 if you have the `pcap_list_datalinks' function. */
#define HAVE_PCAP_LIST_DATALINKS 1

/* Define to 1 if you have the `pcap_open' function. */
#define HAVE_PCAP_OPEN 1

/* Define to 1 if you have the `pcap_open_dead' function. */
#define HAVE_PCAP_OPEN_DEAD 1

/* Define to 1 if you have libpcap/WinPcap remote capturing support. */
#define HAVE_PCAP_REMOTE 1

/* Define to 1 if you have the `pcap_set_datalink' function. */
#define HAVE_PCAP_SET_DATALINK 1

/* Define to 1 if you have the `pcap_setsampling' function. */
#define HAVE_PCAP_SETSAMPLING 1

/* Define to 1 if you have the `pcap_set_tstamp_precision' function. */
/* #undef HAVE_PCAP_SET_TSTAMP_PRECISION */

/* Define to 1 if you have the popcount function. */
/* #undef HAVE_POPCOUNT */

/* Define to 1 if you have the <portaudio.h> header file. */
/* #undef HAVE_PORTAUDIO_H */

/* Define to 1 if you have the <pwd.h> header file. */
/* #undef HAVE_PWD_H */

/* Define to 1 if you have the optreset variable */
/* #undef HAVE_OPTRESET */

/* Define if sa_len field exists in struct sockaddr */
/* #undef HAVE_STRUCT_SOCKADDR_SA_LEN */

/* Define to 1 if you want to playing SBC by standalone BlueZ SBC library */
#define HAVE_SBC 1

/* Define to 1 if you have the SpanDSP library. */
#define HAVE_SPANDSP 1

/* Define to 1 if you have the lixbml2 library. */
#define HAVE_LIBXML2 1

/* Define to 1 if you have the `setresgid' function. */
/* #undef HAVE_SETRESGID */

/* Define to 1 if you have the `setresuid' function. */
/* #undef HAVE_SETRESUID */

/* Define to 1 if you have the WinSparkle library */
#define HAVE_SOFTWARE_UPDATE 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <strings.h> header file. */
/* #undef HAVE_STRINGS_H */

/* Define if you have the 'strptime' function. */
/* #undef HAVE_STRPTIME */

/* Define to 1 if `st_birthtime' is a member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT_ST_BIRTHTIME */

/* Define if st_flags field exists in struct stat */
/* #undef HAVE_STRUCT_STAT_ST_FLAGS */

/* Define to 1 if `__st_birthtime' is a member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT___ST_BIRTHTIME */

/* Define to 1 if you have the `sysconf' function. */
/* #undef HAVE_SYSCONF */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
/* #undef HAVE_SYS_IOCTL_H */

/* Define to 1 if you have the <sys/param.h> header file. */
/* #undef HAVE_SYS_PARAM_H */

/* Define to 1 if you have the <sys/socket.h> header file. */
/* #undef HAVE_SYS_SOCKET_H */

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
/* #undef HAVE_SYS_TIME_H */

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/utsname.h> header file. */
/* #undef HAVE_SYS_UTSNAME_H */

/* Define to 1 if you have the <sys/wait.h> header file. */
/* #undef HAVE_SYS_WAIT_H */

/* Define if tm_zone field exists in struct tm */
/* #undef HAVE_STRUCT_TM_TM_ZONE */

/* Define if tzname array exists */
/* #undef HAVE_TZNAME */

/* Define to 1 if you have the <unistd.h> header file. */
/* #undef HAVE_UNISTD_H */

/* Define to 1 if you have the <windows.h> header file. */
#define HAVE_WINDOWS_H 1

/* Define to 1 if you have the <winsock2.h> header file. */
#define HAVE_WINSOCK2_H 1

/* Name of package */
/* #undef PACKAGE */

/* Define to the address where bug reports for this package should be sent. */
/* #undef PACKAGE_BUGREPORT */

/* Define to the full name of this package. */
/* #undef PACKAGE_NAME */

/* Define to the full name and version of this package. */
/* #undef PACKAGE_STRING */

/* Define to the one symbol short name of this package. */
/* #undef PACKAGE_TARNAME */

/* Define to the version of this package. */
/* #undef PACKAGE_VERSION */

/* Support for pcap-ng */
#define PCAP_NG_DEFAULT 1

/* Plugin installation directory */
#define PLUGIN_INSTALL_DIR "plugins/2.3.0"

/* Define if we are using version of of the Portaudio library API */
/* #undef PORTAUDIO_API_1 */

/* Define if we have QtMultimedia */
#define QT_MULTIMEDIA_LIB 1

/* Define if we have QtMacExtras */
/* #undef QT_MACEXTRAS_LIB */

/* Define if we have QtWinExtras */
/* #undef QT_WINEXTRAS_LIB */

/* Support for packet editor */
#define WANT_PACKET_EDITOR 1

/* Define to 1 if your processor stores words with the most significant byte
first (like Motorola and SPARC, unlike Intel and VAX). */
/* #undef WORDS_BIGENDIAN */

/* Build androiddump with libpcap instead of wireshark stuff */
/* #undef ANDROIDDUMP_USE_LIBPCAP */

/* Large file support */
/* #undef _LARGEFILE_SOURCE */
/* #undef _LARGEFILE64_SOURCE */
/* #undef _LARGE_FILES */
/* #undef _FILE_OFFSET_BITS */

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
`char[]'. */
/* Note: not use in the code */
/* #undef YYTEXT_POINTER */

/* _U_ isn't needed for C++, simply don't name the variable.
However, we do need it for some headers that are shared between C and C++. */
#define _U_ 

/* Hint to the compiler that a function never returns */
#define WS_NORETURN __declspec(noreturn)

#if defined(_WIN32)

/* WpdPack/INclude/pcap/pcap.h checks for "#if defined(WIN32)" */
#  ifndef WIN32
#    define WIN32	1
#  endif

#  if !defined(QT_VERSION) || !defined(_SSIZE_T_DEFINED)
typedef int ssize_t;
#  endif

/* FIXME: Detection doesn't work */
#  define HAVE_NTDDNDIS_H 1
/* Visual C 9 (2008), Visual C 10 (2010), Visual C 11 (2012) and Visual C 12 (2013)
*  need these prototypes
* XXX: Can we use MSC_VER >= 1500 ?? */
#  if _MSC_VER == 1500 || _MSC_VER == 1600 || _MSC_VER == 1700 || _MSC_VER == 1800
#    define NTDDI_VERSION NTDDI_WINXPSP3
#    define _WIN32_WINNT _WIN32_WINNT_WINXP
#  endif

/*
* Flex (v 2.5.35) uses this symbol to "exclude" unistd.h
*/
#  define YY_NO_UNISTD_H


#  define strncasecmp strnicmp
#  define popen       _popen
#  define pclose      _pclose

#  ifndef __STDC__
#    define __STDC__ 0
#  endif
/* Use Unicode in Windows runtime functions. */
#  define UNICODE 1
#  define _UNICODE 1

#  define NEED_STRPTIME_H 1
#endif

#include <ws_diag_control.h>


#else

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
#endif
