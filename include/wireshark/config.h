/* cmakeconfig.h.in */

/* Note: You cannot use earlier #defines in later #cmakedefines (cmake 2.6.2). */

/* Name of package */
#define PACKAGE "wireshark"

/* Version number of package */
#define VERSION "1.12.8"
#define VERSION_MAJOR 1
#define VERSION_MINOR 12
#define VERSION_MICRO 8

/* FIXME: Move the path stuff to the CMakeInstallDirs.cmake file */
/* Directory for data */
#define DATAFILE_DIR "/usr/local/share/wireshark"

/* Path to Python. */
/* #undef PYTHON_DIR */

/* Define to 1 if we want to enable plugins */
#define HAVE_PLUGINS 1

/* Link plugins statically into Wireshark */
/* #undef ENABLE_STATIC */

/* Enable AirPcap */
/* #undef HAVE_AIRPCAP */

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <arpa/nameser.h> header file. */
#define HAVE_ARPA_NAMESER_H 1

/* Define to 1 if you have the `bpf_image' function. */
#define HAVE_BPF_IMAGE 1

/* Define to use c-ares library */
/* #undef HAVE_C_ARES */

/* Define to 1 if you have the <direct.h> header file. */
/* #undef HAVE_DIRECT_H */

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the `dladdr' function. */
#define HAVE_DLADDR 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to use GeoIP library */
/* #undef HAVE_GEOIP */

/* Define if GeoIP supports IPv6 (GeoIP 1.4.5 and later) */
/* #undef HAVE_GEOIP_V6 */

/* Define to 1 if you have the `gethostbyname2' function. */
#define HAVE_GETHOSTBYNAME2 1

/* Define to 1 if you have the getopt_long function. */
#define HAVE_GETOPT_LONG 1

/* Define to 1 if you have the <getopt.h> header file. */
#define HAVE_GETOPT_H 1

/* Define to 1 if you have the `getprotobynumber' function. */
#define HAVE_GETPROTOBYNUMBER 1

/* Define to use GNU ADNS library */
/* #undef HAVE_GNU_ADNS */

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define to use heimdal kerberos */
/* #undef HAVE_HEIMDAL_KERBEROS */

/* Define unless inet/aton.h needs to be included */
/* #undef HAVE_INET_ATON_H */

/* Define if inet_ntop() prototype exists */
#define HAVE_INET_NTOP_PROTO 1

/* Define to 1 if you have the `inflatePrime' function. */
#define HAVE_INFLATEPRIME 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `issetugid' function. */
/* #undef HAVE_ISSETUGID */

/* Define to use kerberos */
/* #undef HAVE_KERBEROS */

/* Define if krb5.h defines KEYTYPE_ARCFOUR_56 */
/* #undef HAVE_KEYTYPE_ARCFOUR_56 */

/* Define to use the libcap library */
/* #undef HAVE_LIBCAP */

/* Define to use libgcrypt */
/* #undef HAVE_LIBGCRYPT */

/* Define to use GnuTLS library */
/* #undef HAVE_LIBGNUTLS */

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
/* #undef HAVE_LIBSMI */

/* Define to use libz library */
#define HAVE_LIBZ 1

/* Define to 1 if you have the <linux/sockios.h> header file. */
#define HAVE_LINUX_SOCKIOS_H 1

/* Define to 1 if you have the <linux/if_bonding.h> header file. */
#define HAVE_LINUX_IF_BONDING_H 1

/* Define to use Lua */
/* #undef HAVE_LUA */

/* Define to 1 if you have the <lua.h> header file. */
/* #undef HAVE_LUA_H */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to use MIT kerberos */
/* #undef HAVE_MIT_KERBEROS */

/* Define to 1 if you have the `mkdtemp' function. */
#define HAVE_MKDTEMP 1

/* Define to 1 if you have the `mkstemp' function. */
#define HAVE_MKSTEMP 1

/* Define to 1 if you have the `mmap' function. */
#define HAVE_MMAP 1

/* Define to 1 if you have the `mprotect' function. */
#define HAVE_MPROTECT 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* nl80211.h is new enough */
#define HAVE_NL80211 1

/* SET_CHANNEL is supported */
#define HAVE_NL80211_CMD_SET_CHANNEL 1

/* Define to 1 if you have the <Ntddndis.h> header file. */
/* #undef HAVE_NTDDNDIS_H */

/* Define to 1 if you have OS X frameworks */
/* #undef HAVE_OS_X_FRAMEWORKS */

/* Define if pcap_breakloop is known */
#define HAVE_PCAP_BREAKLOOP 1

/* FIXME: The code (at least) in dumpcap assumes that PCAP_CREATE is not
 *        available on Windows - but we detect it in winpcap */
#ifndef _WIN32
/* Define to 1 if you have the `pcap_create' function. */
#define HAVE_PCAP_CREATE 1
#endif

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

/* Define to 1 if you have the `pcap_open_dead' function. */
#define HAVE_PCAP_OPEN_DEAD 1

/* Define to 1 if you have WinPcap remote capturing support and prefer to use
   these new API features. */
/* #undef HAVE_PCAP_REMOTE */

/* Define to 1 if you have the `pcap_set_datalink' function. */
#define HAVE_PCAP_SET_DATALINK 1

/* Define to 1 if you have the <portaudio.h> header file. */
/* #undef HAVE_PORTAUDIO_H */

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define if python devel package available */
/* #undef HAVE_PYTHON */

/* Define to 1 if you have the optreset variable */
/* #undef HAVE_OPTRESET */

/* Define to 1 to enable remote capturing feature in WinPcap library */
/* #undef HAVE_REMOTE */

/* Define if sa_len field exists in struct sockaddr */
/* #undef HAVE_SA_LEN */

/* Define to 1 if you want to playing SBC by standalone BlueZ SBC library */
/* #undef HAVE_SBC */

/* Define to 1 if you have the `setresgid' function. */
#define HAVE_SETRESGID 1

/* Define to 1 if you have the `setresuid' function. */
#define HAVE_SETRESUID 1

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define if st_flags field exists in struct stat */
/* #undef HAVE_ST_FLAGS */

/* Define to 1 if you have the `sysconf' function. */
#define HAVE_SYSCONF 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/utsname.h> header file. */
#define HAVE_SYS_UTSNAME_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Define if tm_zone field exists in struct tm */
#define HAVE_TM_ZONE 1

/* Define if tzname array exists */
#define HAVE_TZNAME 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <windows.h> header file. */
/* #undef HAVE_WINDOWS_H */

/* Define to 1 if you have the <winsock2.h> header file. */
/* #undef HAVE_WINSOCK2_H */

/* HTML viewer, e.g. mozilla */
#define HTML_VIEWER

/* Define if inet/v6defs.h needs to be included */
/* #undef NEED_INET_V6DEFS_H */

/* Define if strptime.h needs to be included */
/* #undef NEED_STRPTIME_H */

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
#define PLUGIN_INSTALL_DIR "lib/wireshark/plugins/1.12.8"

/* Define if we are using version of of the Portaudio library API */
/* #undef PORTAUDIO_API_1 */

/* Define if we have QtMacExtras */
/* #undef QT_MACEXTRAS_LIB */

/* Define to 1 if your processor stores words with the most significant byte
   first (like Motorola and SPARC, unlike Intel and VAX). */
/* #undef WORDS_BIGENDIAN */

/* Large file support */
/* #undef _LARGEFILE_SOURCE */
/* #undef _LARGEFILE64_SOURCE */
/* #undef _LARGE_FILES */
/* #undef _FILE_OFFSET_BITS */

/* Define WS_MSVC_NORETURN appropriately for declarations of routines that
   never return (just like Charlie on the MTA).

   Note that MSVC++ expects __declspec(noreturn) to precede the function
   name and GCC, as far as I know, expects __attribute__((noreturn)) to
   follow the function name, so we need two different flavors of
   noreturn tag.  */
#define WS_MSVC_NORETURN  

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
/* Note: not use in the code */
/* #undef YYTEXT_POINTER */

/* _U_ isn't needed for C++, simply don't name the variable.
   However, we do need it for some headers that are shared between C and C++. */
#define _U_ __attribute__((unused))

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
   /* Visual C 9 (2008), Visual C 10 (2010) and Visual C 11 (2012) need these
    * prototypes
    * XXX: Can we use MSC_VER >= 1500 ?? */
#  if _MSC_VER == 1500 || _MSC_VER == 1600 || _MSC_VER == 1700
#    define NTDDI_VERSION NTDDI_WIN2K
#    define _WIN32_WINNT _WIN32_WINNT_WIN2K
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

#  define INET6 1
#  define NEED_INET_V6DEFS_H 1
#  define NEED_STRPTIME_H 1
#endif
