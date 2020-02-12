/*
 * Copyright (c) 2020 The TCPDUMP project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * This code adapted from tcpdump.c by
 *	Michael Richardson <mcr@sandelman.ca>
 */

/*
 * pktdump - dump traffic on a network, write it to a file using a variety of modules
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

/*
 * This must appear after including netdissect-stdinc.h, so that _U_ is
 * defined.
 */
#ifndef lint
static const char copyright[] _U_ =
    "@(#) Copyright (c) 1988 to 2020\n\n";
#endif

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
#include "missing/getopt_long.h"
#endif

#ifdef HAVE_PCAP_OPEN
/*
 * We found pcap_open() in the capture library, so we'll be using
 * the remote capture APIs; define PCAP_REMOTE before we include pcap.h,
 * so we get those APIs declared, and the types and #defines that they
 * use defined.
 *
 * WinPcap's headers require that PCAP_REMOTE be defined in order to get
 * remote-capture APIs declared and types and #defines that they use
 * defined.
 *
 * (Versions of libpcap with those APIs, and thus Npcap, which is based on
 * those versions of libpcap, don't require it.)
 */
#define HAVE_REMOTE
#endif
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <pwd.h>
#include <grp.h>
#endif /* _WIN32 */

/* capabilities convenience library */
/* If a code depends on HAVE_LIBCAP_NG, it depends also on HAVE_CAP_NG_H.
 * If HAVE_CAP_NG_H is not defined, undefine HAVE_LIBCAP_NG.
 * Thus, the later tests are done only on HAVE_LIBCAP_NG.
 */
#ifdef HAVE_LIBCAP_NG
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#else
#undef HAVE_LIBCAP_NG
#endif /* HAVE_CAP_NG_H */
#endif /* HAVE_LIBCAP_NG */

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif /* __FreeBSD__ */

#include "netdissect.h"
#include "interface.h"
#include "addrtoname.h"
#include "machdep.h"
#include "pcap-missing.h"
#include "ascii_strcasecmp.h"

#include "print.h"
#include "pkt_pipeline.h"

#if defined(HAVE_PCAP_DUMP_FLUSH) && defined(SIGUSR2)
#define SIGNAL_FLUSH_PCAP SIGUSR2
#endif

char *program_name;

/* Forwards */
static NORETURN void exit_tcpdump(int);
static void print_version(void);
static void print_usage(void);
static void error(const char *fmt, ...);
static void warning(const char *fmt, ...);

#ifdef SIGNAL_REQ_INFO
static void requestinfo(int);
#endif

#ifdef SIGNAL_FLUSH_PCAP
static void flushpcap(int);
#endif

static pcap_t *pd;
static pcap_dumper_t *pdd = NULL;

struct dump_info {
	char	*WFileName;
	char	*CurrentFileName;
	pcap_t	*pd;
	pcap_dumper_t *pdd;
	netdissect_options *ndo;
#ifdef HAVE_CAPSICUM
	int	dirfd;
#endif
};

/*
 * Short options.
 * In pktwrite, we will start with *NO* short options.
 */

#define SHORTOPTS ""

/*
 * Long options.
 *
 * Everything gets a long option to start with, and a short option
 * once we agree that it is justified.
 * This means that the long option numbers all start at 128 in the enum.
 *
 */

enum LONG_OPTIONS {
  OPTION_VERSION	= 128,
  OPTION_INPUTFILE      = 129,
  OPTION_INPUTPCAP      = 130,
  OPTION_INPUTPCAPNG    = 131,
  OPTION_OUTPUTPCAP     = 132,
  OPTION_OUTPUTPCAPNG   = 133,
  OPTION_PRINT          = 134,
};

static const struct option longopts[] = {
	{ "version",     no_argument,       NULL, OPTION_VERSION },
	{ "inputpcap",   required_argument, NULL, OPTION_INPUTPCAP },
	{ "inputpcapng", required_argument, NULL, OPTION_INPUTPCAPNG },
	{ "inputfile",   required_argument, NULL, OPTION_INPUTFILE },
	{ "outputpcap",  no_argument,       NULL, OPTION_OUTPUTPCAP },
	{ "outputpcapng",no_argument,       NULL, OPTION_OUTPUTPCAPNG },
	{ "print",       no_argument,       NULL, OPTION_PRINT },
	{ NULL, 0, NULL, 0 }
};

int
main(int argc, char **argv)
{
    int op, i, ret;
    char ebuf[PCAP_ERRBUF_SIZE];
    pkt_pipeline_source *pps = NULL;

    program_name = argv[0];

    /*
     * On platforms where the CPU doesn't support unaligned loads,
     * force unaligned accesses to abort with SIGBUS, rather than
     * being fixed up (slowly) by the OS kernel; on those platforms,
     * misaligned accesses are bugs, and we want tcpdump to crash so
     * that the bugs are reported.
     */
    if (abort_on_misalignment(ebuf, sizeof(ebuf)) < 0)
        error("%s", ebuf);

    while ((op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1) {
        switch (op) {
        case OPTION_VERSION:
            print_version();
            exit_tcpdump(S_SUCCESS);
            break;

        case OPTION_INPUTPCAP:
            pps = pktdump_inputsource(optarg, ebuf);
            if(pps == NULL) {
                fprintf(stderr, "can not read pcap file %s: %s\n", optarg, ebuf);
                exit_tcpdump(S_ERR_ND_OPEN_FILE);
            }
            break;

        case OPTION_PRINT:
            if(pps == NULL) {
                fprintf(stderr, "must provide an input source before setting output options\n");
                exit_tcpdump(S_ERR_PD_NO_INPUT);
            }
            if(pktdump_print_pipeline(pps) != 0) {
                fprintf(stderr, "can not initialize packet printing stage\n");
                exit_tcpdump(S_ERR_PD_NO_INPUT);
            }
            break;

        default:
            print_usage();
            exit_tcpdump(S_ERR_HOST_PROGRAM);
            /* NOTREACHED */
        }
    }

    if(pps) {
        ret = pktdump_runpipeline(pps);
    }

    if(pps) {
        ret = pktdump_finish(pps);
        pps = NULL;
    }

    exit_tcpdump(ret);
}

USES_APPLE_DEPRECATED_API
static void
print_version(void)
{
#ifndef HAVE_PCAP_LIB_VERSION
  #ifdef HAVE_PCAP_VERSION
	extern char pcap_version[];
  #else /* HAVE_PCAP_VERSION */
	static char pcap_version[] = "unknown";
  #endif /* HAVE_PCAP_VERSION */
#endif /* HAVE_PCAP_LIB_VERSION */
	const char *smi_version_string;

	(void)fprintf(stderr, "%s version " PACKAGE_VERSION "\n", program_name);
#ifdef HAVE_PCAP_LIB_VERSION
	(void)fprintf(stderr, "%s\n", pcap_lib_version());
#else /* HAVE_PCAP_LIB_VERSION */
	(void)fprintf(stderr, "libpcap version %s\n", pcap_version);
#endif /* HAVE_PCAP_LIB_VERSION */

#if defined(HAVE_LIBCRYPTO) && defined(SSLEAY_VERSION)
	(void)fprintf (stderr, "%s\n", SSLeay_version(SSLEAY_VERSION));
#endif

	smi_version_string = nd_smi_version_string();
	if (smi_version_string != NULL)
		(void)fprintf (stderr, "SMI-library: %s\n", smi_version_string);

#if defined(__SANITIZE_ADDRESS__)
	(void)fprintf (stderr, "Compiled with AddressSanitizer/GCC.\n");
#elif defined(__has_feature)
#  if __has_feature(address_sanitizer)
	(void)fprintf (stderr, "Compiled with AddressSanitizer/CLang.\n");
#  endif
#endif /* __SANITIZE_ADDRESS__ or __has_feature */
}
USES_APPLE_RST

static void
print_usage(void)
{
    print_version();
    (void)fprintf(stderr,
                  "Usage: %s \n", program_name);
    (void)fprintf(stderr,
                  "\t\t[ --version ]\n");

}

/* VARARGS */
static void
error(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
	exit_tcpdump(S_ERR_HOST_PROGRAM);
	/* NOTREACHED */
}

/* VARARGS */
static void
warning(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: WARNING: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}

static void
exit_tcpdump(int status)
{
    nd_cleanup();
    exit(status);
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * c-style: linux
 * End:
 */
