/*
 * Copyright (c) 2013 The TCPDUMP project
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
 * This code was written by Michael Richardson with the support of
 * CIRALabs and Comcast Innovation Fund.
 *
 */


#include <linux/if_packet.h>

/**
 * This file describes a pipeline of aggregate packet processors.
 *
 * The pipeline is a series of modules, each takes a (possibly sparse) array of packets
 * and mutates the array of packets.
 * It may process/filter some of them, leaving others behind, or it may even replace
 * entire packets with new content.
 * The pipeline header contains an allocator/deallocator that can provide packet sized
 * buffers for the pipeline modules.
 * There is a mechanism for a pipeline module to steal a packet, but this operation may
 * result in a memory copy being done.
 * At the end of the pipeline, any packets left in the pipeline are freed and returned
 * to the system.
 *
 * This pipeline is designed to be as compatible with the LINUX TPACKET_v3 mechanism.
 * It may not work well with other systems.
 *
 * The pipeline structure contains a pointer to an array of structures, one for each
 * packet in the pipeline.   These contain a pointer to a tpacket3_hdr on Linux.
 * In addition, there is an array available per-packet, which may be used for each
 * pipeline stage.
 * During initialization, the pipeline state is given a pipeline stage number to index into.
 * (Maybe this will be a compile-time constant).
 * The initialization also examines the size of the structure required and will allocate
 * the space up-front.
 *
 * These are typedef'ed to pkt_pipeline_hdr, and code should not look into the structure
 * directly, but should use the provided macros so that there is some possibility
 * that this code might work on future tpacket layers, and also on other operating systems
 *
 * The array of pointers may contain a NULL, which means that some other layer has already
 * claimed the packet.
 * They might not point to actual capture data, as it might be the result of fragments
 * being assembled into a complete packet, which probably requires additional memory.
 *
 * The array is larger than what is pointed to by this extent: only the portion which has
 * become ready for processing is passed up.
 *
 * A pipeline level which discards a packet will mark the underlying tpacket3_hdr as being
 * available to the kernel again, but the kernel will not walk past an entry which is in use,
 * so it is important that a pipeline stage eventually frees all packets.
 *
 * Multi-process, multi-permission
 * -------------------------------
 *
 * A key part of the pkt_pipeline is that it is multi-process in order that each process
 * can operate with reduced permissions, or completely different permissions than the
 * capture process.
 *
 * This is enabled by the fact that mmap(2) regions are kept across fork(2) operations,
 * and through the primary use of memory operations between processes rather than function
 * calls.
 *
 * The intention is support exec(2) operations so that entirely different sets of code can be
 * started which do not need to be built in (or shared library loaded) to the pkdump executable.
 * This is stretch goal, and will require the FD for the PF_PACKET socket to be passed,
 * and the RX-ring to be mmap(2) again.  There are many other book-keeping issues that need
 * be resolved, so this is a stretch goal.
 *
 * Initialization
 * --------------
 *
 * Each pkt_pipeline stage is provided with a pointer in the pkt_pipeline_extra that it can
 * use to point to it's private information.  This may get mutated into a larger structure
 * once it is better understood what we need.
 *
 * Each stage of the pipeline will have a pipeline stage number assigned when the pipeline
 * is setup.
 *
 * So, PKT_PIPELINE_MAX is the maximum number of stages that can be configured at once.
 * Having it as a compile time constant is probably not a problem, as the total number of
 * possible modules can be known at compile time.  This will be okay until some kind of
 * loadable modules come along.
 */

#define PKT_PIPELINE_MAX   8

typedef struct pkt_pipeline pkt_pipeline;
typedef struct pkt_pipeline_instance pkt_pipeline_instance;
typedef struct pipeline_hdr {
  struct tpacket3_hdr *pkt_pipeline_hdr;
  void                *pkt_pipeline_extra[PKT_PIPELINE_MAX];
} pkt_pipeline_hdr;

typedef struct pkt_pipeline_list {
  pkt_pipeline_hdr **pkt_list;         /* points to an array of pointers */
  unsigned int       pkt_extent;       /* provides the length that is valid */
} pkt_pipeline_list;

typedef struct pkt_pipeline_stage pkt_pipeline_stage;
struct pkt_pipeline_stage {
  const char        *pp_name;
  int              (*pp_init)(pkt_pipeline *pp, pkt_pipeline_instance *pi);
  int              (*pp_process)(pkt_pipeline *pp, pkt_pipeline_instance *pi, pkt_pipeline_list  *packlist);
};

struct pkt_pipeline_instance {
  pkt_pipeline_stage *pi_stage;
  void               *pi_stage_info;
  int                 pi_stage_num;
};

/* this is the global structure for everything */
struct pkt_pipeline {
    pcap_dumper_t         *pkt_dump;
    int                    pkt_datalink;
    pkt_pipeline_list      pkt_master_list;
    unsigned int           pkt_stage_next;   /* the stage number, must be < PKT_PIPELINE_MAX */
    pkt_pipeline_instance  pkt_stages[PKT_PIPELINE_MAX];
};


typedef struct pkt_pipeline_source pkt_pipeline_source;
struct pkt_pipeline_source {
  pkt_pipeline      ps_pipeline;
  const char       *ps_name;
  pcap_t           *ps_pcap_reader;
};

/**
 * the following are routines that setup the pkt_pipeline from a
 * a variety of sources.
 * These routines setup the pkt_pipeline, and then return it
 * so that
 */
extern pkt_pipeline_source *pktdump_inputsource(const char *file, char ebuf[PCAP_ERRBUF_SIZE]);
extern int pktdump_runpipeline(pkt_pipeline_source *);
extern int pktdump_finish(pkt_pipeline_source *);
extern struct pkt_pipeline_instance *pktdump_pipeline_add(pkt_pipeline_source *pps, pkt_pipeline_stage *ps);

extern int pktdump_print_pipeline(pkt_pipeline_source *);

extern pkt_pipeline_source *pktdump_inputkernel(const char *filter, char ebuf[PCAP_ERRBUF_SIZE]);
extern int pktdump_run_groupline(pkt_pipeline_source *pps);


/*
 * Local Variables:
 * c-basic-offset: 4
 * c-style: linux
 * End:
 */
