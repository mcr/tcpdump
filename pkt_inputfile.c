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
 * Written by Michael Richardson <mcr@sandelman.ca> with support
 *   from CIRALabs and Comcast Innovation.
 *
 */


/*
 * pkt_inputfile -- setup a pcap stream reader using the pkt_pipeline
 *                  with the source being a file.
 */

#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "pkt_pipeline.h"

pkt_pipeline_source *pktdump_inputsource(const char *file, char ebuf[PCAP_ERRBUF_SIZE])
{
    pkt_pipeline_source *pps = NULL;

    pps = (pkt_pipeline_source *)malloc(sizeof(*pps));
    memset(pps, 0, sizeof(*pps));

    /* first open the pcap dump file */

    pps->ps_pcap_reader = pcap_open_offline_with_tstamp_precision(file,
                                                                  PCAP_TSTAMP_PRECISION_NANO,
                                                                  ebuf);
    if(pps->ps_pcap_reader == NULL) {
        free(pps);
        return NULL;
    }

    pps->ps_pipeline.pkt_datalink = pcap_datalink(pps->ps_pcap_reader);

    return pps;
}

/*
 * there is no vector/array of packets in this interface.
 */
void pktdump_process_one(u_char *user,
                         const struct pcap_pkthdr *h,
                         const u_char *bytes)
{
    unsigned int caplen;
    unsigned char buffer1[65536+2048];
    struct tpacket3_hdr *th = (struct tpacket3_hdr *)buffer1;
    pkt_pipeline_source *pps = (pkt_pipeline_source *)user;
    pkt_pipeline_list   *ppl = &pps->ps_pipeline.pkt_master_list;
    pkt_pipeline        *pp;
    pkt_pipeline_hdr     pkt0;
    pkt_pipeline_hdr    *pkt1[1];
    unsigned int i, ret;
    memset(th, 0, sizeof(struct tpacket3_hdr));

    th->tp_mac = 2048;  /* offset to the data */
    caplen = h->caplen;
    if(caplen > 65536) caplen=65536;
    memcpy(buffer1 + 2048, bytes, caplen);
    th->tp_sec   = h->ts.tv_sec;
    th->tp_nsec  = h->ts.tv_usec;  /* not us, but nano-sec */
    th->tp_snaplen= caplen;
    th->tp_len   = h->len;
    th->tp_status = 0;

    //th.tp_net   ;
    //th.tp_next_offset;

    pkt1[0] = &pkt0;

    ppl->pkt_list   = pkt1;
    ppl->pkt_extent = 1;
    pkt1[0]->pkt_pipeline_hdr = th;
    pp = &pps->ps_pipeline;
    ret = 0;

    for(i=0; i < pp->pkt_stage_next && i<PKT_PIPELINE_MAX; i++) {
        pkt_pipeline_instance *ppi = &pp->pkt_stages[i];
        ret = 0;
        if(ppi->pi_stage && ppi->pi_stage->pp_process) {
            ret = (ppi->pi_stage->pp_process)(pp, ppi, ppl);
        }
        if(ret != 0) break;
    }

}

int pktdump_runpipeline(pkt_pipeline_source *pps)
{
    int result;

    result = pcap_dispatch(pps->ps_pcap_reader, -1,
                           pktdump_process_one, (void *)pps);

    if(result == -2) {
        return -2;
    } else if(result == -1) {
        return -1;
    } else {
        return 0;
    }
}

int pktdump_finish(pkt_pipeline_source *pps)
{
    if(pps != NULL) free(pps);
    return 1;
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * c-style: linux
 * End:
 */
