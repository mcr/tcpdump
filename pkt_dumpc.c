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
#include "config.h"
#include "netdissect-stdinc.h"
#include "pkt_pipeline.h"
#include "netdissect.h"
#include "print.h"

struct dumpc_pipeline_private {
    struct netdissect_options ndo;
    unsigned int pkt_num;
};

static int pkt_hexdumpc_init(pkt_pipeline *pp, pkt_pipeline_instance *pi)
{
  struct dumpc_pipeline_private *ppp = NULL;

  pi->pi_stage_info = malloc(sizeof(struct dumpc_pipeline_private));
  if(pi->pi_stage_info == NULL) {
    return -2;
  }
  ppp = pi->pi_stage_info;
  memset(ppp, 0, sizeof(struct dumpc_pipeline_private));

  /* set up some ndo options */
  ppp->ndo.ndo_tstamp_precision = PCAP_TSTAMP_PRECISION_NANO;
  ndo_set_function_pointers(&ppp->ndo);

  ppp->ndo.ndo_if_printer = get_if_printer(&ppp->ndo, pp->pkt_datalink);

  /* probably a lot more! */
  return 0;
}

static int pkt_hexdumpc_process(pkt_pipeline *pp,
                                pkt_pipeline_instance *pi,
                                pkt_pipeline_list     *packlist)
{
    int i;
    struct dumpc_pipeline_private *ppp = (struct dumpc_pipeline_private *)pi->pi_stage_info;

    for(i=0; i < packlist->pkt_extent; i++) {
        pkt_pipeline_hdr *pph = packlist->pkt_list[i];
        if(pph != NULL) {
            struct pcap_pkthdr h;
            const  u_char *bytes = ((u_char *)pph->pkt_pipeline_hdr) + (pph->pkt_pipeline_hdr->tp_mac);

            h.ts.tv_sec = pph->pkt_pipeline_hdr->tp_sec;
            h.ts.tv_usec= pph->pkt_pipeline_hdr->tp_nsec;
            h.caplen    = pph->pkt_pipeline_hdr->tp_snaplen;
            h.len       = pph->pkt_pipeline_hdr->tp_len;

            fprintf(stdout, "char *packet_%03u = {\n", ppp->pkt_num++);
            const char *ident = "        ";

            i = 0;
            while (h.caplen > 0) {
                fprintf(stdout, "0x%02x, ", bytes);
                bytes++;
		if ((i++ % 8) == 0) {
                    fprintf(stdout, "\n%s ", ident);
		}
                h.caplen--;
            }
            fprintf(stdout, "\n};\n");
        }
    }

    return 0;
}

static pkt_pipeline_stage hexdumpc_pipeline = {
    .pp_name = "hexdumpc",
    .pp_init = pkt_hexdumpc_init,
    .pp_process = pkt_hexdumpc_process,
};

int pktdump_hexdumpc_pipeline(pkt_pipeline_source *pps)
{
    pkt_pipeline_instance *ppi = NULL;

    ppi = pktdump_pipeline_add(pps, &hexdumpc_pipeline);
    if(ppi == NULL) {
        return -1;
    }

    /* return success */
    return 0;
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * c-style: linux
 * End:
 */
