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


/**
 * pkt_pipeline -- run the pipeline of data
 *
 */

#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "pkt_pipeline.h"


/**
 *
 * pktdump_pipeline_add
 * @pps -- the source to start from
 * @ps  -- the pipeline stage to add
 *
 * This function addes the given pipeline stage to the end of the source.
 */
struct pkt_pipeline_instance *pktdump_pipeline_add(pkt_pipeline_source *pps, pkt_pipeline_stage *ps)
{
    /* first allocate a pipeline stage for this stage */
    pkt_pipeline_instance *pi = NULL;
    int stage_num;

    if(pps->ps_pipeline.pkt_stage_next >= PKT_PIPELINE_MAX) {
        return NULL;
    }
    stage_num = pps->ps_pipeline.pkt_stage_next;
    pps->ps_pipeline.pkt_stage_next++;

    pi = &pps->ps_pipeline.pkt_stages[stage_num];
    pi->pi_stage_num = stage_num;
    pi->pi_stage     = ps;

    /* initialize this stage */
    if(ps->pp_init) {
        ps->pp_init(&pps->ps_pipeline, pi);
    }

    return pi;
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * c-style: linux
 * End:
 */

