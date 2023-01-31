/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */
#include <sc_internal.h>

#include <pcap/pcap.h>
#include <errno.h>
#include <string.h>


struct sc_bpf_predicate {
  pcap_t*             pcap;
  struct bpf_program  bpf;
};


static int sc_bpf_predicate_test_fn(struct sc_pkt_predicate* pred,
                                    struct sc_packet* pkt)
{
  struct sc_bpf_predicate* bp = pred->pred_private;
  struct pcap_pkthdr pkthdr;
  /* pkthdr.ts not set -- I don't think it is used */
  pkthdr.caplen = pkt->iov[0].iov_len;
  pkthdr.len = pkt->frame_len;
  return pcap_offline_filter(&bp->bpf, &pkthdr, pkt->iov[0].iov_base) != 0;
}


int sc_bpf_predicate_alloc(struct sc_pkt_predicate** pred_out,
                           struct sc_session* tg, const char* filter_str)
{
  struct sc_pkt_predicate* pred;
  SC_TRY(sc_pkt_predicate_alloc(&pred, sizeof(struct sc_bpf_predicate)));
  pred->pred_test_fn = sc_bpf_predicate_test_fn;
  struct sc_bpf_predicate* bp = pred->pred_private;
  bp->pcap = pcap_open_dead(DLT_EN10MB, 65535);
  SC_TEST(bp->pcap != NULL);
  int rc = pcap_compile(bp->pcap, &bp->bpf, filter_str,
                        /*optimize*/ 1, PCAP_NETMASK_UNKNOWN);
  if( rc == 0 ) {
    *pred_out = pred;
  }
  else {
    /* ?? fixme: free pred (but no API for that yet) */
    rc = sc_set_err(tg, EINVAL, "%s: ERROR: failed to compile '%s' because "
                    "'%s'\n", __func__, filter_str, pcap_geterr(bp->pcap));
    pcap_close(bp->pcap);
  }
  return rc;
}

/** \endcond NODOC */
