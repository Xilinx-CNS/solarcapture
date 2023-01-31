/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_VI_H__
#define __SC_VI_H__


struct sc_interface {
  struct sc_session*      if_session;
  char*                   if_name;
};


enum sc_capture_mode {
  SC_CAPTURE_MODE_UNSPECIFIED,
  SC_CAPTURE_MODE_STEAL,
  SC_CAPTURE_MODE_SNIFF,
};

enum sc_capture_point {
  SC_CAPTURE_POINT_UNSPECIFIED,
  SC_CAPTURE_POINT_INGRESS,
  SC_CAPTURE_POINT_EGRESS,
};

enum sc_vi_mode {
  SC_VI_MODE_AUTO,
  SC_VI_MODE_PACKED_STREAM,
  SC_VI_MODE_NORMAL,
};

#define SC_SNAP_UNSPECIFIED -1
#define SC_SNAP_ALL 0

typedef int (sc_vi_set_recv_node_fn)(struct sc_vi* vi, struct sc_node* node_in,
                                     const char* name_opt);

typedef int (sc_vi_add_stream_fn)(struct sc_vi* vi, struct sc_stream* s,
                                  enum sc_capture_mode capture_mode,
                                  int promiscuous);

struct sc_vi {
  struct sc_thread*           vi_thread;
  struct sc_interface*        vi_interface;
  struct sc_attr*             vi_attr;
  void*                       vi_priv;
  sc_vi_set_recv_node_fn*     vi_set_recv_node_fn;
  sc_vi_add_stream_fn*        vi_add_stream_fn;
  enum sc_capture_mode        capture_mode;
  enum sc_vi_mode             vi_mode;
  int                         promiscuous;
  char*                       capture_point;
  char*                       capture_interface;
  int                         strip_fcs;
};


struct sc_injector_node {
  struct sc_node*           node;
  struct sc_ef_vi*          vi;
  const struct sc_node_link*next_hop;
  int                       n_pkts_in;
  int                       n_pkts_out;
  int                       eos;
};


extern void sc_interface_get(struct sc_interface** intf_out,
                             struct sc_session* scs,
                             const char* interface_name);

extern void sc_interface_free(struct sc_interface*);


extern int sc_vi_add_stream__ef_vi(struct sc_vi*, struct sc_stream*,
                                   enum sc_capture_mode, int promiscuous);

extern int sc_vi_is_ef_vi(struct sc_vi* vi);


#endif  /* __SC_VI_H__ */
