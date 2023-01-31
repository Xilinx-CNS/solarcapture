/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */
#ifndef __SC_WRITER_H__
#define __SC_WRITER_H__


enum on_error {
  ON_ERROR_EXIT,
  ON_ERROR_ABORT,
  ON_ERROR_MESSAGE,
  ON_ERROR_SILENT,
};

/* This is set to the same as tcpdump (4.5.1) */
#define MAX_SNAPLEN 262144

static inline int on_error_from_str(const char* str, enum on_error* on_error_out)
{
  if( ! strcasecmp(str, "exit") ) {
    *on_error_out = ON_ERROR_EXIT;
    return 1;
  }
  if( ! strcasecmp(str, "abort") ) {
    *on_error_out = ON_ERROR_ABORT;
    return 1;
  }
  if( ! strcasecmp(str, "message") ) {
    *on_error_out = ON_ERROR_MESSAGE;
    return 1;
  }
  if( ! strcasecmp(str, "silent") ) {
    *on_error_out = ON_ERROR_SILENT;
    return 1;
  }
  return 0;
}

static inline int ts_type_from_str(const char* str, enum ts_type* ts_type_out)
{
  if( ! strcasecmp(str, "pcap") ) {
    *ts_type_out = ts_micro;
    return 1;
  }
  if( ! strcasecmp(str, "pcap-ns") ) {
    *ts_type_out = ts_nano;
    return 1;
  }
  return 0;
}

static inline int sc_pcap_filename(char* buf, int buf_len, const char* template_in,
                             bool timed, bool indexed,
                             struct timespec ts, int index)
{
  char tmpl[buf_len];
  if( indexed ) {
    const char* needle = "$i";
    const char* p = strstr(template_in, needle);
    if( p ) {
      if( snprintf(tmpl, buf_len, "%.*s%d%s", (int)(p-template_in), template_in,
            index, p + strlen(needle)) == buf_len )
        return -1;
    }
    else {
      if( snprintf(tmpl, buf_len, "%s%d", template_in, index) == buf_len )
        return -1;
    }
  }
  else {
    /*template_in can have valid escape characters so must use %s*/
    if( snprintf(tmpl, buf_len, "%s", template_in) == buf_len )
      return -1;
  }

  if( timed ) {
    struct tm tm;
    if( strftime(buf, buf_len,
                    tmpl, localtime_r(&ts.tv_sec, &tm)) == 0 )
      return -1;
  }
  else {
    if( snprintf(buf, buf_len, "%s", tmpl) == buf_len )
      return -1;
  }
  return 0;
}

struct sc_pcap_packer_state;

int sc_perf_writer_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory);

void sc_pcap_packer_set_file_byte_count(struct sc_node* packed_node,
                                        uint64_t file_byte_count);

void sc_pcap_packer_redirect_eos(struct sc_node* packed_node,
                                 struct sc_node* eos_fwd);

#endif  /* __SC_WRITER_H__ */
/** \endcond NODOC */
