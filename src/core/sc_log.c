/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"


static void sc_logv(struct sc_session* tg, const char* fmt, va_list va)
{
  vfprintf(stderr, fmt, va);
}


static void __sc_logv(struct sc_session* tg, enum sc_log_level ll,
                      const char* fmt, va_list va)
{
  if( ll <= tg->tg_log_level )
    vfprintf(stderr, fmt, va);
}


void sc_log(struct sc_session* tg, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  sc_logv(tg, fmt, va);
  va_end(va);
}


void sc_err(struct sc_session* tg, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  __sc_logv(tg, SC_LL_ERR, fmt, va);
  va_end(va);
}


void sc_errv(struct sc_session* tg, const char* fmt, va_list args)
{
  __sc_logv(tg, SC_LL_ERR, fmt, args);
}


void sc_warn(struct sc_session* tg, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  __sc_logv(tg, SC_LL_WARN, fmt, va);
  va_end(va);
}


void sc_info(struct sc_session* tg, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  __sc_logv(tg, SC_LL_INFO, fmt, va);
  va_end(va);
}


void sc_trace(struct sc_session* tg, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  __sc_logv(tg, SC_LL_TRACE, fmt, va);
  va_end(va);
}


#ifndef NDEBUG
void sc_tracefp(struct sc_session* tg, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  __sc_logv(tg, SC_LL_TRACEFP, fmt, va);
  va_end(va);
}
#endif


static int __sc_set_err_v(struct sc_session* tg,
                          const char* file, int line,
                          const char* func, int errno_code,
                          const char* fmt, va_list va, int now)
{
  if( now )
    sc_err(tg, "ERROR: errno=%d from %s:%d in %s():\n",
           errno_code, file, line, func);
  free(tg->tg_err_msg);
  int rc = vasprintf(&tg->tg_err_msg, fmt, va);
  if( rc <= 0 ) {
    fprintf(stderr, "%s: ERROR: vasprintf(\"%s\") failed\n", __func__, fmt);
    fprintf(stderr, "%s: ERROR: from %s:%d %s()\n", __func__, file, line,func);
    tg->tg_err_msg = strdup(fmt);
  }
  if( now )
    sc_err(tg, "%s", tg->tg_err_msg);
  tg->tg_err_func = func;
  tg->tg_err_file = file;
  tg->tg_err_line = line;
  tg->tg_err_errno = errno_code;
  return -1;
}


int __sc_set_err(struct sc_session* tg, const char* file, int line,
                 const char* func, int errno_code, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  int rc = __sc_set_err_v(tg, file, line, func, errno_code, fmt, va, 1);
  va_end(va);
  return rc;
}


int __sc_store_err(struct sc_session* tg, const char* file, int line,
                   const char* func, int errno_code, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  int rc = __sc_set_err_v(tg, file, line, func, errno_code, fmt, va, 0);
  va_end(va);
  return rc;
}


int sc_commit_err(struct sc_session* tg)
{
  sc_err(tg, "ERROR: errno=%d from %s:%d in %s():\n",
         tg->tg_err_errno, tg->tg_err_file, tg->tg_err_line, tg->tg_err_func);
  sc_err(tg, "%s", tg->tg_err_msg);
  return -1;
}


void sc_undo_err(struct sc_session* tg)
{
  free(tg->tg_err_msg);
  tg->tg_err_msg = NULL;
}


static int __sc_fwd_err_v(struct sc_session* tg,
                          const char* file, int line,
                          const char* func, const char* fmt, va_list va)
{
  sc_err(tg, "ERROR: VIA %s:%d in %s():\n", file, line, func);
  if( fmt != NULL )
    __sc_logv(tg, SC_LL_ERR, fmt, va);
  return -1;
}


int __sc_fwd_err(struct sc_session* tg, const char* file, int line,
                 const char* func, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  int rc = __sc_fwd_err_v(tg, file, line, func, fmt, va);
  va_end(va);
  return rc;
}


int __sc_node_set_error(struct sc_node* node, const char* file, int line,
                        const char* func, int errno_code, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  int rc = __sc_node_set_errorv(node, file, line, func, errno_code, fmt, va);
  va_end(va);
  return rc;
}


int __sc_node_set_errorv(struct sc_node* node, const char* file, int line,
                         const char* func, int errno_code,
                         const char* fmt, va_list args)
{
  /* ?? todo: add info about what node propagated the error */
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  int rc = __sc_set_err_v(ni->ni_thread->session,
                          file, line, func, errno_code, fmt, args, 1);
  return rc;
}


int __sc_node_fwd_error(struct sc_node* node, const char* file,
                        int line, const char* func, int rc)
{
  struct sc_session* tg =
    SC_NODE_IMPL_FROM_NODE(node)->ni_thread->session;
  __sc_fwd_err(tg, file, line, func, "ERROR: FROM: node=%s type=%s\n",
               node->nd_name, node->nd_type->nt_name);
  if( tg->tg_err_msg == NULL )
    sc_err(tg, "%s: ERROR: node=%s type=%s did not call sc_node_set_error()\n",
           __func__, node->nd_name, node->nd_type->nt_name);
  return rc;
}
