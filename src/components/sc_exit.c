/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_exit}
 *
 * \brief Node that causes the process to exit when a condition is met.
 *
 * \nodedetails
 * By default this node causes the process to exit when all sc_exit nodes
 * in the process have received the end-of-stream signal on their inputs.
 * Typically sc_exit nodes are placed at the end of a pipeline so that the
 * process exits after all packet processing is complete.
 *
 * Each sc_exit node has one or more "exit conditions", set by the
 * end_of_stream and predicate arguments.  Each sc_exit node also has a
 * scope.  When all of the sc_exit nodes in a scope detect their exit
 * condition, the "exit action" is invoked.  The scope argument may take
 * the following values:
 *
 *   * process: Includes all sc_exit nodes in the same process.
 *   * session: Includes all sc_exit nodes in the same session.
 *   * none: Each sc_exit node has its own scope.
 *
 * If the session was started with sc_session_run(), then the default
 * action is to call sc_session_stop() so that the sc_session_run() call
 * returns.  Otherwise the default action is to exit the process by calling
 * exit().  (NB. It is important to ensure that the application cannot also
 * call exit(), because exit() is not thread safe).
 *
 * Input packets are forwarded to the output unmodified.
 *
 * \nodeargs
 * Argument        | Optional? | Default | Type           | Description
 * --------------- | --------- | ------- | -------------- | --------------------------------------------------------------------------------------------
 * action          | Yes       | (1)     | ::SC_PARAM_STR | Action to take when exit condition met.  One of: exit, stop.
 * end_of_stream   | Yes       | 1       | ::SC_PARAM_INT | Exit condition is met when end-of-stream signal is received.
 * scope           | Yes       | process | ::SC_PARAM_STR | See description.  May be process, session or none.
 * predicate       | Yes       |         | ::SC_PARAM_OBJ | Predicate is invoked on each input packet.  Exit condition is met when it returns true.
 *
 * (1) See above for a description of the default action.
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


struct ref_count {
  int                refs;
  struct sc_session* session;
  struct sc_dlist    link;
};


enum action {
  ACT_DEFAULT,
  ACT_EXIT,
  ACT_STOP,
};


static pthread_mutex_t   mutex = PTHREAD_MUTEX_INITIALIZER;
static struct sc_dlist   session_refs;
static struct ref_count* process_refs;


struct sc_exit_state {
  struct sc_node*            node;
  const struct sc_node_link* next_hop;
  struct sc_pkt_predicate*   predicate;
  int                        on_eos;
  int                        exit_code;
  struct ref_count*          refs;
  enum action                action;
};


static void exit_condition_met(struct sc_exit_state* st)
{
  pthread_mutex_lock(&mutex);
  assert( st->refs->refs > 0 );
  if( --(st->refs->refs) == 0 ) {
    if( st->action == ACT_DEFAULT ) {
      struct sc_thread* thread = sc_node_get_thread(st->node);
      st->action = thread->session->tg_run_invoked ? ACT_STOP : ACT_EXIT;
    }
    switch( st->action ) {
    case ACT_EXIT:
      /* NB. exit() is not thread safe, so it is important to ensure that
       * other threads cannot invoke exit() concurrently, hence we do this
       * inside the lock.  (We can't protect against exit() being called by
       * other code -- the application should ensure that).
       */
      exit(st->exit_code);
      break;
    case ACT_STOP:
      sc_session_stop(sc_node_get_thread(st->node)->session, st->exit_code);
      break;
    default:
      SC_TEST( 0 );
      break;
    }
  }
  pthread_mutex_unlock(&mutex);
}


static void sc_exit_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_exit_state* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  if( st->predicate )
    for( next = pl->head; (pkt = next) && ((next = next->next), 1); )
      if( st->predicate->pred_test_fn(st->predicate, pkt) )
        exit_condition_met(st);

  sc_forward_list(node, st->next_hop, pl);
}


static void sc_exit_end_of_stream(struct sc_node* node)
{
  struct sc_exit_state* st = node->nd_private;
  if( st->on_eos )
    exit_condition_met(st);
  sc_node_link_end_of_stream(node, st->next_hop);
}


static int sc_exit_prep(struct sc_node* node,
                          const struct sc_node_link*const* links, int n_links)
{
  struct sc_exit_state* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static struct ref_count* mk_refs(struct sc_session* scs)
{
  struct ref_count* rc = malloc(sizeof(struct ref_count));
  rc->session = scs;
  rc->refs = 1;
  return rc;
}


static int get_refs(struct sc_exit_state* st, struct sc_session* scs,
                    const char* scope)
{
  pthread_mutex_lock(&mutex);

  if( scope == NULL || ! strcmp(scope, "process") ) {
    if( process_refs == NULL )
      process_refs = mk_refs(NULL);
    else
      ++(process_refs->refs);
    st->refs = process_refs;
  }
  else if( ! strcmp(scope, "session") ) {
    if( session_refs.next == NULL )
      sc_dlist_init(&session_refs);
    struct ref_count* rc;
    SC_DLIST_FOR_EACH_OBJ(&session_refs, rc, link)
      if( rc->session == scs ) {
        st->refs = rc;
        ++(rc->refs);
        goto out;
      }
    st->refs = mk_refs(scs);
    sc_dlist_push_tail(&session_refs, &(st->refs->link));
  }
  else if( ! strcmp(scope, "none") ) {
    st->refs = mk_refs(NULL);
  }
  else {
    return -1;
  }

 out:
  pthread_mutex_unlock(&mutex);
  return 0;
}


static int sc_exit_init(struct sc_node* node, const struct sc_attr* attr,
                        const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_exit_pkts;
    nt->nt_prep_fn = sc_exit_prep;
    nt->nt_end_of_stream_fn = sc_exit_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_thread* thread = sc_node_get_thread(node);
  struct sc_exit_state* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  st->node = node;

  if( sc_node_init_get_arg_int(&st->on_eos, node, "end_of_stream", 1) < 0 ||
      sc_node_init_get_arg_int(&st->exit_code, node, "exit_code", 0)  < 0  )
    goto error;

  const char* action;
  if( sc_node_init_get_arg_str(&action, node, "mode", "default") < 0 )
    goto error;
  if( ! strcmp(action, "default") ) {
    st->action = ACT_DEFAULT;
  }
  else if( ! strcmp(action, "exit") ) {
    st->action = ACT_EXIT;
  }
  else if( ! strcmp(action, "stop") ) {
    st->action = ACT_STOP;
  }
  else {
    sc_node_set_error(node, EINVAL,
                      "sc_exit: ERROR: bad action '%s'\n", action);
    goto error;
  }

  const char* scope;
  if( sc_node_init_get_arg_str(&scope, node, "scope", NULL) < 0 )
    goto error;
  if( get_refs(st, sc_thread_get_session(thread), scope) < 0 ) {
    sc_node_set_error(node, EINVAL,
                      "sc_exit: ERROR: bad scope '%s'\n", scope);
    goto error;
  }

  struct sc_object* obj;
  int rc;
  rc = sc_node_init_get_arg_obj(&obj, node, "predicate", SC_OBJ_PKT_PREDICATE);
  if( rc == 0 )
    st->predicate = sc_pkt_predicate_from_object(obj);
  else if( rc < 0 )
    goto error;

  return 0;

 error:
  sc_thread_mfree(thread, st);
  return -1;
}


const struct sc_node_factory sc_exit_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_exit",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_exit_init,
};

/** \endcond NODOC */
