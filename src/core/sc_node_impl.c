/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"


#define ni_set_err(ni, errno_code, ...)                                 \
  sc_set_err((ni)->ni_thread->session, (errno_code), __VA_ARGS__)


struct sc_args {
  const struct sc_arg* args;
  int                  n_args;
  int*                 used;
};


/* NOTE: It is possible for a node to appear in this stack more than once */
static __thread struct sc_node_impl** current_stack;
static __thread int current_stack_n;
static __thread int current_stack_i = -1;


static void current_node_push(struct sc_node_impl* ni)
{
  SC_TEST( current_stack_i >= -1 && current_stack_i < current_stack_n );
  if( current_stack_i == current_stack_n - 1 )
    SC_REALLOC(&current_stack, ++current_stack_n);
  current_stack[++current_stack_i] = ni;
}


static void current_node_pop(struct sc_node_impl* ni)
{
  SC_TEST( current_stack_i >= 0 && current_stack_i < current_stack_n &&
           current_stack[current_stack_i] == ni );
  --current_stack_i;
}


static void sc_node_set_state(struct sc_node_impl* ni,
                              enum sc_node_state state)
{
  ni->ni_state = state;
  ni->ni_stats->state = state;
}


static void __sc_node_init(struct sc_node_impl* n,
                           struct sc_thread* t, char* name,
                           const char* group_name)
{
  struct sc_session* tg = t->session;

  n->ni_node.nd_name = name;
  sc_packet_list_init(&n->ni_pkt_list);
  n->ni_thread = t;
  n->ni_id = tg->tg_nodes_n++;
  sc_dlist_init(&n->ni_dispatch_link);  /* Self-linked means not in list. */
  /* n->ni_init_args = NULL; */
  SC_REALLOC(&tg->tg_nodes, tg->tg_nodes_n);
  tg->tg_nodes[n->ni_id] = n;

  TRY(sc_stats_add_block(t, name, "sc_node_stats", "n", n->ni_id,
                         sizeof(*n->ni_stats), &n->ni_stats));
  if( group_name != NULL )
    sc_stats_add_info_str(tg, "n", n->ni_id, "group_name", group_name);
  sc_bitmask_init(&n->ni_src_pools);
  sc_bitmask_init(&n->ni_src_nodes);
  n->ni_stats->id = n->ni_id;
  n->ni_stats->thread_id = t->id;
  sc_object_impl_init(&(n->ni_obj), SC_OBJ_NODE);

  sc_node_set_state(n, SC_NODE_INITED);
}


static void __sc_node_add(struct sc_node_impl* n)
{
  struct sc_session* tg = n->ni_thread->session;
  sc_stats_set_str(n->ni_stats->node_type_name, n->ni_node.nd_type->nt_name);
  /* Ensure nul-terminated, as this field is also used as a c-string. */
  n->ni_stats->node_type_name[SC_STATS_MAX_NAME_LEN - 1] = '\0';
  sc_dlist_push_tail(&tg->tg_unpreped_nodes, &n->ni_link);
  if( current_stack_i >= 0 ) {
    struct sc_node_impl* current_node = current_stack[current_stack_i];
    n->ni_parent_node = current_node;
    sc_stats_add_info_int(tg, "n", n->ni_id, "parent_node_id",
                          current_node->ni_id);
  }
}


void sc_node_init(struct sc_node_impl* n,
                  const struct sc_node_type* node_type,
                  struct sc_thread* t, char* name, const char* group_name)
{
  __sc_node_init(n, t, name, group_name);
  n->ni_node.nd_type = node_type;
  __sc_node_add(n);
}


static int sc_node_factory_init_node(const struct sc_node_factory* factory,
                                     struct sc_node_impl* ni,
                                     const struct sc_attr* attr,
                                     const struct sc_arg* args, int n_args)
{
  struct sc_session* scs = ni->ni_thread->session;

  int used[n_args];
  memset(used, 0, sizeof(used));
  if( factory->nf_init_fn != NULL ) {
    struct sc_args the_args;
    the_args.args = args;
    the_args.n_args = n_args;
    the_args.used = used;
    ni->ni_init_args = &the_args;
    current_node_push(ni);
    int rc = factory->nf_init_fn(&(ni->ni_node), attr, factory);
    current_node_pop(ni);
    ni->ni_init_args = NULL;
    if( rc < 0 ) {
      struct sc_session_error* scs_err = sc_session_error_get(scs);
      if( scs_err == NULL )
        rc = sc_set_err(scs, -rc, "sc_node_alloc: ERROR: Init failed "
                        "(factory=%s rc=%d)\n", factory->nf_name, rc);
      else
        sc_session_error_free(scs, scs_err);
      return rc;
    }
    SC_TEST( ni->ni_node.nd_type != NULL );
  }
  int i;
  for( i = 0; i < n_args; ++i )
    if( ! used[i] ) {
      sc_warn(scs, "%s: WARNING: arg(%s) not used by factory(%s)\n",
              __func__, args[i].name, factory->nf_name);
      /* ?? todo: optional error */
    }
  return 0;
}


int sc_node_alloc(struct sc_node** node_out, const struct sc_attr* attr,
                  struct sc_thread* t, const struct sc_node_factory* factory,
                  const struct sc_arg* args, int n_args)
{
  struct sc_session* tg = t->session;

  TEST(factory->nf_node_api_ver >= 0);
  if( factory->nf_node_api_ver > SC_API_VER_MAX )
    return sc_set_err(tg, EINVAL,
                      "%s: ERROR: factory '%s' has api ver %d (max %d)\n",
                      __func__, factory->nf_name, factory->nf_node_api_ver,
                      SC_API_VER_MAX);

  TRY(sc_thread_affinity_save_and_set(t));

  struct sc_node_impl* n = sc_thread_calloc(t, sizeof(*n));
  TEST(n);
  char* name;
  if( attr->name == NULL )
    TEST(asprintf(&name, "%s(%d)", factory->nf_name, tg->tg_nodes_n) > 0);
  else
    name = strdup(attr->name);

  __sc_node_init(n, t, name, attr->group_name);

  int rc = sc_node_factory_init_node(factory, n, attr, args, n_args);
  if( rc < 0 ) {
    sc_node_set_state(n, SC_NODE_BROKEN);
    free(n->ni_node.nd_name);
    sc_thread_mfree(t, n);
    TRY(sc_thread_affinity_restore(t));
    return rc;
  }

  __sc_node_add(n);
  TRY(sc_thread_affinity_restore(t));
  *node_out = &n->ni_node;
  sc_trace(tg, "%s: name=%s type=%s thread=%s\n", __func__,
           n->ni_node.nd_name, n->ni_node.nd_type->nt_name, t->name);
  return 0;
}


int sc_node_alloc_named(struct sc_node** node_out, const struct sc_attr* attr,
                        struct sc_thread* t, const char* factory_name,
                        const char* lib_name,
                        const struct sc_arg* args, int n_args)
{
  const struct sc_node_factory* factory;
  int rc;
  rc = sc_node_factory_lookup(&factory, t->session, factory_name, lib_name);
  if( rc < 0 )
    return sc_fwd_err(t->session, NULL);
  return sc_node_alloc(node_out, attr, t, factory, args, n_args);
}


static unsigned strchrcount(const char* str, char c)
{
  unsigned n = 0;
  while( *str )
    if( *str++ == c )
      ++n;
  return n;
}


int sc_node_alloc_from_str(struct sc_node** node_out,
                           const struct sc_attr* attr,
                           struct sc_thread* thread,
                           const char* node_spec)
{
  const char* node_type;
  char *freeme, *args, *arg, *arg_iter = NULL, *val;
  int rc;

  int n_args = strchrcount(node_spec, ';') + 1;  /* may be overestimate */
  struct sc_arg sc_args[n_args];
  n_args = 0;

  freeme = strdup(node_spec);
  node_type = freeme;
  if ((args = strchr(freeme, ':')) != NULL) {
    *args++ = '\0';
    arg = sc_strtok_r(args, ';', &arg_iter);
    while (arg != NULL) {
      if ((val = strchr(arg, '=')) == NULL)
        goto bad_node_spec;
      *val++ = '\0';
      sc_args[n_args].name = arg;
      sc_args[n_args].type = SC_PARAM_STR;
      sc_args[n_args].val.str = val;
      ++n_args;
      arg = sc_strtok_r(NULL, ';', &arg_iter);
    }
  }

  rc = sc_node_alloc_named(node_out, attr, thread, node_type,
                           NULL, sc_args, n_args);
 out:
  free(freeme);
  return rc;

 bad_node_spec:
  rc = sc_set_err(sc_thread_get_session(thread), EINVAL,
                  "ERROR: %s: Bad node spec '%s'\n", __func__, node_spec);
  goto out;
}


int sc_node_init_delegate(struct sc_node* node,
                          const struct sc_attr* attr,
                          const struct sc_node_factory* factory,
                          const struct sc_arg* args, int n_args)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_session* scs = ni->ni_thread->session;

  SC_TEST( ni->ni_init_args != NULL );

  SC_TEST( factory->nf_node_api_ver >= 0 );
  if( factory->nf_node_api_ver > SC_API_VER_MAX )
    return sc_set_err(scs, EINVAL,
                      "%s: ERROR: factory '%s' requires api ver %d (max %d)\n",
                      __func__, factory->nf_name, factory->nf_node_api_ver,
                      SC_API_VER_MAX);

  if( n_args == -1 ) {
    int i;
    for( i = 0; i < ni->ni_init_args->n_args; ++i )
      ni->ni_init_args->used[i] = 1;
    args = ni->ni_init_args->args;
    n_args = ni->ni_init_args->n_args;
  }

  return sc_node_factory_init_node(factory, ni, attr, args, n_args);
}


#define BAD_STR  ((char*)(uintptr_t) 1)


struct sc_node* sc_node_get_ingress_node(struct sc_node* node, char** name)
{
  struct sc_node* orig_node = node;
  TEST(node != NULL);
  while( node->nd_type->nt_select_subnode_fn != NULL ) {
    struct sc_node* was_node = node;
    char* new_name = BAD_STR;
    current_node_push(SC_NODE_IMPL_FROM_NODE(was_node));
    node = node->nd_type->nt_select_subnode_fn(node, *name, &new_name);
    current_node_pop(SC_NODE_IMPL_FROM_NODE(was_node));
    if( node != was_node )
      sc_trace(sc_node_get_thread(orig_node)->session,
               "%s: %s/%s redirected to %s/%s\n", __func__,
               was_node->nd_name, *name, (node) ? node->nd_name:"NULL",
               (new_name == BAD_STR) ? *name : new_name);
    if( new_name != BAD_STR ) {
      free(*name);
      *name = new_name;
    }
    if( node == was_node )
      break;
    if( node == NULL ) {
      ni_set_err(SC_NODE_IMPL_FROM_NODE(was_node), EINVAL,
                 "%s: ERROR: node(%s/%s) has no ingress link '%s'\n",
                 __func__, was_node->nd_name, was_node->nd_type->nt_name,
                 *name);
      break;
    }
  }
  return node;
}


struct sc_node_link_impl* __sc_node_add_link(struct sc_node_impl* from_ni,
                                             const char* link_name,
                                             struct sc_node_impl* to_ni,
                                             char* to_name_opt)
{
  struct sc_session* scs = from_ni->ni_thread->session;
  sc_trace(scs, "%s: n%d:%s[%s] => n%d:%s\n",
           __func__, from_ni->ni_id, from_ni->ni_node.nd_name, link_name,
           to_ni ? to_ni->ni_id : -1,
           to_ni ? to_ni->ni_node.nd_name : "#sc_free");
  TEST(to_ni == NULL || from_ni->ni_thread == to_ni->ni_thread);
  struct sc_node_link_impl* l;
  TEST((l = sc_thread_calloc(from_ni->ni_thread, sizeof(*l))) != NULL);
  l->nl_public.name = strdup(link_name);
  l->nl_to_node = to_ni;
  l->nl_from_node = from_ni;
  l->nl_to_name = to_name_opt;
  /* l->nl_flags = 0; */
  sc_bitmask_init(&l->nl_pools);

  if( to_ni != NULL )
    ++(to_ni->ni_n_incoming_links);

  SC_REALLOC(&from_ni->ni_links, from_ni->ni_n_links + 1);
  from_ni->ni_links[from_ni->ni_n_links] = l;
  ++from_ni->ni_n_links;
  return l;
}


struct sc_node* sc_node_add_link_cross_thread(struct sc_thread* from_thread,
                                              struct sc_node_impl* to_ni,
                                              const char* to_name)
{
  /* Option to find and use a suitable existing mailbox. */

  struct sc_mailbox *from_mb, *to_mb;
  struct sc_attr* attr;

  assert(from_thread != to_ni->ni_thread);

  TRY(sc_attr_alloc(&attr));
  TRY(sc_mailbox_alloc(&from_mb, attr, from_thread));
  TRY(sc_mailbox_alloc(&to_mb, attr, to_ni->ni_thread));
  TRY(sc_mailbox_connect(from_mb, to_mb));
  sc_attr_free(attr);
  TRY(sc_thread_affinity_save_and_set(to_ni->ni_thread));
  sc_mailbox_set_recv(to_mb, &to_ni->ni_node, to_name);
  TRY(sc_thread_affinity_restore(to_ni->ni_thread));
  return sc_mailbox_get_send_node(from_mb);
}


int sc_node_add_link(struct sc_node* from_node, const char* link_name,
                     struct sc_node* to_node, const char* to_name_opt)
{
  struct sc_node_impl* from_ni = SC_NODE_IMPL_FROM_NODE(from_node);
  struct sc_session* tg = from_ni->ni_thread->session;
  if( from_ni->ni_state != SC_NODE_ADD_LINK )
    sc_trace(tg, "%s: n%d:%s[%s] => n%d:%s[%s]\n", __func__, from_ni->ni_id,
             from_node->nd_name, link_name,
             SC_NODE_IMPL_FROM_NODE(to_node)->ni_id,
             to_node->nd_name, to_name_opt ? to_name_opt : "");
  if( from_node->nd_type->nt_add_link_fn != NULL &&
      from_ni->ni_state == SC_NODE_INITED ) {
    sc_node_set_state(from_ni, SC_NODE_ADD_LINK);
    current_node_push(from_ni);
    int rc = from_node->nd_type->nt_add_link_fn(from_node, link_name,
                                                to_node, to_name_opt);
    current_node_pop(from_ni);
    sc_node_set_state(from_ni, SC_NODE_INITED);
    return rc;
  }

  TEST(from_ni->ni_state == SC_NODE_INITED ||
       from_ni->ni_state == SC_NODE_ADD_LINK);

  struct sc_node_impl* to_ni = SC_NODE_IMPL_FROM_NODE(to_node);
  if( from_ni->ni_thread != to_ni->ni_thread )
    to_node = sc_node_add_link_cross_thread(from_ni->ni_thread,
                                            to_ni, to_name_opt);
  char* to_name = to_name_opt ? strdup(to_name_opt) : NULL;
  to_node = sc_node_get_ingress_node(to_node, &to_name);
  if( to_node == NULL ) {
    free(to_name);
    return sc_fwd_err(tg, NULL);
  }
  to_ni = SC_NODE_IMPL_FROM_NODE(to_node);
  TEST(from_ni->ni_thread == to_ni->ni_thread);
  TEST(from_ni != to_ni);
  TEST(to_ni->ni_state == SC_NODE_INITED ||
       to_ni->ni_state == SC_NODE_ADD_LINK);

  TRY(sc_thread_affinity_save_and_set(from_ni->ni_thread));
  __sc_node_add_link(from_ni, link_name, to_ni, to_name);
  TRY(sc_thread_affinity_restore(from_ni->ni_thread));
  return 0;
}


struct sc_thread* sc_node_get_thread(const struct sc_node* node)
{
  return SC_NODE_IMPL_FROM_NODE(node)->ni_thread;
}


void sc_node_propagate_pools(struct sc_node_impl* ni,
                             const struct sc_bitmask* pools)
{
  TEST(ni->ni_n_incoming_links > ni->ni_n_incoming_links_preped);
  ++(ni->ni_n_incoming_links_preped);
  sc_bitmask_or(&ni->ni_src_pools, pools);
  char* bitmask_list = sc_bitmask_fmt(&ni->ni_src_pools);
  SC_TEST( strlen(bitmask_list) < SC_STATS_MAX_POOLS_LIST_LEN );
  strcpy(ni->ni_stats->pools_in, bitmask_list);

  if( ni->ni_state == SC_NODE_PREPED ) {
    /* To keep dispatch order correct if new links are added during prep, the
     * destination node for any new links needs to be preped after the link has
     * been added. This is only possible for free-path nodes since for other
     * nodes, all incoming links exist before prep.
     * This means that free-path nodes can get preped multiple times.
     */
    struct sc_session* tg = ni->ni_thread->session;
    SC_TEST(ni->ni_stats->is_free_path);
    ni->ni_state = SC_NODE_INITED;
    sc_dlist_push_tail(&tg->tg_unpreped_nodes, &ni->ni_link);
  }
  sc_trace(ni->ni_thread->session, "%s: node(%d,%s) incom=%d preped=%d "
           "pools=(%s)\n", __func__, ni->ni_id,
           ni->ni_node.nd_type->nt_name, ni->ni_n_incoming_links,
           ni->ni_n_incoming_links_preped, sc_bitmask_fmt(&ni->ni_src_pools));
}


int sc_node_prep(struct sc_node_impl* ni)
{
  const struct sc_node_type* node_type = ni->ni_node.nd_type;
  struct sc_session* tg = ni->ni_thread->session;
  int i, rc;

  sc_trace(tg, "%s: node(%d,%s)\n", __func__,
           ni->ni_id, ni->ni_node.nd_type->nt_name);

  TEST(ni->ni_state == SC_NODE_INITED);
  sc_node_set_state(ni, SC_NODE_PREPING);

  rc = 0;
  if( node_type->nt_prep_fn != NULL ) {
    TEST(ni->ni_n_links >= 0);
    const struct sc_node_link* hops[ni->ni_n_links];
    for( i = 0; i < ni->ni_n_links; ++i )
      hops[i] = &ni->ni_links[i]->nl_public;
    current_node_push(ni);
    rc = node_type->nt_prep_fn(&ni->ni_node, hops, ni->ni_n_links);
    current_node_pop(ni);
    if( rc != 0 )
      sc_node_fwd_error(&ni->ni_node, rc);
  }
  else if( ni->ni_n_links != 0 ) {
    sc_warn(tg, "%s: WARNING: node '%s' of type '%s' has links but no "
            "nt_prep_fn\n", __func__, ni->ni_node.nd_name, node_type->nt_name);
  }
  TEST(rc == 0 || rc < 0);
  if( rc == 0 ) {
    /* Propagate pool info through links. */
    for( i = 0; i < ni->ni_n_links; ++i ) {
      struct sc_node_link_impl* nl = ni->ni_links[i];
      if( ! ni->ni_set_forward_links )
        sc_bitmask_or(&nl->nl_pools, &ni->ni_src_pools);
      if( nl->nl_to_node == NULL )
        sc_node_link_setup_pkt_free(nl);
      sc_node_propagate_pools(nl->nl_to_node, &nl->nl_pools);
      sc_stats_add_info_nodelink(tg, ni->ni_id, nl->nl_public.name,
                                 nl->nl_to_node->ni_id, nl->nl_to_name);
    }
    ni->ni_dispatch_order = tg->tg_dispatch_order++;
    ni->ni_stats->dispatch_order = ni->ni_dispatch_order;
    ni->ni_stats->eos_left = ni->ni_n_incoming_links;
    ni->ni_stats->n_links_in = ni->ni_n_incoming_links;
    ni->ni_stats->n_links_out = ni->ni_n_links;
    sc_node_set_state(ni, SC_NODE_PREPED);
  }
  else {
    sc_node_set_state(ni, SC_NODE_INITED);
  }
  return rc;
}

#define ARG_TYPE_ERR(node, name, got, want)                             \
  ni_set_err(SC_NODE_IMPL_FROM_NODE(node), EINVAL,                      \
             "ERROR: %s: arg '%s' for node '%s' has type %s, expected %s\n", \
             __func__, name, node->nd_type->nt_name,                    \
             SC_PARAM_TYPE_NAME(got),                                   \
             SC_PARAM_TYPE_NAME(want))


int sc_node_init_get_arg_int(int* v_out, struct sc_node* node,
                             const char* name, int v_default)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_args* args = ni->ni_init_args;
  const struct sc_arg* arg;
  char dummy;
  int i;

  TEST(args != NULL);
  TEST(node->nd_type != NULL);
  *v_out = v_default;
  for( i = 0; i < args->n_args; ++i )
    if( ! strcmp((arg = &args->args[i])->name, name) ) {
      args->used[i] = 1;
      switch( arg->type ) {
      case SC_PARAM_INT:
        *v_out = arg->val.i;
        if( *v_out != arg->val.i )
          return ni_set_err(ni, EINVAL,
                            "%s: ERROR: arg(%s) for node(%s) out of range\n",
                            __func__, name, node->nd_type->nt_name);
        break;
      case SC_PARAM_STR:
        /* Allow string if can be converted to int.  This is important
         * because it is not possible for the python front-end to know what
         * type to convert arguments to.
         */
        if( sscanf(arg->val.str, "%i%c", v_out, &dummy) == 1 )
          break;
        /* else fall-through... */
      default:
        return ARG_TYPE_ERR(node, name, arg->type, SC_PARAM_INT);
      }
      sc_trace(ni->ni_thread->session, "%s: node(%s) %s=%d\n",
               __func__, node->nd_type->nt_name, name, *v_out);
      return 0;
    }
  sc_trace(ni->ni_thread->session, "%s: node(%s) %s=%d (default)\n",
           __func__, node->nd_type->nt_name, name, *v_out);
  return 1;
}


int sc_node_init_get_arg_int64(int64_t* v_out, struct sc_node* node,
                               const char* name, int64_t v_default)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_args* args = ni->ni_init_args;
  const struct sc_arg* arg;
  char dummy;
  int i;

  TEST(args != NULL);
  TEST(node->nd_type != NULL);
  *v_out = v_default;
  for( i = 0; i < args->n_args; ++i )
    if( ! strcmp((arg = &args->args[i])->name, name) ) {
      args->used[i] = 1;
      switch( arg->type ) {
      case SC_PARAM_INT:
        *v_out = arg->val.i;
        break;
      case SC_PARAM_STR:
        /* Allow string if can be converted to int.  This is important
         * because it is not possible for the python front-end to know what
         * type to convert arguments to.
         */
        if( sscanf(arg->val.str, "%"PRId64"%c", v_out, &dummy) == 1 )
          break;
        /* else fall-through... */
      default:
        return ARG_TYPE_ERR(node, name, arg->type, SC_PARAM_INT);
      }
      sc_trace(ni->ni_thread->session, "%s: node(%s) %s=%"PRId64"d\n",
               __func__, node->nd_type->nt_name, name, *v_out);
      return 0;
    }
  sc_trace(ni->ni_thread->session, "%s: node(%s) %s=%"PRId64" (default)\n",
           __func__, node->nd_type->nt_name, name, *v_out);
  return 1;
}


int sc_node_init_get_arg_str(const char** v_out, struct sc_node* node,
                             const char* name, const char* v_default)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_args* args = ni->ni_init_args;
  const struct sc_arg* arg;
  int i;

  TEST(args != NULL);
  TEST(node->nd_type != NULL);
  *v_out = v_default;
  for( i = 0; i < args->n_args; ++i )
    if( ! strcmp((arg = &args->args[i])->name, name) ) {
      args->used[i] = 1;
      switch( arg->type ) {
      case SC_PARAM_STR:
        *v_out = arg->val.str;
        break;
      default:
        /* TODO: I'd like for us to convert other arg types here.  If you
         * implement that don't forget you'll need to allocate storage for
         * the strings, and free them after nf_init_fn() returns.
         */
        return ARG_TYPE_ERR(node, name, arg->type, SC_PARAM_STR);
      }
      sc_trace(ni->ni_thread->session, "%s: node(%s) %s=%s\n",
               __func__, node->nd_type->nt_name, name, *v_out);
      return 0;
    }
  sc_trace(ni->ni_thread->session, "%s: node(%s) %s=%s (default)\n",
           __func__, node->nd_type->nt_name, name, *v_out);
  return 1;
}


int sc_node_init_get_arg_obj(struct sc_object** obj_out, struct sc_node* node,
                             const char* name, enum sc_object_type obj_type)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_args* args = ni->ni_init_args;
  const struct sc_arg* arg;
  int i;

  TEST(args != NULL);
  TEST(node->nd_type != NULL);
  for( i = 0; i < args->n_args; ++i )
    if( ! strcmp((arg = &args->args[i])->name, name) ) {
      args->used[i] = 1;
      if( arg->type != SC_PARAM_OBJ )
        return ARG_TYPE_ERR(node, name, arg->type, SC_PARAM_OBJ);
      if( obj_type != SC_OBJ_ANY && arg->val.obj->obj_type != obj_type )
        return ni_set_err(ni, EINVAL, "%s: ERROR: arg(%s) for node(%s) is "
                          "type(%d) but wanted(%d)\n", __func__, name,
                          node->nd_type->nt_name, arg->val.obj->obj_type,
                          obj_type);
      *obj_out = arg->val.obj;
      sc_trace(ni->ni_thread->session, "%s: node(%s) %s=(type %d)\n",
               __func__, node->nd_type->nt_name, name, (*obj_out)->obj_type);
      return 0;
    }
  sc_trace(ni->ni_thread->session, "%s: node(%s) %s not found\n",
           __func__, node->nd_type->nt_name, name);
  return 1;
}


static int _parse_dbl(double* v_out, const char* str)
{
  char unit, dummy;
  int n = sscanf(str, "%lf%c%c", v_out, &unit, &dummy);
  if( n == 0 || n > 2 )
    return -1;
  if( n == 2 ) {
    switch( unit ) {
    case 'G':
      *v_out *= 1000.0;
    case 'M':
      *v_out *= 1000.0;
    case 'k':
      *v_out *= 1000.0;
      break;
    default:
      return -1;
    }
  }
  return 0;
}


int sc_node_init_get_arg_dbl(double* v_out, struct sc_node* node,
                             const char* name, double v_default)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_args* args = ni->ni_init_args;
  const struct sc_arg* arg;
  int i;

  TEST(args != NULL);
  TEST(node->nd_type != NULL);
  *v_out = v_default;
  for( i = 0; i < args->n_args; ++i )
    if( ! strcmp((arg = &args->args[i])->name, name) ) {
      args->used[i] = 1;
      switch( arg->type ) {
      case SC_PARAM_DBL:
        *v_out = arg->val.dbl;
        break;
      case SC_PARAM_INT:
        *v_out = arg->val.i;
        break;
      case SC_PARAM_STR:
        /* Allow string if can be converted to dbl.  This is important
         * because it is not possible for the python front-end to know what
         * type to convert arguments to.
         */
        if( _parse_dbl(v_out, arg->val.str) == 0 )
          break;
        /* else fall-through... */
      default:
        return ARG_TYPE_ERR(node, name, arg->type, SC_PARAM_DBL);
      }
      sc_trace(ni->ni_thread->session, "%s: node(%s) %s=%lf\n",
               __func__, node->nd_type->nt_name, name, *v_out);
      return 0;
    }
  sc_trace(ni->ni_thread->session, "%s: node(%s) %s=%lf (default)\n",
           __func__, node->nd_type->nt_name, name, *v_out);
  return 1;
}


struct sc_node_link_impl*
sc_node_find_link(struct sc_node* node, const char* link_name)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_node_link_impl* nl;
  int i;

  for( i = 0; i < ni->ni_n_links; ++i )
    if( ! strcmp((nl = ni->ni_links[i])->nl_public.name, link_name) )
      return nl;
  return NULL;
}


const struct sc_node_link*
sc_node_prep_get_link(struct sc_node* node, const char* link_name)
{
  struct sc_node_link_impl* nl;
  TEST(link_name != NULL);
  if( (nl = sc_node_find_link(node, link_name)) != NULL ) {
    nl->nl_flags |= SC_NL_FOUND;
    return &nl->nl_public;
  }
  return NULL;
}


const struct sc_node_link*
sc_node_prep_get_link_or_free(struct sc_node* node, const char* link_name)
{
  const struct sc_node_link* l = NULL;
  if( link_name != NULL )
    if( (l = sc_node_prep_get_link(node, link_name)) != NULL )
      return l;
  if( link_name == NULL )
    link_name = "#sc_free";
  struct sc_node_link_impl* nl;
  nl = __sc_node_add_link(SC_NODE_IMPL_FROM_NODE(node), link_name, NULL, NULL);
  nl->nl_flags |= SC_NL_FOUND;
  return &nl->nl_public;
}


static int __sc_node_prep_get_pool(struct sc_pool** pool_out,
                                   const struct sc_attr* attr_opt,
                                   struct sc_node* node,
                                   struct sc_node_link_impl*const* links,
                                   int n_links)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_session* tg = ni->ni_thread->session;
  struct sc_attr* tmp_attr = NULL;
  struct sc_netif* netif;
  struct sc_pkt_pool* pp;
  uint64_t netifs;
  int i, netif_id;

  TEST(ni->ni_state == SC_NODE_PREPING);

  netifs = 0;
  for( i = 0; i < n_links; ++i ) {
    TEST(links[i]->nl_from_node == ni);
    if( links[i]->nl_to_node != NULL )
      netifs |= sc_topology_find_sender_netifs(links[i]->nl_to_node);
  }

  if( netifs != 0 ) {
    netif_id = ffsll(netifs) - 1;
    if( (1llu << netif_id) == netifs )
      netif = tg->tg_netifs[netif_id];
    else
      netif = NULL;
  }
  else {
    /* Packets aren't going to reach any netif.
     *
     * ?? TODO: Would be nice to have option to use a separate pool here.
     * Seems a shame to waste DMA-mapped packet buffers if they're not
     * going to be used for DMA.
     */
    netif = NULL;
  }

  if( attr_opt == NULL ) {
    TRY(sc_attr_alloc(&tmp_attr));
    attr_opt = tmp_attr;
  }

  /* This will give us a pool that may or may not be mapped into all of the
   * interfaces that are reachable.  We'll map the pool into any missing
   * interfaces in sc_injector_node_prep().
   */
  sc_thread_get_pool(ni->ni_thread, attr_opt, netif, &pp);
  sc_pkt_pool_request_bufs(pp, attr_opt);

  sc_trace(tg, "%s: n%d:%s p%d fill=%"PRId64"\n", __func__,
           ni->ni_id, node->nd_name, pp->pp_id, attr_opt->n_bufs_tx);

  for( i = 0; i < n_links; ++i ) {
    sc_bitmask_set(&links[i]->nl_pools, pp->pp_id);
    sc_trace(tg, "%s: node=%s link=%s pools=(%s)\n", __func__,
             node->nd_name, links[i]->nl_public.name, sc_bitmask_fmt(&links[i]->nl_pools));
  }
  sc_stats_add_info_int_list(tg, "n", ni->ni_id, "pools", pp->pp_id);
  *pool_out = &(pp->pp_public);

  if( tmp_attr != NULL )
    sc_attr_free(tmp_attr);
  return 0;
}


int sc_node_prep_get_pool(struct sc_pool** pool_out,
                          const struct sc_attr* attr_opt, struct sc_node* node,
                          const struct sc_node_link*const* links_in,
                          int n_links_in)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  TEST(n_links_in <= ni->ni_n_links);
  int i, n_links = n_links_in ? n_links_in : ni->ni_n_links;
  struct sc_node_link_impl* links_storage[n_links];
  struct sc_node_link_impl** links;
  if( n_links_in ) {
    links = links_storage;
    for( i = 0; i < n_links; ++i )
      links[i] = SC_NODE_LINK_IMPL_FROM_NODE_LINK(links_in[i]);
  }
  else {
    links = ni->ni_links;
  }
  return __sc_node_prep_get_pool(pool_out, attr_opt, node, links, n_links);
}


int sc_node_prep_check_links(struct sc_node* node)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_node_link_impl* nl;
  int i, rc = 0;

  for( i = 0; i < ni->ni_n_links; ++i )
    if( ((nl = ni->ni_links[i])->nl_flags & SC_NL_FOUND) == 0 )
      return ni_set_err(ni, EINVAL,
                        "%s: ERROR: node(%s) link(%s) not used\n",
                        __func__, node->nd_name, nl->nl_public.name);
  return rc;
}


void sc_node_prep_does_not_forward(struct sc_node* node)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  SC_TEST( ni->ni_state == SC_NODE_PREPING );
  ni->ni_set_forward_links = 1;
}


void sc_node_prep_link_forwards_from_node(struct sc_node* node,
                                          const struct sc_node_link* link,
                                          struct sc_node* from_node)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  SC_TEST( ni->ni_state == SC_NODE_PREPING );
  struct sc_node_link_impl* nl = SC_NODE_LINK_IMPL_FROM_NODE_LINK(link);
  SC_TEST( nl->nl_from_node == ni );
  struct sc_node_impl* from_ni = SC_NODE_IMPL_FROM_NODE(from_node);
  SC_TEST( from_node == node || from_ni->ni_state == SC_NODE_PREPED );
  sc_bitmask_or(&(nl->nl_pools), &(from_ni->ni_src_pools));
}


#undef sc_forward
#undef sc_forward_list


void sc_forward_list2(const struct sc_node_link* hop,
                      struct sc_packet_list* pl)
{
  struct sc_node_link_impl* link = SC_NODE_LINK_IMPL_FROM_NODE_LINK(hop);
  struct sc_node_impl* from_ni = link->nl_from_node;
  struct sc_node_impl* to_ni = link->nl_to_node;

  (void) from_ni;
  sc_tracefp(from_ni->ni_thread->session, "%s: n%d:%s/%s => n%d:%s "
             "num_pkts=%d\n", __func__, from_ni->ni_id,
             from_ni->ni_node.nd_name, hop->name, to_ni->ni_id,
             to_ni->ni_node.nd_name, pl->num_pkts);
  assert(from_ni->ni_state == SC_NODE_PREPED);
  assert((link->nl_flags & SC_NL_EOS) == 0);
  assert(to_ni->ni_dispatch_order > from_ni->ni_dispatch_order);
  sc_validate_list_path(from_ni->ni_thread->session, pl, &link->nl_pools,
                        from_ni->ni_node.nd_name, hop->name);
  assert(!sc_packet_list_is_empty(pl));
  NODE_STATS(from_ni->ni_stats->pkts_out += pl->num_pkts);

  sc_packet_list_append_list(&to_ni->ni_pkt_list, pl);
  sc_node_need_dispatch(to_ni);
}


#ifndef NDEBUG
void __sc_forward_list(struct sc_node* node, const struct sc_node_link* hop,
                       struct sc_packet_list* pl)
{
  sc_packet_list_finalise(pl);
  sc_forward_list(node, hop, pl);
}


void __sc_forward_list2(const struct sc_node_link* hop,
                        struct sc_packet_list* pl)
{
  sc_packet_list_finalise(pl);
  sc_forward_list2(hop, pl);
}
#endif


void sc_forward2(const struct sc_node_link* hop, struct sc_packet* pkt)
{
  struct sc_node_link_impl* link = SC_NODE_LINK_IMPL_FROM_NODE_LINK(hop);
  struct sc_node_impl* from_ni = link->nl_from_node;
  struct sc_node_impl* to_ni = link->nl_to_node;

  (void) from_ni;
  sc_tracefp(from_ni->ni_thread->session, "%s: n%d:%s/%s => n%d:%s\n",
             __func__, from_ni->ni_id, from_ni->ni_node.nd_name, hop->name,
             to_ni->ni_id, to_ni->ni_node.nd_name);
  assert(from_ni->ni_state == SC_NODE_PREPED);
  assert((link->nl_flags & SC_NL_EOS) == 0);
  assert(to_ni->ni_dispatch_order > from_ni->ni_dispatch_order);
  sc_validate_packet_path(from_ni->ni_thread->session, pkt, &link->nl_pools,
                          from_ni->ni_node.nd_name, hop->name);
  NODE_STATS(++(from_ni->ni_stats->pkts_out));

  __sc_packet_list_append(&to_ni->ni_pkt_list, pkt);
  sc_node_need_dispatch(to_ni);
}


void sc_forward_list(struct sc_node* node, const struct sc_node_link* hop,
                     struct sc_packet_list* pl)
{
  assert( &(SC_NODE_LINK_IMPL_FROM_NODE_LINK(hop)->nl_from_node->ni_node)
          == node );
  sc_forward_list2(hop, pl);
}


void sc_forward(struct sc_node* node, const struct sc_node_link* hop,
                struct sc_packet* pkt)
{
  assert( &(SC_NODE_LINK_IMPL_FROM_NODE_LINK(hop)->nl_from_node->ni_node)
          == node );
  sc_forward2(hop, pkt);
}


int sc_node_type_alloc(struct sc_node_type** nt_out,
                       const struct sc_attr* attr_opt,
                       const struct sc_node_factory* factory)
{
  struct sc_node_type* nt = calloc(1, sizeof(*nt));
  TEST(nt != NULL);
  nt->nt_name = strdup(factory->nf_name);
  *nt_out = nt;
  return 0;
}


#if 0  /* ?? purge me: unused */
void sc_node_free_to_pools(const struct sc_node_impl* ni,
                           bool remote, struct sc_bitmask* pools)
{
  /* Return the set of pools that this node can free to.  If [remote] is
   * true, then we return only pools in different threads from the node.
   * Otherwise we return all pools.
   *
   * This function only returns the correct result after the node is preped
   * and before the free-paths have been setup.
   */
  struct sc_session* tg = ni->ni_thread->session;
  struct sc_node_link_impl* nl;
  struct sc_pkt_pool* pp;
  int nl_id, pp_id = -1;

  for( nl_id = 0; nl_id < ni->ni_n_links; ++nl_id )
    if( (nl = ni->ni_links[nl_id])->nl_to_node == NULL ) {
      int i;
      for( i = 0; i < nl->nl_pools.bm_num_masks; i++ ) {
        pp_id = ffsll(nl->nl_pools.bm_masks[i]) - 1;
        if( pp_id >= 0 ) {
          /* At the moment a link can only free to a single pool. */
          TEST(nl->nl_pools.bm_masks[i] == (1llu << pp_id));
          pp_id = pp_id + (i * sizeof(uint64_t));
          break;
        }
      }
      TEST(pp_id >= 0);
      TEST(pp_id < tg->tg_pkt_pools_n);
      pp = tg->tg_pkt_pools[pp_id];
      if( ! remote || pp->pp_thread != ni->ni_thread )
        sc_bitmask_set(pools, pp_id);
    }
}
#endif


static void __sc_node_end_of_stream(struct sc_callback* cb, void* event_info)
{
  struct sc_node_impl* ni = cb->cb_private;
  struct sc_session* tg = ni->ni_thread->session;
  sc_trace(tg, "%s: %d:%s\n", __func__, ni->ni_id, ni->ni_node.nd_name);
  SC_TEST(sc_packet_list_is_empty(&ni->ni_pkt_list));
  if( ni->ni_node.nd_type->nt_end_of_stream_fn != NULL )
    ni->ni_node.nd_type->nt_end_of_stream_fn(&ni->ni_node);
  sc_callback_free(cb);
}


void sc_node_end_of_stream(struct sc_node_impl* ni)
{
  SC_TEST(ni->ni_n_incoming_links_eos < ni->ni_n_incoming_links);
  sc_trace(ni->ni_thread->session, "%s: %s (n_eos=%d n_links=%d)\n",
           __func__, ni->ni_node.nd_name,
           ni->ni_n_incoming_links_eos + 1, ni->ni_n_incoming_links);
  if( ++(ni->ni_n_incoming_links_eos) == ni->ni_n_incoming_links ) {
    struct sc_callback* cb;
    SC_TRY( sc_callback_alloc2(&cb, NULL, ni->ni_thread, NULL) );
    cb->cb_private = ni;
    cb->cb_handler_fn = __sc_node_end_of_stream;
    if( sc_packet_list_is_empty(&ni->ni_pkt_list) )
      sc_callback_at_safe_time(cb);
    else
      /* Defer end-of-stream until next time around the polling loop.
       * Necessary to ensure queued packets are pushed into the node first.
       * (NB. This requires that thread poll loop pushes packets between
       * nodes immediately before handling timers).
       */
      sc_timer_expire_after_ns(cb, 1);
  }
  ni->ni_stats->eos_left =
    ni->ni_n_incoming_links - ni->ni_n_incoming_links_eos;
}


#undef sc_node_link_end_of_stream


void sc_node_link_end_of_stream2(const struct sc_node_link* link)
{
  struct sc_node_link_impl* nl = SC_NODE_LINK_IMPL_FROM_NODE_LINK(link);
  struct sc_node_impl* to_ni = nl->nl_to_node;
  struct sc_session* tg = to_ni->ni_thread->session;
  if( (nl->nl_flags & SC_NL_EOS) == 0 ) {
    sc_trace(tg, "%s: %s/%s => %s\n", __func__,
             nl->nl_from_node->ni_node.nd_name,
             link->name, to_ni->ni_node.nd_name);
    nl->nl_flags |= SC_NL_EOS;
    SC_TEST(to_ni->ni_n_incoming_links_eos < to_ni->ni_n_incoming_links);
    sc_node_end_of_stream(to_ni);
  }
}


void sc_node_link_end_of_stream(struct sc_node* from_node,
                                const struct sc_node_link* link)
{
  struct sc_node_link_impl* nl = SC_NODE_LINK_IMPL_FROM_NODE_LINK(link);
  SC_TEST(from_node == &(nl->nl_from_node->ni_node));
  sc_node_link_end_of_stream2(link);
}


int sc_node_export_state(struct sc_node* node, const char* type_name,
                         int size, void* pp_area)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  TRY(sc_stats_add_block(ni->ni_thread, node->nd_name, type_name,
                         "n", ni->ni_id, size, pp_area));
  return 0;
}


void sc_node_add_info_str(struct sc_node* node,
                          const char* field_name, const char* field_val)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  sc_stats_add_info_str(ni->ni_thread->session, "n", ni->ni_id,
                        field_name, field_val);
}


void sc_node_add_info_int(struct sc_node* node,
                          const char* field_name, int64_t field_val)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  sc_stats_add_info_int(ni->ni_thread->session, "n", ni->ni_id,
                        field_name, field_val);
}


bool sc_node_subnodes_are_preped(struct sc_node_impl* ni)
{
  struct sc_session* scs = ni->ni_thread->session;
  int i;
  for( i = 0; i < scs->tg_nodes_n; ++i )
    if( scs->tg_nodes[i]->ni_parent_node == ni &&
        scs->tg_nodes[i]->ni_state != SC_NODE_PREPED &&
        ! scs->tg_nodes[i]->ni_reachable_from_ancestor )
      return false;
  return true;
}


struct sc_object* sc_node_to_object(struct sc_node* node)
{
  if( node == NULL )
    return NULL;
  return &(SC_NODE_IMPL_FROM_NODE(node)->ni_obj.obj_public);
}


struct sc_node* sc_node_from_object(struct sc_object* obj)
{
  if( obj == NULL || obj->obj_type != SC_OBJ_NODE )
    return NULL;
  struct sc_node_impl* ni;
  ni = SC_CONTAINER(struct sc_node_impl, ni_obj.obj_public, obj);
  return &(ni->ni_node);
}
