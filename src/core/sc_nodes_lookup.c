/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"

#include <dlfcn.h>
#include <sc_internal/builtin_nodes.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>


static int file_exists(const char* fname)
{
  struct stat sbuf;
  return stat(fname, &sbuf) == 0;
}


static const struct sc_node_factory*
  sc_node_factory_try_open(struct sc_session* tg, const char* libpath,
                           const char* node_name)
{
  if( ! file_exists(libpath) ) {
    sc_trace(tg, "%s: stat(%s) => %s\n", __func__, libpath, strerror(errno));
    return NULL;
  }
  void* lib = dlopen(libpath, RTLD_NOW);
  sc_trace(tg, "%s: dlopen(%s) => %s\n", __func__, libpath,
           lib ? "OK" : dlerror());
  if( lib == NULL )
    return NULL;

  struct sc_node_factory* factory;
  char node_name_scnf[strlen(node_name) + 20];
  sprintf(node_name_scnf, "%s_sc_node_factory", node_name);
  if( (factory = dlsym(lib, node_name_scnf)) != NULL )
    return factory;
  dlclose(lib);
  sc_trace(tg, "%s: did not find %s\n", __func__, node_name_scnf);
  return NULL;
}


/* NB. This has not been tested on any Debian-derived distros. We need to do
 * this to extend support to them.
 */
#define PATH_FMT_32  \
  ".:%s%s/usr/lib/solar_capture/site-nodes:/usr/lib/i386-linux-gnu/solar_capture/site-nodes:/usr/lib/solar_capture/nodes:/usr/lib/i386-linux-gnu/solar_capture/nodes"
#define PATH_FMT_64  \
  ".:%s%s/usr/lib64/solar_capture/site-nodes:/usr/lib/x86_64-linux-gnu/solar_capture/site-nodes:/usr/lib64/solar_capture/nodes:/usr/lib/x86_64-linux-gnu/solar_capture/nodes"


static const struct sc_node_factory*
  sc_node_factory_search(struct sc_session* tg, const char* lib_name,
                         const char* node_name, const char* env_path)
{
  const struct sc_node_factory* factory;

  if( strchr(lib_name, '/') != NULL )
    /* We've been provided an explicit path to the library file. */
    return sc_node_factory_try_open(tg, lib_name, node_name);

  const char* path_fmt;
  path_fmt = (sizeof(void*) == 8) ? PATH_FMT_64 : PATH_FMT_32;
  char path[(env_path ? strlen(env_path) : 0) + strlen(path_fmt)];
  sprintf(path, path_fmt, env_path ? env_path:"", env_path ? ":":"");

  char lib_path[strlen(path) + strlen(lib_name)];
  char* saveptr = NULL;
  char* dir = strtok_r(path, ":", &saveptr);
  do {
    /* We accept "lib_name" or "lib_name.so". */
    if( strcmp(".so", lib_name + strlen(lib_name) - 3) == 0 )
      sprintf(lib_path, "%s/%s", dir, lib_name);
    else
      sprintf(lib_path, "%s/%s.so", dir, lib_name);
    factory = sc_node_factory_try_open(tg, lib_path, node_name);
  } while( factory == NULL && (dir = strtok_r(NULL, ":", &saveptr)) );

  return factory;
}


struct builtin_node_factory {
  const char* name;
  const struct sc_node_factory* node_factory;
};


#define NF(name)                                           \
  { #name, &name##_sc_node_factory }


static const struct builtin_node_factory builtin_node_factories[] = {
  NF(sc_pcap_packer),
  NF(sc_ps_to_ps_packer),
  NF(sc_reader),
  NF(sc_injector),
  NF(sc_filter),
  NF(sc_tap),
  NF(sc_fd_reader),
  NF(sc_fd_writer),
  NF(sc_stopcock),
  NF(sc_signal_vi),
  NF(sc_line_reader),
  NF(sc_tracer),
  NF(sc_exit),
  NF(sc_merge_sorter),
  NF(sc_rate_monitor),
  NF(sc_snap),
  NF(sc_sim_work),
  NF(sc_batch_limiter),
  NF(sc_no_op),
  NF(sc_pool_forwarder),
  NF(sc_range_filter),
  NF(sc_timestamp_filter),
  NF(sc_append_to_list),
  NF(sc_delay_line),
  NF(sc_strip_vlan),
  NF(sc_pktgen),
  NF(sc_subnode_helper),
  NF(sc_ps_packer),
  NF(sc_ps_unpacker),
  NF(sc_vi_node),
  NF(sc_rr_spreader),
  NF(sc_rr_gather),
  NF(sc_token_bucket_shaper),
  NF(sc_cpacket_encap),
  NF(sc_pass_n),
  NF(sc_wrap_undo),
  NF(sc_io_demux),
  NF(sc_tuntap),

  NF(sc_block_writer),

  NF(sc_flow_balancer),
  NF(sc_shm_import),
  NF(sc_shm_export),
  NF(sc_shm_broadcast),
  NF(sc_tunnel),

  NF(sc_writer),
  NF(sc_arista_ts),
  NF(sc_cpacket_ts),
  NF(sc_ts_adjust),
  NF(sc_pacer),
  NF(sc_rt_pacer),
  NF(sc_repeater),
  NF(sc_vss),
};

#define N_BUILTIN_NODE_FACTORIES                                        \
  (sizeof(builtin_node_factories) / sizeof(builtin_node_factories[0]))


static int
sc_node_factory_lookup_builtin(const struct sc_node_factory** pp_factory,
                               struct sc_session* scs, const char* factory_name)
{
  const struct builtin_node_factory* bnf;
  const struct builtin_node_factory* bnf_end;
  bnf_end = builtin_node_factories + N_BUILTIN_NODE_FACTORIES;
  for( bnf = builtin_node_factories; bnf < bnf_end; ++bnf )
    if( ! strncmp(factory_name, bnf->name, strlen(bnf->name)) ) {
      *pp_factory = bnf->node_factory;
      return 0;
    }
  return -1;
}


int sc_node_factory_lookup(const struct sc_node_factory** pp_factory,
                           struct sc_session* tg,
                           const char* factory_name, const char* lib_name)
{
  char* default_lib_name = NULL;
  const char* env_node_path = getenv("SC_NODE_PATH");
  int rc = 0;

  *pp_factory = NULL;

  /* Lookup builtin nodes first.  Disadvantage is we lose some flexibility:
   * They can't be replaced at runtime.  Advantage is we can be sure the
   * built-in version is used.
   */
  if( sc_node_factory_lookup_builtin(pp_factory, tg, factory_name) == 0 )
    return 0;

  /* If we didn't get provided a lib_name, then assume library is
   * factory_name.so.
   */
  if( lib_name == NULL ) {
    TEST( asprintf(&default_lib_name, "%s.so", factory_name) > 0 );
    lib_name = default_lib_name;
  }

  *pp_factory = sc_node_factory_search(tg, lib_name, factory_name,
                                       env_node_path);

  /* Haven't found node factory yet, check the builtins. */
  if( ! *pp_factory ) {
  }

  if( *pp_factory == NULL )
    rc = sc_set_err(tg, ENOENT,
                    "%s: ERROR: Failed to find node %s in lib %s in system"
                    " paths, working directory or SC_NODE_PATH (%s)\n",
                    __func__, factory_name, lib_name, env_node_path);

  free(default_lib_name);
  return rc;
}
