/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief Interface for writing custom nodes.
 */

#ifndef __SOLAR_CAPTURE_EXT_NODE_H__
#define __SOLAR_CAPTURE_EXT_NODE_H__

#include <stdarg.h>


/**
 * \brief Description of a node
 *
 * This is passed to every function used to call into the node.
 */
struct sc_node {
  const struct sc_node_type*  nd_type;      /**< Type of node, set automatically on creation of the node */
  char*                       nd_name;      /**< Name of the node, set automatically when creating node. @p nd_name is set to attribute name if this provided, otherwise ::sc_node_factory.nf_name with a unique node instance number appended */
  void*                       nd_private;   /**< Set by node for local state*/
};


/**
 * \brief Description of a link the node has
 *
 * This is passed to the node initialisation function
 */
struct sc_node_link {
  const char* name;   /**< Set when a link is added to the node */
};


struct sc_packet;
struct sc_packet_list;
struct sc_attr;
struct sc_node_factory;
struct sc_pool;


/**
 * \brief Signature of function to initialise a node
 *
 * \param node         The node being initialised
 * \param attr         Attributes used to create the node
 * \param factory      The node factory
 *
 * This callback is used to initialise the private state of a node
 * instance.  It is called in response to sc_node_alloc() (or similar).
 *
 * This function must set sc_node::nd_type before invoking any other
 * function call on the node.
 *
 * The lifetime of the @p attr argument is limited to this call only.  Use
 * ::sc_attr_dup() if a copy is needed after this call returns.
 */
typedef int (sc_node_init_fn)(struct sc_node* node,
                              const struct sc_attr* attr,
                              const struct sc_node_factory* factory);

/**
 * \brief Struct to hold information about how to create an instance of this
 * node.
 */
struct sc_node_factory {
  int                       nf_node_api_ver; /**< Minimum version of SolarCapture that this node is compatible with. */
  const char*               nf_name;         /**< Name of this node factory. */
  const char*               nf_source_file;  /**< Name of the source file for this node.  (Use __FILE__ if you like). */
  void*                     nf_private;      /**< Private state for the implementation. */
  sc_node_init_fn*          nf_init_fn;      /**< Function called by SolarCapture core to initialise a new node. */
  void*                     nf_reserved[8];  /**< Reserved. */
};


/**
 * \brief Signature of nt_prep_fn function
 *
 * \param node         The node being prepared
 * \param links        Array of outgoing links the node has
 * \param n_links      Number of outgoing links in the array
 *
 * This callback is invoked to prepare @p node for live packet processing.
 * The implementation typically checks the egress links and saves them to
 * private storage.
 *
 * Any initialisation that could not be done in sc_node_init should be done
 * here.
 *
 * If the node needs to create subnodes and establish links it should be done
 * __before__ this stage in one of ::sc_node_init_fn, ::sc_node_select_subnode_fn
 * or ::sc_node_add_link_fn.
 *
 * Note that the array @p links is only valid for the duration of this
 * function call, but the ::sc_node_link objects are valid for at least the
 * lifetime of the node.
 */
typedef int (sc_node_prep_fn)(struct sc_node* node,
                              const struct sc_node_link*const* links,
                              int n_links);


/**
 * \brief Signature of nt_pkts_fn function
 *
 * \param node         The node receiving the packets
 * \param packet_list  List of packets
 *
 * This function will be called when packets are received on __any__ incoming link to
 * the node. It is not possible to distinguish which incoming link the packets
 * arrived from directly. If the node needs to distinguish between incoming streams
 * then either upstream nodes must append metadata to the packets or the node must be
 * constructed from subnodes with each subnode connected to a subset of incoming links.
 *
 * Once this function is invoked the node gets ownership of the packets.
 * Ownership is relinquished by invoking ::sc_forward_list,
 * ::sc_forward_list2, ::sc_forward or ::sc_forward2 to forward or free the
 * packets.
 */
typedef void (sc_node_pkts_fn)(struct sc_node* node,
                               struct sc_packet_list* packet_list);


/**
 * \brief Signature of nt_add_link_fn function
 *
 * \param from_node    The node being linked from
 * \param link_name    The name of the link
 * \param to_node      The node being linked to
 * \param to_name_opt  Optional name of ingress link
 *
 * This method is optional and supports compound nodes.  It is invoked on
 * @p from_node when ::sc_node_add_link(from_node, link_name, to_node,
 * to_name_opt) is called, and gives the implementation an opportunity to
 * select the subnode(s) to be linked from or issue an error if an attempt
 * is made to create an unwanted link.
 *
 * The implementation of this function should invoke ::sc_node_add_link()
 * on @p from_node or on a subnode, or should return an error. If it
 * returns an error it should do so by calling ::sc_node_set_error with a
 * suitable error message, and return the value returned by
 * ::sc_node_set_error.
 *
 * The @p to_node and @p to_name_opt arguments should be passed unmodified. The
 * implementation may invoke ::sc_node_add_link() multiple times to create
 * links from multiple subnodes.
 */
typedef int (sc_node_add_link_fn)(struct sc_node* from_node,
                                  const char* link_name,
                                  struct sc_node* to_node,
                                  const char* to_name_opt);


/**
 * \brief Signature of nt_select_subnode_fn function
 *
 * \param node          The node being linked to
 * \param name_opt      The name of the link (may be NULL)
 * \param new_name_out  Use to set a different name for sub-node
 *
 * This method is optional and supports compound nodes. It is invoked on
 * to_node when ::sc_node_add_link(from_node, link_name, to_node,
 * to_name_opt) is called, and gives the implementation an opportunity to
 * select an alternative subnode that should be linked to or issue an error
 * if an attempt is made to create an unwanted link.
 *
 * The implementation should return @p node or a subnode, or NULL to
 * indicate that @p name_opt2 is not valid for this node.  If returning NULL
 * the implementation should first call ::sc_node_set_error() to give the
 * reason for the error.
 *
 * @p name_opt2 comes from the to_name_opt argument passed to
 * ::sc_node_add_link(), and may be NULL.  If multiple links are added with
 * the same non-NULL @p name_opt2 then they should be treated as being
 * logically the same link.
 *
 * If a new name is specified via @p new_name_out then ownership is passed
 * to the caller, and it will be freed with free().
 */
typedef struct sc_node*
  (sc_node_select_subnode_fn)(struct sc_node* node, const char* name_opt,
                              char** new_name_out);

#if SC_API_VER >= 1
/**
 * \brief Signature of nt_end_of_stream_fn function
 *
 * \param node          The node.
 *
 * This method is invoked when all incoming upstream nodes have indicated
 * end-of-stream. After this method has been called ::sc_node_pkts_fn will not be
 * called again. The implementation of this function may propagate end-of-stream
 * through its outgoing links by calling ::sc_node_link_end_of_stream(). If this
 * function is not provided end-of-stream will not propagate further through
 * the node graph.
 *
 * After the node has propagated end-of-stream to a node through its outgoing
 * link it should not pass any more packets to this node.
 *
 * This method is optional.
 */
typedef void (sc_node_end_of_stream_fn)(struct sc_node* node);
#endif


/**
 * \brief Describes a type of node
 *
 * This struct describes what functions are responsible for the behaviour of the
 * node.
 */
struct sc_node_type {
  const char*                   nt_name;              /**< Name of the node type (set from ::sc_node_factory.nf_name). */
  void*                         nt_private;           /**< Private state for the implementation. */
  sc_node_prep_fn*              nt_prep_fn;           /**< (Optional) Prepare for packet processing. */
  sc_node_pkts_fn*              nt_pkts_fn;           /**< (Optional) Handle incoming packets. */
  sc_node_add_link_fn*          nt_add_link_fn;       /**< (Optional) Add an outgoing link. */
  sc_node_select_subnode_fn*    nt_select_subnode_fn; /**< (Optional) Select target node for an incoming link. */
#if SC_API_VER >= 1
  sc_node_end_of_stream_fn*     nt_end_of_stream_fn;  /**< (Optional) Handle end-of-stream signal. */
#endif
};


/**
 * \brief Allocate an sc_node_type instance.
 *
 * \param nt_out          The allocated sc_node_type instance
 * \param attr_opt        Optional attributes (may be NULL)
 * \param factory         The factory that created the node
 *
 * \return 0 on success, or a negative error code.
 *
 * At the time of writing @p attr_opt is not used and this call always
 * succeeds.  In future it may fail if the attributes are invalid in some
 * way.
 */
extern int sc_node_type_alloc(struct sc_node_type** nt_out,
                              const struct sc_attr* attr_opt,
                              const struct sc_node_factory* factory);


/**
 * \brief Forward a list of packets.
 *
 * \param node            The node
 * \param link            The link to forward through
 * \param pl              The list of packets to forward
 *
 * See also ::sc_forward_list2.
 */
extern void sc_forward_list(struct sc_node* node,
                            const struct sc_node_link* link,
                            struct sc_packet_list* pl);


#if SC_API_VER >= 4
/**
 * \brief Forward a list of packets.
 *
 * \param link            The link to forward through
 * \param pl              The list of packets to forward
 */
extern void sc_forward_list2(const struct sc_node_link* link,
                             struct sc_packet_list* pl);

/** \cond NODOC */
static inline void sc_forward_list2__(struct sc_node* node,
                                      const struct sc_node_link* link,
                                      struct sc_packet_list* pl)
{
  sc_forward_list2(link, pl);
}
# define sc_forward_list(n, l, pl)  sc_forward_list2__((n), (l), (pl))
/** \endcond */
#endif


/**
 * \brief Forward a single packet.
 *
 * \param node            The node
 * \param link            The link to forward through
 * \param packet          The packet to forward
 *
 * See also ::sc_forward2.
 */
extern void sc_forward(struct sc_node* node, const struct sc_node_link* link,
                       struct sc_packet* packet);


#if SC_API_VER >= 4
/**
 * \brief Forward a single packet.
 *
 * \param link            The link to forward through
 * \param packet          The packet to forward
 */
extern void sc_forward2(const struct sc_node_link* link,
                        struct sc_packet* packet);

/** \cond NODOC */
static inline void sc_forward2__(struct sc_node* node,
                                 const struct sc_node_link* link,
                                 struct sc_packet* packet)
{
  sc_forward2(link, packet);
}
# define sc_forward(n, l, p)  sc_forward2__((n), (l), (p))
/** \endcond */
#endif


/**
 * \brief Get an integer argument.
 *
 * \param v_out      On success, the value is returned here
 * \param node       The node
 * \param name       The name of the argument
 * \param v_default  Default returned if arg not found
 *
 * \return 0 on success\n
 *         1 if the argument is not found (in which case v_default is copied\n
 *           to v_out)\n
 *         -1 if the argument was found but is of the wrong type.
 *
 * This may only be called from ::sc_node_init_fn.  
 */
extern int sc_node_init_get_arg_int(int* v_out, struct sc_node* node,
                                    const char* name, int v_default);


#if SC_API_VER >= 4
/**
 * \brief Get a 64 bit integer argument.
 *
 * \param v_out      On success, the value is returned here
 * \param node       The node
 * \param name       The name of the argument
 * \param v_default  Default returned if arg not found
 *
 * \return 0 on success\n
 *         1 if the argument is not found (in which case v_default is copied\n
 *           to v_out)\n
 *         -1 if the argument was found but is of the wrong type.
 *
 * This may only be called from ::sc_node_init_fn.  
 */
extern int sc_node_init_get_arg_int64(int64_t* v_out, struct sc_node* node,
                                      const char* name, int64_t v_default);
#endif


/**
 * \brief Get an string argument.
 *
 * \param v_out      On success, the value is returned here
 * \param node       The node
 * \param name       The name of the argument
 * \param v_default  Default returned if arg not found
 *
 * \return 0 on success\n
 *         1 if the argument is not found (in which case v_default is copied\n
 *           to v_out)\n
 *         -1 if the argument was found but is of the wrong type.
 *
 * This may only be called from ::sc_node_init_fn.  
 *
 * The string returned is valid only until the ::sc_node_init_fn call
 * returns.
 */
extern int sc_node_init_get_arg_str(const char** v_out, struct sc_node* node,
                                    const char* name, const char* v_default);


#if SC_API_VER >= 1
/**
 * \brief Get an sc_object argument.
 *
 * \param obj_out    On success, the value is returned here
 * \param node       The node
 * \param name       The name of the argument
 * \param obj_type   The type of object wanted, or SC_OBJ_ANY
 *
 * \return 0 on success\n
 *         1 if the argument is not found (in which case v_default is copied\n
 *           to v_out)\n
 *         -1 if the argument was found but is of the wrong type.
 *
 * This may only be called from ::sc_node_init_fn.  
 */
extern int sc_node_init_get_arg_obj(struct sc_object** obj_out,
                                    struct sc_node* node, const char* name,
                                    enum sc_object_type obj_type);
#endif


#if SC_API_VER >= 1
/**
 * \brief Get a double argument.
 *
 * \param v_out      On success, the value is returned here
 * \param node       The node
 * \param name       The name of the argument
 * \param v_default  Default returned if arg not found
 *
 * \return 0 on success\n
 *         1 if the argument is not found (in which case v_default is copied\n
 *           to v_out)\n
 *         -1 if the argument was found but is of the wrong type.
 *
 * This may only be called from ::sc_node_init_fn.  
 */
extern int sc_node_init_get_arg_dbl(double* v_out, struct sc_node* node,
                                    const char* name, double v_default);
#endif


/**
 * \brief Find a named outgoing link.
 *
 * \param node       The node
 * \param link_name  Name of the link
 *
 * \return The named link, or NULL if the named link doesn't exist.
 *
 * A node's ::sc_node_prep_fn can either use this mechanism to query its
 * links, or it can simply iterate over the links passed as arguments to
 * ::sc_node_prep_fn.
 *
 * This function may only be called from ::sc_node_prep_fn.
 *
 * See also ::sc_node_prep_check_links().
 */
extern const struct sc_node_link*
  sc_node_prep_get_link(struct sc_node* node, const char* link_name);

/**
 * \brief Find a named outgoing link or return a link for freeing.
 *
 * \param node       The node
 * \param link_name  Name of the link
 *
 * \return The named link, or a special link that frees packets if the named 
 * link doesn't exist.
 *
 * This function behaves just like ::sc_node_prep_get_link(), except that if
 * no link of that name has been added to the node, a special link is
 * returned that frees packets.
 *
 * @p link_name may be NULL, in which case a link for freeing packets is
 * returned.
 */
extern const struct sc_node_link*
  sc_node_prep_get_link_or_free(struct sc_node* node, const char* link_name);

/**
 * \brief Check the node's links for any unused links.
 *
 * \param node       The node
 *
 * \return 0 if all is fine (or only warnings are needed)\n
 *         -1 on error, which should be propagated out of ::sc_node_prep_fn().
 *
 * This may only be called from ::sc_node_prep_fn(), and should only be used
 * by nodes that find their links by calling ::sc_node_prep_get_link().
 *
 * This function will complain about any links added to the node that have
 * not been queried by ::sc_node_prep_get_link().  It may emit a warning, or
 * generate an error.
 */
extern int
  sc_node_prep_check_links(struct sc_node* node);

#if SC_API_VER >= 1
/**
 * \brief Get a packet pool that can be used to obtain empty packet buffers that
 * can be passed to any of the given set of links.
 *
 * \param pool_out   On success, the pool is returned here
 * \param attr       Packet pool attributes (optional, may be NULL)
 * \param node       The node
 * \param links      The link(s) packets from the pool may be passed to (set to NULL for all)
 * \param n_links    Number of links in 'links' (set to 0 for all)
 *
 * \return 0 on success, or a negative error code.
 *
 * The node must only forward packets from the returned pool over the links
 * identified by @p links and @p n_links.  If @p n_links is 0 then it is
 * assumed that packets from the pool may be forwarded over any of the
 * node's links.
 *
 * Restricting the links packets can be sent along allows SolarCapture
 * to optimise the releasing of packets back to the pool when the node graph is
 * finished with them.
 *
 * This may only be called from ::sc_node_prep_fn.
 */
extern int sc_node_prep_get_pool(struct sc_pool** pool_out,
                                 const struct sc_attr* attr,
                                 struct sc_node* node,
                                 const struct sc_node_link*const* links,
                                 int n_links);
#endif


#if SC_API_VER >= 4
/**
 * \brief Indicate that this node does not forward to all of its links.
 *
 * \param node       A node
 *
 * By default it is assumed that packets arriving at a node may be
 * forwarded through any of the node's outgoing links.  The effect of this
 * call is to break that assumption.  SolarCapture will assume that packets
 * arriving at @p node are not forwarded via any of the outgoing links,
 * unless overridden by ::sc_node_prep_link_forwards_from_node.
 */
extern void sc_node_prep_does_not_forward(struct sc_node* node);
#endif


#if SC_API_VER >= 4
/**
 * \brief Indicate that packets arriving at a node pass through a link.
 *
 * \param node       The node that @p link originates from
 * \param link       A link from @p node to another node
 * \param from_node  Node at which packets arrive
 *
 * This call tells SolarCapture that packets arriving at @p from_node are
 * forwarded via @p link.
 *
 * You will also need to call ::sc_node_prep_does_not_forward to cancel the
 * default assumption that all links are used for forwarding.
 *
 * Note that most nodes do not need to use this function, because
 * SolarCapture assumes by default that packets arriving at a node may be
 * forwarded through any of the node's outgoing links.  This call is useful
 * when either (a) only a subset of links are used for forwarding or (b) a
 * node forwards packets that arrived at a different node.
 */
extern void sc_node_prep_link_forwards_from_node(struct sc_node* node,
                                               const struct sc_node_link* link,
                                               struct sc_node* from_node);
#endif


#if SC_API_VER >= 1
/** \cond NODOC */
extern int __sc_node_set_error(struct sc_node* node, const char* file,
                               int line, const char* func, int errno_code,
                               const char* fmt, ...)
  __attribute__((format(printf,6,7)));

extern int __sc_node_fwd_error(struct sc_node* node, const char* file,
                               int line, const char* func, int rc);
/** \endcond */
#endif


#if SC_API_VER >= 5
/** \cond NODOC */
extern int __sc_node_set_errorv(struct sc_node* node, const char* file,
                               int line, const char* func, int errno_code,
                               const char* fmt, va_list args);
/** \endcond */
#endif


/**
 * \brief Set error from within the implementation of a node.
 *
 * \param node       The node that originates the error
 * \param errno_code An error code from errno.h (or can be zero)
 *
 * Call this function when returning an error to SolarCapture from a node.
 * The value returned by this function should be passed on to the caller of
 * the function reporting the error.
 */
#define sc_node_set_error(node, errno_code, ...)                \
  __sc_node_set_error((node), __FILE__, __LINE__, __func__,     \
                      (errno_code), __VA_ARGS__)


/**
 * \brief Set error from within the implementation of a node.
 *
 * \param node       The node that originates the error
 * \param errno_code An error code from errno.h (or can be zero)
 * \param fmt        vprintf style format string
 * \param args       vprintf arguments matching format string
 *
 * Call this function when returning an error to SolarCapture from a node.
 * The value returned by this function should be passed on to the caller of
 * the function reporting the error.
 *
 * See also ::sc_node_set_error.
 */
#define sc_node_set_errorv(node, errno_code, fmt, args)         \
  __sc_node_set_errorv((node), __FILE__, __LINE__, __func__,    \
                       (errno_code), (fmt), (args))


/**
 * \brief Forward error from a failed sc call.
 *
 * \param node       The node that forwards the error
 * \param rc         The error code returned by the sc call
 *
 * Call this function to propagate an error generated by SolarCapture.
 */
#define sc_node_fwd_error(node, rc)                                     \
  __sc_node_fwd_error((node), __FILE__, __LINE__, __func__, (rc))


#if SC_API_VER >= 1
/**
 * \brief Indicate end-of-stream on a link.
 *
 * \param node           The node
 * \param link           The link
 *
 * It is a fatal error to forward any further packets through the link
 * after calling this function.
 */
extern void sc_node_link_end_of_stream(struct sc_node* node,
                                       const struct sc_node_link* link);
#endif


#if SC_API_VER >= 4
/**
 * \brief Indicate end-of-stream on a link.
 *
 * \param link           The link
 *
 * It is a fatal error to forward any further packets through the link
 * after calling this function.
 */
extern void sc_node_link_end_of_stream2(const struct sc_node_link* link);

/** \cond NODOC */
static inline void __sc_node_link_end_of_stream2(struct sc_node* node,
                                            const struct sc_node_link* link)
{
  sc_node_link_end_of_stream2(link);
}
# define sc_node_link_end_of_stream(n, l)       \
  __sc_node_link_end_of_stream2((n), (l))
/** \endcond */
#endif


#if SC_API_VER >= 1
/**
 * \brief Export dynamic state to solar_capture_monitor.
 *
 * \param node           The node exporting state
 * \param type_name      Name of the exported datastructure
 * \param type_size      Size in bytes of the exported datastructure
 * \param pp_area        Pointer to memory is returned here
 *
 * \return 0 on success, or a negative error code.
 *
 * Use this function to export dynamic runtime information about a node to
 * solar_capture_monitor.  The information can include configuration
 * information, statistics and/or other runtime state.
 *
 * @p pp_area gives the address of a pointer that is overwritten with a
 * pointer to the memory area large enough for an instance of @p type_name.
 * So @p pp_area should be of type 'struct type_name**'.
 *
 * The type @p type_name must already have been declared by creating the
 * type_name_declare() function using declare_types.h::SC_DECLARE_TYPES and
 * calling it.
 *
 * See also ::sc_node_add_info_str() and ::sc_node_add_info_int(), which are
 * useful for exporting static data.
 */
extern int sc_node_export_state(struct sc_node* node, const char* type_name,
                                int type_size, void* pp_area);
#endif


#endif  /* __SOLAR_CAPTURE_EXT_NODE_H__ */
/** @}*/
