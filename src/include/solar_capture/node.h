/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief Sc_node: An object that processes packets.
 */

#ifndef __SOLAR_CAPTURE_NODE_H__
#define __SOLAR_CAPTURE_NODE_H__


struct sc_node;
struct sc_attr;
struct sc_thread;
struct sc_session;
struct sc_node_factory;
struct sc_arg;


/**
 * \brief Allocate a packet processing node.
 *
 * \param node_out        The allocated node is returned here
 * \param attr            Attributes
 * \param thread          The thread the node will be in
 * \param factory         A node factory
 * \param args            An array of arguments for node initialisation
 * \param n_args          The number of arguments
 *
 * \return 0 on success, or a negative error code.
 *
 * Nodes perform packet processing services such as filtering, packet
 * modification, import/export and packet injection.
 *
 * A node factory allocates nodes of a particular type, and the argument
 * list provides configuration for the node instance.
 *
 * Use this function when you have a pointer to the node factory.  For
 * built-in nodes or nodes in a separate library it is simpler to use
 * ::sc_node_alloc_named().
 */
extern int sc_node_alloc(struct sc_node** node_out, const struct sc_attr* attr,
                         struct sc_thread* thread,
                         const struct sc_node_factory* factory,
                         const struct sc_arg* args, int n_args);

#if SC_API_VER >= 1
/**
 * \brief Allocate a packet processing node by name.
 *
 * \param node_out        The allocated node is returned here.
 * \param attr            Attributes.
 * \param thread          The thread the node will be in.
 * \param factory_name    Name of the node factory.
 * \param lib_name        Name of the node library (may be NULL).
 * \param args            An array of arguments for node initialisation.
 * \param n_args          The number of arguments.
 *
 * \return 0 on success, or a negative error code.
 *
 * Nodes perform packet processing services such as filtering, packet
 * modification, import/export and packet injection.
 *
 * This function allocates a node of type @p factory_name, and the argument
 * list provides configuration for the node instance.
 *
 * This function is a short-cut for ::sc_node_factory_lookup() followed by
 * ::sc_node_alloc().
 */
extern int sc_node_alloc_named(struct sc_node** node_out,
                               const struct sc_attr* attr,
                               struct sc_thread* thread,
                               const char* factory_name,
                               const char* lib_name,
                               const struct sc_arg* args, int n_args);
#endif


#if SC_API_VER >= 5
/**
 * \brief Allocate a packet processing node using a string specification.
 *
 * \param node_out        The allocated node is returned here.
 * \param attr            Attributes.
 * \param thread          The thread the node will be in.
 * \param node_spec       String giving the node type and arguments.
 *
 * \return 0 on success, or a negative error code.
 *
 * This function allocates a node as specified in @p node_spec, which is
 * formatted as follows:
 *
 *   NODE_SPEC  :=  NODE_TYPE [":" ARGS]
 *   ARGS       :=  NAME=VAL [";" ARGS]
 *
 * Example:  "sc_vi_node:interface=eth4;streams=all"
 */
extern int sc_node_alloc_from_str(struct sc_node** node_out,
                                  const struct sc_attr* attr,
                                  struct sc_thread* thread,
                                  const char* node_spec);
#endif


/**
 * \brief Add a link from one node to another.
 *
 * \param from_node       Node to connect from.
 * \param link_name       Name of the @p from_node's egress link.
 * \param to_node         Node to connect to.
 * \param to_name_opt     Optional ingress port name (may be NULL).
 *
 * \return 0 on success, or a negative error code.
 *
 * Packets flow from node to node along links.  This function adds a link
 * from @p from_node to @p to_node.
 *
 * @p link_name identifies @p from_node's egress link.  By convention the
 * default egress link is named "".
 *
 * Some node types support multiple ingress ports so that the node can
 * receive and separate multiple incoming packet streams.  The name of the
 * ingress port is given by @p to_name_opt.
 *
 * Since SolarCapture 1.1, if the nodes are in different threads then this
 * function automatically creates a link between the threads using
 * mailboxes.
 */
extern int sc_node_add_link(struct sc_node* from_node, const char* link_name,
                            struct sc_node* to_node, const char* to_name_opt);

/**
 * \brief Return the thread associated with a node.
 *
 * \param node            The node.
 *
 * \return The thread associated with the node.
 */
extern struct sc_thread* sc_node_get_thread(const struct sc_node* node);


/**
 * \brief Find a node factory.
 *
 * \param factory_out     The node factory found.
 * \param session         The SolarCapture session.
 * \param factory_name    Name of the node factory.
 * \param lib_name        Name of the node library (may be NULL).
 *
 * \return 0 on success, or a negative error code.
 *
 * Finds the factory of name @p factory_name.  It may be a built-in factory
 * (in which case @p lib_name should be NULL) or a factory in an external
 * library.
 *
 * A factory library is a shared object file that contains one or more node
 * factory instances.
 *
 * @p lib_name may be NULL, in which case it defaults to being the same as
 * the @p factory_name.
 *
 * If @p lib_name contains a '/' character it is treated as the full path to
 * the library object file.
 *
 * Otherwise @p lib_name is the name of the library object file (either with
 * or without a .so suffix).  This function will search for the library
 * object file in the following directories (in order):
 *
 *   - the current working directory
 *   - directories specified by the SC_NODE_PATH environment variable
 *   - /usr/lib64/solar_capture/site-nodes
 *   - /usr/lib/x86_64-linux-gnu/solar_capture/site-nodes
 *   - /usr/lib64/solar_capture/nodes
 *   - /usr/lib/x86_64-linux-gnu/solar_capture/nodes
 *
 * Depending on the target system, not all of the above directories may exist.
 * In particular, the subdirectories of /usr/lib/x86_64-linux-gnu/ will only
 * exist on Debian-derived systems using the multiarch structure for library
 * folders. This is not expected to cause a problem at runtime.
 *
 * If we decide to support 32-bit builds again, these directories will be
 * searched instead (in order):
 *
 *   - the current working directory
 *   - directories specified by the SC_NODE_PATH environment variable
 *   - /usr/lib/solar_capture/site-nodes
 *   - /usr/lib/i386-linux-gnu/solar_capture/site-nodes
 *   - /usr/lib/solar_capture/nodes
 *   - /usr/lib/i386-linux-gnu/solar_capture/nodes
 *
 * If a library containing the named factory is not found by this search,
 * the built-in nodes are searched last.
 */
extern int sc_node_factory_lookup(const struct sc_node_factory** factory_out,
                                  struct sc_session* session,
                                  const char* factory_name,
                                  const char* lib_name);


#if SC_API_VER >= 2
/**
 * \brief Export information to solar_capture_monitor.
 *
 * \param node           The node exporting state.
 * \param field_name     Name of field.
 * \param field_val      State to export.
 *
 * Use this function to export static runtime information about a node to
 * solar_capture_monitor.  This function can be used in the implementation
 * of a new node type, or in an application using a node.
 *
 * See also ::sc_node_add_info_int() and ::sc_node_export_state().
 */
extern void sc_node_add_info_str(struct sc_node* node,
                                 const char* field_name, const char* field_val);
#endif


#if SC_API_VER >= 2
/**
 * \brief Export information to solar_capture_monitor.
 *
 * \param node           The node exporting state.
 * \param field_name     Name of field.
 * \param field_val      State to export.
 *
 * Use this function to export static runtime information about a node to
 * solar_capture_monitor.  This function can be used in the implementation
 * of a new node type, or in an application using a node.
 *
 * See also ::sc_node_add_info_str() and ::sc_node_export_state().
 */
extern void sc_node_add_info_int(struct sc_node* node,
                                  const char* field_name, int64_t field_val);
#endif


#if SC_API_VER >= 4
/**
 * \brief Convert an ::sc_node to an ::sc_object.
 *
 * \param node            An ::sc_node instance or NULL
 * \return                NULL if @p node is NULL otherwise the ::sc_object.
 */
extern struct sc_object* sc_node_to_object(struct sc_node* node);
#endif


#if SC_API_VER >= 4
/**
 * \brief Convert an ::sc_object to an ::sc_node.
 *
 * \param obj             An ::sc_object instance or NULL
 * \return                NULL if @p obj is NULL otherwise the ::sc_node.
 *
 * Also returns NULL if @p obj is not of type SC_OBJ_NODE.
 */
extern struct sc_node* sc_node_from_object(struct sc_object* obj);
#endif


#endif  /* __SOLAR_CAPTURE_NODE_H__ */
/** @} */
