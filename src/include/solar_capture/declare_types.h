/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief This header is used to generate C type definitions and corresponding
 * runtime type information for data structures that are shared by
 * SolarCapture with other processes.
 *
 * In order to create runtime type information a template header file must be
 * created. For example a node called my_node could have a template file
 * my_node_tmpl.h as follows
 *
 *
 *     ST_STRUCT(my_node_stats)
 *       ST_FIELD(double,   some_stat,         config)
 *       ST_FIELD(int,      some_other_stat,   pkt_count)
 *       ST_FIELD(double,   another_stat,      magnitude)
 *       ST_FIELD(double,   yet_one_more_stat, ev_count)
 *       ...
 *     ST_STRUCT_END
 *
 *
 * In the node source file the node must
 *   1. Define SC_TYPE_TEMPLATE to be a header file containing the node's type
 *   template definition.
 *   2. Define SC_DECLARE_TYPES to be the name of the declaration function to
 *   create.
 *   3. Include declare_types.h
 *   4. Call the function defined by (2)
 *   5. Call ::sc_node_export_state to allocate a struct of the type defined in
 *   the node's type template definition.
 *
 * Stats can them be updated by changing the values of the fields in the newly
 * created struct from step (5). If stats need to be updated during runtime a means
 * of accessing this struct should be kept in the nodes nd_private field.
 *
 * For example, a node which would like to create a declaration function with name
 * my_node_declare using the template my_node_tmpl.h would do the following
 *
 *
 *     #define SC_TYPE_TEMPLATE  <my_node_tmpl.h>
 *     #define SC_DECLARE_TYPES my_node_declare
 *     #include <solar_capture/declare_types.h>
 *
 *     ...
 *
 *     static int my_node_init(struct sc_node* node, const struct sc_attr* attr,
 *                     const struct sc_node_factory* factory)
 *     {
 *       ...
 *       my_node_declare(sc_thread_get_session(sc_node_get_thread(node)));
 *       ...
 *       struct my_node_stats* stats;
 *       sc_node_export_state(node, "my_node_stats",
 *                      sizeof(struct my_node_stats), &stats);
 *     }
 *
 *
 *
 */

#ifndef SC_TYPE_TEMPLATE
# error SC_TYPE_TEMPLATE must be defined before including declare_types.h
#endif


/**********************************************************************
 * Generate C type definitions.
 */

/**
 * \brief A constant value in the template definition.
 *
 * After the node has initialised its shared data structures @p name will be
 * used as the field in the stats struct to update this data.
 *
 * \param name      The field name.
 * \param val       The constant.
 */
#define ST_CONSTANT(name, val)         enum { name = val };a
/**
 * \brief Start of the template definition.
 *
 * After the node has initialised its shared data structures the resulting struct
 * type for updating the stats will use @p name for its type.
 *
 * \param name      The name of the template.
 */
#define ST_STRUCT(name)                struct name {
/**
 * \brief A string field in the template definition
 *
 * After the node has initialised its shared data structures @p name will be
 * used as the field in the stats struct to update this data.
 *
 * \param name      The field name.
 * \param len       The length of the string.
 * \param kind      A string to describe the kind of data. Examples used by
 *                  SolarCapture nodes are pkt_count, ev_count, config, const,
 *                  magnitude.
 */
#define ST_FIELD_STR(name, len, kind)  char name[len];
/**
 *  \brief A C basic type field in the template definition.
 *
 *  After the node has initialised its shared data structures @p name will be
 *  used as the field in the stats struct to update this data.
 *
 *  \param type     The basic data type.
 *  \param name     The field name.
 *  \param kind     A string to describe the kind of data. Examples used by
 *                  SolarCapture nodes are pkt_count, ev_count, config, const,
 *                  magnitude.
 */
#define ST_FIELD(type, name, kind)     type name;
/**
 * \brief End of the template definition
 */
#define ST_STRUCT_END                  };

#include SC_TYPE_TEMPLATE

#undef ST_CONSTANT
#undef ST_STRUCT
#undef ST_FIELD_STR
#undef ST_FIELD
#undef ST_STRUCT_END


/**********************************************************************
 * Generate function to declare the types.
 */

#ifdef SC_DECLARE_TYPES
/** \brief Function to declare the runtime type information to be shared with
 * other processes.
 *
 * \param scs       The current solar capture session.
 *
 */
static inline void SC_DECLARE_TYPES(struct sc_session* scs)
{
#define __scs scs
#define ST_CONSTANT(name, val)                  \
  sc_montype_constant(__scs, #name, val);
#define ST_STRUCT(name)                         \
  sc_montype_struct(__scs, #name);
#define ST_FIELD_STR(name, len, kind)                   \
  sc_montype_field(__scs, #name, "str", #kind, #len);
#define ST_FIELD(type, name, kind)                      \
  sc_montype_field(__scs, #name, #type, #kind, NULL);
#define ST_STRUCT_END                           \
  sc_montype_struct_end(__scs);

#include SC_TYPE_TEMPLATE
  sc_montype_flush(scs);

#undef ST_CONSTANT
#undef ST_STRUCT
#undef ST_FIELD_STR
#undef ST_FIELD
#undef ST_STRUCT_END
}

#undef SC_DECLARE_TYPES
#endif


#undef SC_TYPE_TEMPLATE
/** @}*/
