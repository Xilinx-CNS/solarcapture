/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_arg: An argument to a node's initialisation function.
 */

#ifndef __SOLAR_CAPTURE_ARGS_H__
#define __SOLAR_CAPTURE_ARGS_H__

/**
 * \brief Possible parameter types that can be used for arguments in a node's
 * init function.
 */
enum sc_param_type {
  SC_PARAM_STR, /**< const char pointer (nul terminated) */
  SC_PARAM_INT, /**< signed 64 bit int */
  SC_PARAM_OBJ, /**< sc_object pointer */
  SC_PARAM_DBL, /**< native double type */
};


/**
 * \struct sc_arg
 * \brief Representation of an argument.  Used by node init functions.
 */
struct sc_arg {
  const char*        name; /**< Parameter name*/
  enum sc_param_type type; /**< Parameter type*/
  union {
    const char*             str;
    int64_t                 i;
    struct sc_object*       obj;
    double                  dbl;
  }                  val; /**< Parameter value */
};

/**
 * Function to construct a ::sc_arg struct of type ::SC_PARAM_INT
 * \param name       Name of argument.
 * \param val        Value of argument.
 * \return           The constructed ::sc_arg struct
 */
static inline struct sc_arg SC_ARG_INT(const char *name, int64_t val)
{
  struct sc_arg argument;
  argument.name = name;
  argument.type = SC_PARAM_INT;
  argument.val.i = val;
  return argument;
}

/**
 * Function to construct a ::sc_arg struct of type ::SC_PARAM_STR
 * \param name       Name of argument.
 * \param val        Value of argument.
 * \return           The constructed ::sc_arg struct
 */
static inline struct sc_arg SC_ARG_STR(const char *name, const char *val)
{
  struct sc_arg argument;
  argument.name = name;
  argument.type = SC_PARAM_STR;
  argument.val.str = val;
  return argument;
}

/**
 * Function to construct a ::sc_arg struct of type ::SC_PARAM_OBJ
 * \param name       Name of argument.
 * \param val        Value of argument.
 * \return           The constructed ::sc_arg struct
 */
static inline struct sc_arg SC_ARG_OBJ(const char *name, struct sc_object* val)
{
  struct sc_arg argument;
  argument.name = name;
  argument.type = SC_PARAM_OBJ;
  argument.val.obj = val;
  return argument;
}

/**
 * Function to construct a ::sc_arg struct of type ::SC_PARAM_DBL
 * \param name       Name of argument.
 * \param val        Value of argument.
 * \return           The constructed ::sc_arg struct
 */
static inline struct sc_arg SC_ARG_DBL(const char *name, double val)
{
  struct sc_arg argument;
  argument.name = name;
  argument.type = SC_PARAM_DBL;
  argument.val.dbl = val;
  return argument;
}


#endif  /* __SOLAR_CAPTURE_ARGS_H__ */

/** @}*/
