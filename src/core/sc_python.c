/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <Python.h>
#define SC_API_VER SC_API_VER_MAX
#include <solar_capture.h>
#include <solar_capture/private.h>

#include <stdarg.h>

#include <sys/types.h>
#include <grp.h>

#include "compiled_ef_vi_version.h"

/* Python2 implemented this as PyString_AsString, for python3 we have to go
   via utf8.
   This will return a failure if non-ascii unicode gets used.
*/
const char* pystring_to_cstring(PyObject* s) {
  /* Use Python to do the unicode translation for us */
  return PyUnicode_AsUTF8(s);
}

static PyObject* SCError;


static inline PyObject* raise_session_err(struct sc_session* tg)
{
  struct sc_session_error* err = sc_session_error_get(tg);
  PyObject* exc = Py_BuildValue("sssii", err->err_msg, err->err_func,
                                err->err_file, err->err_line, err->err_errno);
  PyErr_SetObject(SCError, exc);
  sc_session_error_free(tg, err);
  return NULL;
}

#define TRY(x)                                                          \
  do {                                                                  \
    int __rc = (x);                                                     \
    if( __rc < 0 ) {                                                    \
      fprintf(stderr, "ERROR: %s: TRY(%s) failed\n", __func__, #x);     \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",                   \
              __rc, errno, strerror(errno));                            \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


#define TEST(x)                                                         \
  do {                                                                  \
    if( ! (x) ) {                                                       \
      fprintf(stderr, "ERROR: %s: TEST(%s) failed\n", __func__, #x);    \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


#define ALLOW_THREADS(x)                        \
  ({                                            \
    int __rc;                                   \
    Py_BEGIN_ALLOW_THREADS                      \
      __rc = (x);                               \
    Py_END_ALLOW_THREADS                        \
    __rc;                                       \
  })


/* This is only needed before python 2.7 but I can't see an easy way
 * to distinguish version 2.5, 2.6 and 2.7 as PYTHON_VERSION_API
 * wasn't incremented 
 */

static PyObject* sc_initgroups(PyObject *self, PyObject *args)
{
 	char *username;
 	long gid;
 
	if (!PyArg_ParseTuple(args, "sl:initgroups", &username, &gid))
		return NULL;
 
	if (initgroups(username, (gid_t) gid) == -1)
		return PyErr_SetFromErrno(PyExc_OSError);

	Py_INCREF(Py_None);
	return Py_None;
}

#if PYTHON_API_VERSION <= 1012  /* Python 2.4 or earlier */

# define Py_ssize_t int

static PyObject* fix_PyObject_GetAttrString(PyObject *o, const char *attr_name)
{
  return PyObject_GetAttrString(o, (char*) attr_name);
}
#define PyObject_GetAttrString fix_PyObject_GetAttrString

#endif


static struct sc_vi_group** vi_groups;
static int n_vi_groups;

static struct sc_session** sessions;
static int n_sessions;

static struct sc_thread** threads;
static int n_threads;

static struct sc_node** nodes;
static int n_nodes;

static struct sc_mailbox** mailboxes;
static int n_mailboxes;

static struct sc_vi** vis;
static int n_vis;


static int sc_py_get_index(PyObject* obj, const char* index_name)
{
  PyObject* o = PyObject_GetAttrString(obj, index_name);
  int rc = o ? PyLong_AsLong(o) : -1;
  Py_XDECREF(o);
  return rc;
}


static int sc_py_get_vi_group(PyObject* obj, struct sc_vi_group** out)
{
  int i = sc_py_get_index(obj, "__vigroup_index__");
  TEST((unsigned) i < (unsigned) n_vi_groups);
  *out = vi_groups[i];
  return 1;
}


static int sc_py_get_session(PyObject* obj, struct sc_session** out)
{
  int i = sc_py_get_index(obj, "__session_index__");
  TEST((unsigned) i < (unsigned) n_sessions);
  *out = sessions[i];
  return 1;
}


static int sc_py_get_thread(PyObject* obj, struct sc_thread** out)
{
  int i = sc_py_get_index(obj, "__thread_index__");
  TEST((unsigned) i < (unsigned) n_threads);
  *out = threads[i];
  return 1;
}


static int sc_py_get_node(PyObject* obj, struct sc_node** out)
{
  int i = sc_py_get_index(obj, "__node_index__");
  TEST((unsigned) i < (unsigned) n_nodes);
  *out = nodes[i];
  return 1;
}


static int sc_py_get_mailbox(PyObject* obj, struct sc_mailbox** out)
{
  int i = sc_py_get_index(obj, "__mbox_index__");
  TEST((unsigned) i < (unsigned) n_mailboxes);
  *out = mailboxes[i];
  return 1;
}


static int sc_py_get_vi(PyObject* obj, struct sc_vi** out)
{
  int i = sc_py_get_index(obj, "__vi_index__");
  TEST((unsigned) i < (unsigned) n_vis);
  *out = vis[i];
  return 1;
}


struct sc_attr* sc_attr_from_py(PyObject* attr_dict)
{
  struct sc_attr* attr;
  Py_ssize_t pos = 0;
  const char* name;
  PyObject *k, *v;
  int rc;
  char errmsg[100];

  /* ?? TODO: also accept None here? */
  if( ! PyDict_Check(attr_dict) ) {
    PyErr_SetString(PyExc_TypeError, "attr must be dictionary");
    return NULL;
  }
  if( (rc = sc_attr_alloc(&attr)) < 0 ) {
    if( rc == -EINVAL )
      PyErr_Format(SCError, "ERROR: bad SC_ATTR environment variable\n");
    else
      PyErr_Format(SCError, "ERROR: sc_attr_alloc failed rc=%d\n", rc);
    return NULL;
  }
  while( PyDict_Next(attr_dict, &pos, &k, &v) ) {
    if( (name = pystring_to_cstring(k)) == NULL ) {
      PyErr_SetString(PyExc_TypeError, "attr keys must be strings");
      goto error;
    }
    if( PyLong_Check(v) ) {
      int64_t lv;
      lv = PyLong_AS_LONG(v);
      if( (rc = sc_attr_set_int(attr, name, lv)) < 0 ) {
        if( rc == -EOVERFLOW )
          snprintf(errmsg, 100, "attribute '%s' value %ld overflow", name, lv);
        else
          snprintf(errmsg, 100, "unknown attribute '%s'", name);

        if( PyDict_GetItemString(attr_dict, "unknown_attr_ignore") ) {
          continue;
        }
        else if( PyDict_GetItemString(attr_dict, "unknown_attr_warn") ) {
          fprintf(stderr, "solar_capture: WARNING: %s\n", errmsg);
          continue;
        }
        else {
          PyErr_Format(SCError, "ERROR: %s\n", errmsg);
          goto error;
        }
      }
    }
    else if( PyUnicode_Check(v) ) {
      const char* val = pystring_to_cstring(v);
      if( (rc = sc_attr_set_from_str(attr, name, val)) < 0 ) {
        if( rc == -ENOMSG )
          snprintf(errmsg, 100, "attribute %s: invalid value '%s'",
                   name, val);
        else
          snprintf(errmsg, 100, "unknown attribute '%s'", name);
        if( PyDict_GetItemString(attr_dict, "unknown_attr_ignore") ) {
          continue;
        }
        else if( PyDict_GetItemString(attr_dict, "unknown_attr_warn") ) {
          fprintf(stderr, "solar_capture: WARNING: %s", errmsg);
          continue;
        }
        else {
          PyErr_Format(SCError, "ERROR: %s\n", errmsg);
          goto error;
        }
      }
    }
    else {
      PyErr_Format(SCError, "ERROR: Bad value for attribute '%s'\n", name);
      goto error;
    }
  }

  return attr;

 error:
  sc_attr_free(attr);
  return NULL;
}


static PyObject* session_alloc(PyObject* self, PyObject* args)
{
  PyObject *attr_dict;
  struct sc_attr* attr;

  if( ! PyArg_ParseTuple(args, "O", &attr_dict) )
    return NULL;
  if( (attr = sc_attr_from_py(attr_dict)) == NULL )
    return NULL;

  struct sc_session* tg;
  int rc = sc_session_alloc(&tg, attr);
  sc_attr_free(attr);
  if( rc < 0 )
    return PyErr_Format(SCError, "ERROR: Failed to allocate session\n");

  sessions = realloc(sessions,
                          (n_sessions + 1) * sizeof(*sessions));
  TEST(sessions);
  sessions[n_sessions] = tg;
  int session_i = n_sessions;
  ++n_sessions;

  return PyLong_FromLong(session_i);
}


static PyObject* session_destroy(PyObject* self, PyObject* args)
{
  PyObject *scs_obj;
  int i;

  if( ! PyArg_ParseTuple(args, "O", &scs_obj) )
    return NULL;
  i = sc_py_get_index(scs_obj, "__session_index__");
  TEST((unsigned) i < (unsigned) n_sessions);
  int rc = ALLOW_THREADS(sc_session_destroy(sessions[i]));
  sessions[i] = NULL;
  if( rc < 0 )
    return PyErr_Format(SCError, "ERROR: Failed to destroy session (%d)", rc);
  Py_RETURN_NONE;
}


static PyObject* session_prepare(PyObject* self, PyObject* args)
{
  struct sc_session* tg;
  PyObject* tg_obj;

  if( ! PyArg_ParseTuple(args, "O", &tg_obj) ||
      ! sc_py_get_session(tg_obj, &tg)        )
    return NULL;
  if( ALLOW_THREADS(sc_session_prepare(tg)) < 0 )
    return raise_session_err(tg);
  Py_RETURN_NONE;
}


static PyObject* session_go(PyObject* self, PyObject* args)
{
  struct sc_session* tg;
  PyObject* tg_obj;

  if( ! PyArg_ParseTuple(args, "O", &tg_obj) ||
      ! sc_py_get_session(tg_obj, &tg)        )
    return NULL;
  if( ALLOW_THREADS(sc_session_go(tg)) < 0 )
    return raise_session_err(tg);
  Py_RETURN_NONE;
}


static PyObject* session_run(PyObject* self, PyObject* args)
{
  struct sc_session* tg;
  PyObject* tg_obj;
  int exit_code;

  if( ! PyArg_ParseTuple(args, "O", &tg_obj) ||
      ! sc_py_get_session(tg_obj, &tg)        )
    return NULL;
  if( ALLOW_THREADS(sc_session_run(tg, &exit_code)) < 0 )
    return raise_session_err(tg);
  return PyLong_FromLong(exit_code);
}


static PyObject* session_pause(PyObject* self, PyObject* args)
{
  struct sc_session* tg;
  PyObject* tg_obj;

  if( ! PyArg_ParseTuple(args, "O", &tg_obj) ||
      ! sc_py_get_session(tg_obj, &tg)        )
    return NULL;
  if( ALLOW_THREADS(sc_session_pause(tg)) < 0 )
    return raise_session_err(tg);
  Py_RETURN_NONE;
}


static PyObject* session_stop(PyObject* self, PyObject* args)
{
  struct sc_session* tg;
  PyObject* tg_obj;
  int exit_code;

  if( ! PyArg_ParseTuple(args, "Oi", &tg_obj, &exit_code) ||
      ! sc_py_get_session(tg_obj, &tg)                     )
    return NULL;
  if( ALLOW_THREADS(sc_session_stop(tg, exit_code)) < 0 )
    return raise_session_err(tg);
  Py_RETURN_NONE;
}


static PyObject* thread_alloc(PyObject* self, PyObject* args)
{
  PyObject *attr_dict, *tg_obj;
  struct sc_session* tg;
  struct sc_attr* attr;

  if( ! PyArg_ParseTuple(args, "OO", &attr_dict, &tg_obj) ||
      ! sc_py_get_session(tg_obj, &tg)                )
    return NULL;
  if( (attr = sc_attr_from_py(attr_dict)) == NULL )
    return NULL;

  struct sc_thread* thread;
  int rc = ALLOW_THREADS(sc_thread_alloc(&thread, attr, tg));
  sc_attr_free(attr);
  if( rc < 0 )
    return raise_session_err(tg);

  threads = realloc(threads, (n_threads + 1) * sizeof(*threads));
  TEST(threads);
  threads[n_threads] = thread;
  int thread_i = n_threads;
  ++n_threads;

  return PyLong_FromLong(thread_i);
}


static PyObject* vi_group_alloc(PyObject* self, PyObject* args)
{
  PyObject *attr_dict, *tg_obj;
  struct sc_session* tg;
  struct sc_attr* attr;
  char* intf;
  int n_vis;

  if( ! PyArg_ParseTuple(args, "OOsi", &attr_dict, &tg_obj, &intf, &n_vis) ||
      ! sc_py_get_session(tg_obj, &tg)                                 )
    return NULL;
  if( (attr = sc_attr_from_py(attr_dict)) == NULL )
    return NULL;

  struct sc_vi_group* set;
  int rc = ALLOW_THREADS(sc_vi_group_alloc(&set, attr, tg, intf, n_vis));
  sc_attr_free(attr);
  if( rc < 0 )
    return raise_session_err(tg);

  vi_groups = realloc(vi_groups, (n_vi_groups + 1) * sizeof(*vi_groups));
  TEST(vi_groups);
  vi_groups[n_vi_groups] = set;
  int set_i = n_vi_groups;
  ++n_vi_groups;

  return PyLong_FromLong(set_i);
}


static PyObject* mailbox_alloc(PyObject* self, PyObject* args)
{
  PyObject *attr_dict, *thread_obj;
  struct sc_thread* thread;
  struct sc_attr* attr;

  if( ! PyArg_ParseTuple(args, "OO", &attr_dict, &thread_obj) ||
      ! sc_py_get_thread(thread_obj, &thread)                  )
    return NULL;
  if( (attr = sc_attr_from_py(attr_dict)) == NULL )
    return NULL;

  struct sc_mailbox* mailbox;
  TRY(sc_mailbox_alloc(&mailbox, attr, thread));
  sc_attr_free(attr);

  mailboxes = realloc(mailboxes, (n_mailboxes + 1) * sizeof(*mailboxes));
  TEST(mailboxes);
  mailboxes[n_mailboxes] = mailbox;
  int mailbox_i = n_mailboxes;
  ++n_mailboxes;

  nodes = realloc(nodes, (n_nodes + 1) * sizeof(*nodes));
  TEST(nodes);
  nodes[n_nodes] = sc_mailbox_get_send_node(mailbox);
  int node_i = n_nodes;
  ++n_nodes;

  return Py_BuildValue("ii", mailbox_i, node_i);
}


static PyObject* mailbox_set_recv(PyObject* self, PyObject* args)
{
  struct sc_mailbox* mailbox;
  struct sc_node* node;
  PyObject *mailbox_obj, *node_obj, *to_name_obj;
  char const* to_name = NULL;

  if( ! PyArg_ParseTuple(args, "OOO", &mailbox_obj,
                         &node_obj, &to_name_obj)  ||
      ! sc_py_get_mailbox(mailbox_obj, &mailbox)   ||
      ! sc_py_get_node(node_obj, &node)             )
    return NULL;
  if( PyUnicode_Check(to_name_obj) )
    to_name = pystring_to_cstring(to_name_obj);
  TRY(sc_mailbox_set_recv(mailbox, node, to_name));
  Py_RETURN_NONE;
}


static PyObject* mailbox_connect(PyObject* self, PyObject* args)
{
  struct sc_mailbox* sender;
  struct sc_mailbox* receiver;
  PyObject* sender_obj;
  PyObject* receiver_obj;

  if( ! PyArg_ParseTuple(args, "OO", &sender_obj, &receiver_obj) ||
      ! sc_py_get_mailbox(sender_obj, &sender)                 ||
      ! sc_py_get_mailbox(receiver_obj, &receiver)              )
    return NULL;
  sc_mailbox_connect(sender, receiver);
  Py_RETURN_NONE;
}


static int get_and_check_args(const struct sc_node_factory* factory,
                              PyObject* args_dict,
                              struct sc_arg* args, int n_args)
{
  Py_ssize_t pos = 0;
  PyObject *k, *v;
  int i;

  for( i = 0; PyDict_Next(args_dict, &pos, &k, &v); ++i ) {
    /* NB. This returns a pointer to the internal string, not a copy. */
    if( (args[i].name = pystring_to_cstring(k)) == NULL )
      return -1;
    if( PyUnicode_Check(v) ) {
      args[i].val.str = pystring_to_cstring(v);
      args[i].type = SC_PARAM_STR;
    }
    else if( PyLong_Check(v) ) {
      args[i].val.i = PyLong_AsLongLong(v);
      args[i].type = SC_PARAM_INT;
    }
    else if( PyFloat_Check(v) ) {
      args[i].val.dbl = PyFloat_AS_DOUBLE(v);
      args[i].type = SC_PARAM_DBL;
    }
    else {
      PyErr_Format(PyExc_TypeError, "Unexpected argument type for "
                   "factory(%s) arg(%s)", factory->nf_name, args[i].name);
      return -1;
    }
  }
  TEST(i == n_args);

  return 0;
}


static PyObject* node_alloc(PyObject* self, PyObject* py_args)
{
  PyObject *thread_obj, *attr_dict, *args_dict;
  const struct sc_node_factory* factory;
  char *factory_name, *factory_lib;
  struct sc_thread* thread;
  struct sc_attr* attr;

  if( ! PyArg_ParseTuple(py_args, "OOssO", &attr_dict, &thread_obj,
                         &factory_name, &factory_lib, &args_dict) ||
      ! sc_py_get_thread(thread_obj, &thread)                      )
    return NULL;
  if( ! PyDict_Check(args_dict) ) {
    PyErr_Format(PyExc_TypeError, "Expected dictionary");
    return NULL;
  }

  if( factory_lib[0] == '\0' )
    factory_lib = NULL;

  struct sc_session* tg = sc_thread_get_session(thread);
  if( sc_node_factory_lookup(&factory, tg, factory_name, factory_lib) != 0 ) {
    switch( errno ) {
    case ELIBACC:
      return PyBytes_FromFormat("Unable to open library '%s'", factory_lib);
    case ENOENT:
      return PyBytes_FromFormat("No factory '%s' in library '%s'",
                                 factory_name, factory_lib ? factory_lib : "");
    default:
      return PyBytes_FromFormat("sc_node_factory_lookup(%s, %s) failed "
                                 "(%d %s)", factory_lib ? factory_lib : "",
                                 factory_name, errno, strerror(errno));
    }
  }

  int n_args = PyDict_Size(args_dict);
  struct sc_arg args[n_args];
  if( get_and_check_args(factory, args_dict, args, n_args) < 0 )
    return NULL;
  if( (attr = sc_attr_from_py(attr_dict)) == NULL )
    return NULL;

  struct sc_node* node;
  int rc = ALLOW_THREADS(sc_node_alloc(&node, attr, thread,
                                       factory, args, n_args));
  sc_attr_free(attr);
  if( rc < 0 )
    return raise_session_err(tg);

  nodes = realloc(nodes, (n_nodes + 1) * sizeof(*nodes));
  TEST(nodes);
  nodes[n_nodes] = node;
  int node_i = n_nodes;
  ++n_nodes;

  return PyLong_FromLong(node_i);
}


static PyObject* node_alloc_from_str(PyObject* self, PyObject* py_args)
{
  PyObject *thread_obj, *attr_dict;
  struct sc_thread* thread;
  struct sc_attr* attr;
  char *node_spec;

  if( ! PyArg_ParseTuple(py_args, "OOs", &attr_dict, &thread_obj, &node_spec) ||
      ! sc_py_get_thread(thread_obj, &thread)                                  )
    return NULL;
  if( (attr = sc_attr_from_py(attr_dict)) == NULL )
    return NULL;

  struct sc_session* scs = sc_thread_get_session(thread);
  struct sc_node* node;
  int rc = ALLOW_THREADS(sc_node_alloc_from_str(&node, attr,
                                                thread, node_spec));
  sc_attr_free(attr);
  if( rc < 0 )
    return raise_session_err(scs);

  nodes = realloc(nodes, (n_nodes + 1) * sizeof(*nodes));
  TEST(nodes);
  nodes[n_nodes] = node;
  int node_i = n_nodes;
  ++n_nodes;
  return PyLong_FromLong(node_i);
}


static PyObject* node_add_link(PyObject* self, PyObject* args)
{
  PyObject *node_obj, *link_node_obj, *to_name_obj;
  char *link_name = NULL;
  char const* to_name = NULL;
  struct sc_node* link_node;
  struct sc_node* node;

  if( ! PyArg_ParseTuple(args, "OsOO", &node_obj,
                         &link_name, &link_node_obj, &to_name_obj) ||
      ! sc_py_get_node(node_obj, &node)                            ||
      ! sc_py_get_node(link_node_obj, &link_node)                   )
    return NULL;
  if( PyUnicode_Check(to_name_obj) )
    to_name = pystring_to_cstring(to_name_obj);
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(node));
  if( ALLOW_THREADS(sc_node_add_link(node, link_name,
                                     link_node, to_name)) < 0 )
    return raise_session_err(tg);
  Py_RETURN_NONE;
}


static PyObject* node_add_info(PyObject* self, PyObject* args)
{
  PyObject *node_obj, *field_val;
  char *field_name;
  struct sc_node* node;

  if( ! PyArg_ParseTuple(args, "OsO", &node_obj, &field_name, &field_val) ||
      ! sc_py_get_node(node_obj, &node)                                    )
    return NULL;

  if( PyLong_Check(field_val) )
    sc_node_add_info_int(node, field_name,
                         PyLong_AsUnsignedLongLongMask(field_val));
  else if( PyUnicode_Check(field_val) )
    sc_node_add_info_str(node, field_name, pystring_to_cstring(field_val));
  else
    return PyErr_Format(PyExc_TypeError, "expected string or integer");

  Py_RETURN_NONE;
}


static PyObject* vi_alloc(PyObject* self, PyObject* args)
{
  PyObject *thread_obj, *attr_dict;
  struct sc_thread* thread;
  struct sc_attr* attr;
  struct sc_vi* vi;
  char* intf;

  if( ! PyArg_ParseTuple(args, "OOs", &attr_dict, &thread_obj, &intf) ||
      ! sc_py_get_thread(thread_obj, &thread)                          )
    return NULL;
  if( (attr = sc_attr_from_py(attr_dict)) == NULL )
    return NULL;

  struct sc_session* tg = sc_thread_get_session(thread);
  int rc = ALLOW_THREADS(sc_vi_alloc(&vi, attr, thread, intf));
  sc_attr_free(attr);
  if( rc < 0 )
    return raise_session_err(tg);

  vis = realloc(vis, (n_vis + 1) * sizeof(*vis));
  TEST(vis);
  vis[n_vis] = vi;
  int vi_i = n_vis;
  ++n_vis;
  return PyLong_FromLong(vi_i);
}


static PyObject* vi_alloc_from_group(PyObject* self, PyObject* args)
{
  PyObject *thread_obj, *set_obj, *attr_dict;
  struct sc_thread* thread;
  struct sc_vi_group* set;
  struct sc_attr* attr;
  struct sc_vi* vi;

  if( ! PyArg_ParseTuple(args, "OOO", &thread_obj, &attr_dict, &set_obj) ||
      ! sc_py_get_thread(thread_obj, &thread)                            ||
      ! sc_py_get_vi_group(set_obj, &set)                                 )
    return NULL;
  if( (attr = sc_attr_from_py(attr_dict)) == NULL )
    return NULL;

  struct sc_session* tg = sc_thread_get_session(thread);
  int rc = ALLOW_THREADS(sc_vi_alloc_from_group(&vi, attr, thread, set));
  sc_attr_free(attr);
  if( rc < 0 )
    return raise_session_err(tg);
  vis = realloc(vis, (n_vis + 1) * sizeof(*vis));
  TEST(vis);
  vis[n_vis] = vi;
  int vi_i = n_vis;
  ++n_vis;
  return PyLong_FromLong(vi_i);
}


static PyObject* vi_set_recv_node(PyObject* self, PyObject* args)
{
  PyObject *vi_obj, *node_obj, *to_name_obj;
  struct sc_node* node;
  struct sc_vi* vi;
  const char* to_name = NULL;

  if( ! PyArg_ParseTuple(args, "OOO", &vi_obj, &node_obj, &to_name_obj) ||
      ! sc_py_get_vi(vi_obj, &vi)                                       ||
      ! sc_py_get_node(node_obj, &node)                                  )
    return NULL;
  if( PyUnicode_Check(to_name_obj) )
    to_name = pystring_to_cstring(to_name_obj);
  TRY(sc_vi_set_recv_node(vi, node, to_name));
  Py_RETURN_NONE;
}


static PyObject* vi_get_interface_name(PyObject* self, PyObject* args)
{
  PyObject *vi_obj;
  struct sc_vi* vi;

  if( ! PyArg_ParseTuple(args, "O", &vi_obj) ||
      ! sc_py_get_vi(vi_obj, &vi)             )
    return NULL;
  return PyBytes_FromString(sc_vi_get_interface_name(vi));
}


/**********************************************************************
 * Streams
 */


struct sc_stream* sc_stream_from_py(const char* stream_str,
                                    const struct sc_attr* attr,
                                    struct sc_session* tg)
{
  struct sc_stream* stream;

  if( sc_stream_alloc(&stream, attr, tg) < 0 ) {
    raise_session_err(tg);
    return NULL;
  }
  if( sc_stream_set_str(stream, stream_str) < 0 ) {
    sc_stream_free(stream);
    raise_session_err(tg);
    return NULL;
  }

  return stream;
}


static PyObject* sc_stream_get_mcast_group(PyObject* self, PyObject* args)
{
  PyObject *attr_dict, *tg_obj;
  struct sc_session* tg;
  struct sc_attr* attr;
  struct sc_stream* stream;
  const char* stream_str;
  uint32_t dhost;
  uint16_t vlan_id;

  if( ! PyArg_ParseTuple(args, "OOs", &attr_dict, &tg_obj, &stream_str) ||
      ! sc_py_get_session(tg_obj, &tg) ) {
    fprintf( stderr, "error: sc_stream_get_mcast_group: No session provided\n" );
    return NULL;
    }
  if( (attr = sc_attr_from_py(attr_dict)) == NULL ) {
    fprintf( stderr, "error: sc_stream_get_mcast_group: Could not parse attributes.\n");
    return NULL;
    }
  stream = sc_stream_from_py(stream_str, attr, tg);
  sc_attr_free(attr);
  if( stream == NULL ) {
    fprintf( stderr, "error: sc_stream_get_mcast_group: Stream is empty.\n");
    return NULL;
    }

  if( __sc_stream_extract_mcast_group(stream, &dhost) != 0 ) {
    return Py_None;
  }
  else if( __sc_stream_extract_vlan_id(stream, &vlan_id) != 0 ) {
    return PyBytes_FromFormat("%d.%d.%d.%d", dhost >> 24,
                               (dhost >> 16) & 0xFF,
                               (dhost >> 8) & 0xFF,
                               dhost & 0xff);
  }
  else
    return PyBytes_FromFormat("vid=%d,%d.%d.%d.%d", vlan_id,
                               dhost >> 24,
                               (dhost >> 16) & 0xFF,
                               (dhost >> 8) & 0xFF,
                               dhost & 0xff);
}


static PyObject* vi_add_stream(PyObject* self, PyObject* args)
{
  PyObject *vi_obj, *attr_dict;
  char* stream_str;
  struct sc_session* tg;
  struct sc_stream* stream;
  struct sc_attr* attr;
  struct sc_vi* vi;

  if( ! PyArg_ParseTuple(args, "OsO", &vi_obj,
                         &stream_str, &attr_dict) ||
      ! sc_py_get_vi(vi_obj, &vi)                  )
    return NULL;
  if( (attr = sc_attr_from_py(attr_dict)) == NULL )
    return NULL;

  tg = sc_thread_get_session(sc_vi_get_thread(vi));
  stream = sc_stream_from_py(stream_str, attr, tg);
  sc_attr_free(attr);
  if( stream == NULL )
    return NULL;
  int rc = ALLOW_THREADS(sc_vi_add_stream(vi, stream));
  sc_stream_free(stream);
  if( rc < 0 )
    return raise_session_err(tg);
  Py_RETURN_NONE;
}


static PyObject* vi_group_add_stream(PyObject* self, PyObject* args)
{
  PyObject *vi_group_obj, *attr_dict;
  char* stream_str;
  struct sc_vi_group* vi_group;
  struct sc_session* tg;
  struct sc_stream* stream;
  struct sc_attr* attr;

  if( ! PyArg_ParseTuple(args, "OsO", &vi_group_obj,
                         &stream_str, &attr_dict)  ||
      ! sc_py_get_vi_group(vi_group_obj, &vi_group) )
    return NULL;
  if( (attr = sc_attr_from_py(attr_dict)) == NULL )
    return NULL;
  tg = sc_vi_group_get_session(vi_group);
  stream = sc_stream_from_py(stream_str, attr, tg);
  sc_attr_free(attr);
  if( stream == NULL )
    return NULL;
  int rc = ALLOW_THREADS(sc_vi_group_add_stream(vi_group, stream));
  sc_stream_free(stream);
  if( rc < 0 )
    return raise_session_err(tg);
  Py_RETURN_NONE;
}


static PyObject* join_mcast_group(PyObject* self, PyObject* args)
{
  struct sc_session* tg;
  char *intf, *group;
  PyObject* tg_obj;

  if( ! PyArg_ParseTuple(args, "Oss", &tg_obj, &intf, &group) ||
      ! sc_py_get_session(tg_obj, &tg)                         )
    return NULL;
  if( ALLOW_THREADS(sc_join_mcast_group(tg, intf, group)) < 0 )
    return raise_session_err(tg);
  Py_RETURN_NONE;
}


static PyObject* efvi_ver(PyObject* self, PyObject* args)
{
  const char* version = COMPILED_EF_VI_VERSION;
  return PyUnicode_Decode(version, strlen(version), "utf-8", "strict");
}

static PyObject* attr_doc(PyObject* self, PyObject* args)
{
  PyObject* list;
  const char* attr_name;
  const char** docs;
  int i, docs_len;

  if( ! PyArg_ParseTuple(args, "s", &attr_name) )
    return NULL;
  if( sc_attr_doc(attr_name, &docs, &docs_len) < 0 )
    return PyErr_Format(PyExc_ValueError, "no attribute named %s", attr_name);
  if( ! (list = PyList_New(docs_len)) ) {
    free(docs);
    return NULL;
  }
  for( i = 0; i < docs_len; ++i )
    PyList_SET_ITEM(list, i, PyBytes_FromString(docs[i]));
  free(docs);
  return list;
}


#define method(name, doc)                               \
  { #name, (PyCFunction) (name), METH_VARARGS, (doc) }


static PyMethodDef solar_capture_c_methods[] = {
  method(vi_group_alloc, "Create a vi group"),

  method(session_alloc, "Create a session"),
  method(session_destroy, "Destroy a session"),
  method(session_prepare, "Prepare session"),
  method(session_go, "Prepare session and start threads"),
  method(session_run, "Prepare session, start threads, block 'till stopped"),
  method(session_pause, "Pause session threads"),
  method(session_stop, "Pause session threads and unblock session_run"),

  method(thread_alloc, "Create a thread"),

  method(mailbox_alloc, "Create a mailbox"),
  method(mailbox_set_recv, "Set recv on an mbox node"),
  method(mailbox_connect, "Connect mbox nodes"),

  method(node_alloc, "Create a node"),
  method(node_alloc_from_str, "Create a node from a string specification"),
  method(node_add_link, "Add a link to node"),
  method(node_add_info, "Add info to a node"),

  method(vi_alloc, "Create a VI"),
  method(vi_alloc_from_group, "Create a VI within a set"),
  method(vi_set_recv_node, "Set receive node for a VI"),
  method(vi_get_interface_name, "Get name of interface associated with VI"),

  method(sc_stream_get_mcast_group, "Extract multicast group from a stream"),
  method(vi_add_stream, "Add a stream to a VI"),
  method(vi_group_add_stream, "Add a stream to a VI set"),

  method(join_mcast_group, "Join multicast group"),

  method(sc_initgroups, "C initgroups: initialise the group access list"),

  method(efvi_ver, "Retreive version of libraries SolarCapture is linked against"),
  method(attr_doc, "Retrieve documentation for attributes"),

  {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC PyInit_solar_capture_c(void)
{
  static struct PyModuleDef module_definition = {
    PyModuleDef_HEAD_INIT,
    "solar_capture_c",          /* name */
    "",                         /* docs */
    -1,                         /* reserved size */
    solar_capture_c_methods
  };
  PyObject* module = PyModule_Create(&module_definition);

  if( module == NULL )
    return NULL;

  PyModule_AddIntConstant(module, "SC_CSUM_ERROR", SC_CSUM_ERROR);
  PyModule_AddIntConstant(module, "SC_CRC_ERROR", SC_CRC_ERROR);
  PyModule_AddIntConstant(module, "SC_TRUNCATED", SC_TRUNCATED);
  PyModule_AddIntConstant(module, "SC_MCAST_MISMATCH", SC_MCAST_MISMATCH);
  PyModule_AddIntConstant(module, "SC_UCAST_MISMATCH", SC_UCAST_MISMATCH);
  PyModule_AddStringConstant(module, "SC_VER", SC_VER);

  SCError = PyErr_NewException("solar_capture_c.SCError", NULL, NULL);
  PyModule_AddObject(module, "SCError", SCError);

  return module;
}
