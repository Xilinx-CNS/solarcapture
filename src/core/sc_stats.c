/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <fcntl.h>
#include <pwd.h>
#include <dirent.h>
#include <limits.h>


#define SC_PURGE_DAYS_DEFAULT    7

/* Align stats blocks to this boundary.  Max field size is 8 bytes, so this
 * should ensure fields are naturally aligned (subject to offsets being
 * aligned).
 */
#define STATS_ALIGN              8


static char* log_dir_prefix;


static int sc_stats_session_purge(struct sc_session* tg,
                                  const char* s_dir_path,
                                  int s_dir_fd, int parent_dir_fd,
                                  const char* s_dir)
{
  struct dirent* dp;
  DIR* dir;
  int rc = -1;

  sc_trace(tg, "%s: %s\n", __func__, s_dir_path);

  if( (dir = fdopendir(dup(s_dir_fd))) == NULL ) {
    sc_warn(tg, "%s: ERROR: fdopendir(%s) failed (%d, %s)\n",
            __func__, s_dir_path, errno, strerror(errno));
    return -1;
  }
  while( 1 ) {
    errno = 0;
    if( (dp = readdir(dir)) == NULL && errno != 0 ) {
      sc_warn(tg, "%s: ERROR: readdir(%s) failed (%d, %s)\n",
              __func__, s_dir_path, errno, strerror(errno));
      goto out;
    }
    if( dp == NULL )
      break;
    if( ! strcmp(dp->d_name, ".") || ! strcmp(dp->d_name, "..") )
      continue;
    if( (rc = unlinkat(s_dir_fd, dp->d_name, 0)) < 0 )
      sc_warn(tg, "%s: ERROR: unlinkat(%s/%s) failed (%d, %s)\n",
              __func__, s_dir_path, dp->d_name, errno, strerror(errno));
  }
  if( (rc = unlinkat(parent_dir_fd, s_dir, AT_REMOVEDIR)) < 0 ) {
    sc_warn(tg, "%s: ERROR: unlinkat(%s/) failed (%d, %s)\n",
            __func__, s_dir_path, errno, strerror(errno));
    goto out;
  }
  rc = 0;

 out:
  closedir(dir);
  return rc;
}


static int sc_stats_session_is_running(struct sc_session* tg, int s_dir_fd)
{
  int pid, info_fd, rc = -1;
  int fd = openat(s_dir_fd, "sc_info", O_RDONLY);
  if( fd >= 0 ) {
    FILE* fp = fdopen(fd, "r");
    if( fp != NULL ) {
      char buf[80];
      if( fgets(buf, sizeof(buf), fp) != NULL &&
          sscanf(buf, "info: pid %d", &pid) == 1 &&
          fgets(buf, sizeof(buf), fp) != NULL &&
          sscanf(buf, "info: sc_info_fd %d", &info_fd) == 1 ) {
        char proc_path[128];
        struct stat s1, s2;
        sprintf(proc_path, "/proc/%d/fd/%d", pid, info_fd);
        if( fstatat(s_dir_fd, "sc_info", &s2, AT_SYMLINK_NOFOLLOW) == 0 )
          rc = stat(proc_path, &s1) == 0 &&
            s1.st_dev == s2.st_dev && s1.st_ino == s2.st_ino;
      }
      fclose(fp);
    }
    else
      close(fd);
  }
  return rc;
}


static int sc_stats_session_age(struct sc_session* tg, int s_dir_fd)
{
  struct stat s;
  if( fstatat(s_dir_fd, "sc_info", &s, AT_SYMLINK_NOFOLLOW) == 0 )
    return time(NULL) - s.st_mtime;
  return -1;
}


static int sc_stats_try_purge_old_pid(struct sc_session* tg,
                                      const char* pid_dir_path,
                                      int pid_dir_fd)
{
  char s_dir_path[strlen(pid_dir_path) + 20];
  struct dirent* dp;
  DIR* dir;
  int rc = -1, all_gone = 1, any_sessions = 0;

  sc_trace(tg, "%s: %s\n", __func__, pid_dir_path);

  static int max_session_age_days;
  if( max_session_age_days == 0 ) {
    const char* s = getenv("SC_PURGE_DAYS");
    max_session_age_days = SC_PURGE_DAYS_DEFAULT;
    if( s != NULL && (max_session_age_days = atoi(s)) == 0 )
      /* 0 means don't ever purge.  (Avoid overflow: 68 years.) */
      max_session_age_days = INT_MAX / (24*60*60);
  }

  /* Find all sessions, and purge if old and not running.
   *
   * FIXME: The check to see whether a session is running fails if the pid
   * that created the session has gone away.  eg. If the process has
   * daemonised.  So we can purge log dirs for long running sessions.
   */
  if( (dir = fdopendir(pid_dir_fd)) == NULL ) {
    sc_warn(tg, "%s: ERROR: fdopendir(%s) failed (%d, %s)\n",
            __func__, pid_dir_path, errno, strerror(errno));
    close(pid_dir_fd);
    return -1;
  }
  while( 1 ) {
    errno = 0;
    if( (dp = readdir(dir)) == NULL && errno != 0 ) {
      sc_warn(tg, "%s: ERROR: readdir(%s) failed (%d, %s)\n",
              __func__, pid_dir_path, errno, strerror(errno));
      goto out;
    }
    if( dp == NULL )
      break;
    if( ! strcmp(dp->d_name, ".") || ! strcmp(dp->d_name, "..") )
      continue;
    any_sessions = 1;
    char dummy;
    int sess_id;
    if( sscanf(dp->d_name, "%d%c", &sess_id, &dummy) != 1 ) {
      sc_warn(tg, "%s: WARNING: unexpected '%s' in '%s'\n",
              __func__, dp->d_name, pid_dir_path);
      goto out;
    }
    int s_dir_fd = openat(pid_dir_fd, dp->d_name, O_DIRECTORY | O_RDONLY);
    if( s_dir_fd >= 0 ) {
      sprintf(s_dir_path, "%s/%s", pid_dir_path, dp->d_name);
      int is_running = sc_stats_session_is_running(tg, s_dir_fd);
      int age = sc_stats_session_age(tg, s_dir_fd);
      sc_trace(tg, "%s: %s running=%d age=%.1f\n",
               __func__, s_dir_path, is_running, age / (24*60*60.0));
      if( is_running == 0 && age > max_session_age_days * 24*60*60 ) {
        if( sc_stats_session_purge(tg, s_dir_path, s_dir_fd,
                                   pid_dir_fd, dp->d_name) < 0 ) {
          sc_warn(tg, "%s: WARNING: failed to purge %s\n",
                  __func__, s_dir_path);
          all_gone = 0;
        }
      }
      else
        all_gone = 0;
      close(s_dir_fd);
    }
  }
  if( any_sessions && all_gone && (rc = rmdir(pid_dir_path)) < 0 ) {
    sc_warn(tg, "%s: WARNING: unlinkat(%s/) failed (%d, %s)\n",
            __func__, pid_dir_path, errno, strerror(errno));
    goto out;
  }
  rc = 0;

 out:
  closedir(dir);
  return rc;
}


static int scan_filter(const struct dirent* dp)
{
  return strncmp(dp->d_name, log_dir_prefix, strlen(log_dir_prefix)) == 0;
}


static void sc_stats_purge_old(struct sc_session* tg, const char* base_path)
{
  struct dirent** namelist;
  int n = scandir(base_path, &namelist, scan_filter, NULL);
  if( n < 0 ) {
    sc_warn(tg, "%s: ERROR: scandir(%s) failed %d, %s\n", __func__,
            base_path, errno, strerror(errno));
    return;
  }
  while( n-- ) {
    const char* dir = namelist[n]->d_name;
    char pid_dir_path[strlen(dir) + strlen(base_path) + 10];
    sprintf(pid_dir_path, "%s/%s", base_path, dir);
    int pid_dir_fd = open(pid_dir_path, O_DIRECTORY | O_RDONLY);
    if( pid_dir_fd >= 0 )
      sc_stats_try_purge_old_pid(tg, pid_dir_path, pid_dir_fd);
    free(namelist[n]);
  }
  free(namelist);
}


static int sc_stats_create_log_dir(struct sc_session* tg,
                                   const struct sc_attr* attr)
{
  const char* base_dir_path = "/var/tmp";
  if( attr->log_base_dir != NULL )
    base_dir_path = attr->log_base_dir;

  static char* user;
  if( user == NULL ) {
    struct passwd pwd_s, *pwd;
    char buf[1024];
    TEST(getpwuid_r(geteuid(), &pwd_s, buf, sizeof(buf), &pwd) == 0);
    TEST(pwd != NULL);
    user = strdup(pwd->pw_name);
    TEST(asprintf(&log_dir_prefix, "solar_capture_%s_", user) > 0);
  }

  sc_stats_purge_old(tg, base_dir_path);

  TEST(tg->tg_stats_dir_name == NULL );
  if( attr->log_dir != NULL ) {
    tg->tg_stats_dir_name = strdup(attr->log_dir);
  }
  else {
    char pid_dir_path[strlen(base_dir_path) + strlen(log_dir_prefix) + 20];
    sprintf(pid_dir_path, "%s/%s%d", base_dir_path, log_dir_prefix,
            (int) getpid());
    if( mkdir(pid_dir_path, S_IRWXU|S_IRWXG|S_IRWXO) < 0 && tg->tg_id == 0 ) {
      /* Must be left over from previous process with same pid. */
      char cmd[strlen(pid_dir_path) + 40];
      sprintf(cmd, "rm -rf '%s'", pid_dir_path);
      system(cmd);
      mkdir(pid_dir_path, S_IRWXU|S_IRWXG|S_IRWXO);
    }
    TEST(asprintf(&tg->tg_stats_dir_name, "%s/%d",
                  pid_dir_path, tg->tg_id) > 0);
  }

  sc_info(tg, "SolarCapture session=%d/%d log=%s\n",
          (int) getpid(), tg->tg_id, tg->tg_stats_dir_name);

  int rc = mkdir(tg->tg_stats_dir_name, S_IRWXU|S_IRWXG|S_IRWXO);
  if( rc )
    return sc_set_err(tg, errno,
                      "%s: ERROR: unable to create log directory '%s'\n",
                      __func__, tg->tg_stats_dir_name);
  return 0;
}


static int sc_stats_create_info_file(struct sc_session* tg,
                                     const struct sc_attr* attr)
{
  TEST(tg->tg_info_file == NULL);

  char filename[strlen(tg->tg_stats_dir_name) + 20];
  sprintf(filename, "%s/sc_info", tg->tg_stats_dir_name);
  int fd;
  TRY(fd = open(filename, O_RDWR|O_CREAT|O_TRUNC,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
  tg->tg_info_file = fdopen(fd, "w");
  TRY(tg->tg_info_file == NULL ? -1 : 0);

  /* NB. Purging code relies on 'pid' first then 'fd'. */
  fprintf(tg->tg_info_file, "info: pid %d\n", (int) getpid());
  fprintf(tg->tg_info_file, "info: sc_info_fd %d\n", fd);

  fprintf(tg->tg_info_file, "info: name %s\n", attr->name);
  fprintf(tg->tg_info_file, "info: group_name %s\n", attr->group_name);
  fprintf(tg->tg_info_file, "info: version %s\n", SC_VER);
  fprintf(tg->tg_info_file, "info: src_id %s\n", "%{SC_SRC_ID}");
  fprintf(tg->tg_info_file, "info: uid %d\n", (int) getuid());
  fprintf(tg->tg_info_file, "info: euid %d\n", (int) geteuid());
  fprintf(tg->tg_info_file, "info: id %d\n", tg->tg_id);
  fflush(tg->tg_info_file);
  return 0;
}


static int sc_stats_create_type_file(struct sc_session* tg)
{
  TEST(tg->tg_type_file == NULL);
  char filename[strlen(tg->tg_stats_dir_name) + 20];
  sprintf(filename, "%s/sc_types", tg->tg_stats_dir_name);
  int fd;
  TRY(fd = open(filename, O_RDWR|O_CREAT|O_TRUNC,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
  tg->tg_type_file = fdopen(fd, "w");
  TRY(tg->tg_type_file == NULL ? -1 : 0);
  return 0;
}


static int sc_stats_write_builtin_types(struct sc_session* scs)
{
#define __scs scs
#define ST_CONSTANT(name, val)  sc_montype_constant(__scs, #name, val);
#define ST_STRUCT(name)         sc_montype_struct(__scs, #name);
#define ST_FIELD_STR(name, len, kind)                   \
  sc_montype_field(__scs, #name, "str", #kind, #len);
#define ST_FIELD(type, name, kind)                      \
  sc_montype_field(__scs, #name, #type, #kind, NULL);
#define ST_STRUCT_END           sc_montype_struct_end(__scs);
#include <sc_internal/stats_tmpl.h>
  sc_montype_flush(__scs);
  return 0;
}


int sc_stats_new_session(struct sc_session* tg, const struct sc_attr* attr)
{
  int rc;
  if( (rc = sc_stats_create_log_dir(tg, attr)) < 0 )
    return rc;
  if( (rc = sc_stats_create_info_file(tg, attr)) < 0 )
    return rc;
  if( (rc = sc_stats_create_type_file(tg)) < 0 )
    return rc;
  if( (rc = sc_stats_write_builtin_types(tg)) < 0 )
    return rc;
  return 0;
}


union pp_void {
  void*  p;
  void** pp;
};


int sc_stats_add_block(struct sc_thread* thread, const char* name,
                       const char* type_name, const char* type_code,
                       int id, int size, void* pp_area)
{
  struct sc_session* tg = thread->session;

  TEST(tg->tg_stats_dir_name != NULL);

  if( ! tg->tg_stats_file_size ) {
    const char* s = getenv("SC_LOG_FILE_SIZE");
    if( s != NULL )
      tg->tg_stats_file_size = atoi(s);
    else
      tg->tg_stats_file_size = 1 << 20;
  }
  if( ! thread->stats_header ) {
    char filename[128];
    snprintf(filename, 128, "%s/sc_thread%d.tss",
             tg->tg_stats_dir_name, thread->id);
    int fd;
    TRY(fd = open(filename, O_RDWR|O_CREAT|O_TRUNC,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
    TRY(ftruncate(fd, tg->tg_stats_file_size));
    thread->stats_header = mmap(NULL, tg->tg_stats_file_size,
                                PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    TRY(close(fd));
    thread->stats_header->total_length =
      roundup(sizeof(struct sc_stats_file_header), STATS_ALIGN);
  }

  struct sc_stats_file_header* head = thread->stats_header;
  int obj_off = head->total_length;
  SC_TEST( (obj_off & (STATS_ALIGN - 1)) == 0 );
  int new_total_len = obj_off + roundup(size, STATS_ALIGN);
  void* p;

  if( new_total_len >= tg->tg_stats_file_size ) {
    TEST(p = calloc(1, size));
    sc_err(tg, "%s: ERROR: log file too small (%d bytes), stats "
           "for %s not stored\n", __func__, tg->tg_stats_file_size, name);
  }
  else {
    p = (void*) ((uintptr_t) head + obj_off);
    head->total_length = new_total_len;
    fprintf(tg->tg_info_file, "obj: %s %s%d %s %d %d %d\n",
            type_name, type_code, id, name, thread->id, obj_off, size);
    fflush(tg->tg_info_file);
  }

  union pp_void v;
  v.p = pp_area;
  *v.pp = p;
  return 0;
}


void sc_stats_add_info_str(struct sc_session* scs, const char* type_code,
                           int id, const char* key, const char* val)
{
  fprintf(scs->tg_info_file, "objinfo: %s%d str %s %s\n",
          type_code, id, key, val);
  fflush(scs->tg_info_file);
}


void sc_stats_add_info_int(struct sc_session* scs, const char* type_code,
                           int id, const char* key, int64_t val)
{
  fprintf(scs->tg_info_file, "objinfo: %s%d int %s %"PRIi64"\n",
          type_code, id, key, val);
  fflush(scs->tg_info_file);
}


void sc_stats_add_info_int_list(struct sc_session* scs, const char* type_code,
                                int id, const char* key, int64_t val)
{
  fprintf(scs->tg_info_file, "objinfo: %s%d intlist %s %"PRIi64"\n",
          type_code, id, key, val);
  fflush(scs->tg_info_file);
}


void sc_stats_add_info_nodelink(struct sc_session* scs, int from_id,
                                const char* link_name, int to_id,
                                const char* to_name_opt)
{
  if( to_name_opt )
    fprintf(scs->tg_info_file, "nodelink: n%d n%d \"%s\" \"%s\"\n",
            from_id, to_id, link_name, to_name_opt);
  else
    fprintf(scs->tg_info_file, "nodelink: n%d n%d \"%s\" NULL\n",
            from_id, to_id, link_name);
  fflush(scs->tg_info_file);
}


/* Returns true if this stats type is new to the session or false otherwise */
static bool add_stats_type_once(struct sc_session* tg, const char* stats_type)
{
  int i;
  for( i = 0; i < tg->tg_stats_types_n; ++i )
    if( !strcmp(stats_type, tg->tg_stats_types[i]) )
      return false;
  SC_REALLOC(&tg->tg_stats_types, ++tg->tg_stats_types_n);
  tg->tg_stats_types[tg->tg_stats_types_n - 1] = strdup(stats_type);
  return true;
}

void sc_montype_constant(struct sc_session* tg, const char* name, int val)
{
  if( add_stats_type_once(tg, name) )
    fprintf(tg->tg_type_file, "%s = %d\n", name, val);
}


void sc_montype_struct(struct sc_session* tg, const char* name)
{
  if( (tg->tg_write_stats_types = add_stats_type_once(tg, name)) )
    fprintf(tg->tg_type_file, "%s = sw.StructType('%s', [\n", name, name);
}


void sc_montype_field(struct sc_session* tg, const char* name,
                      const char* type, const char* kind, const char* more)
{
  if( !tg->tg_write_stats_types )
    return;
  if( ! strcmp(type, "str") )
    fprintf(tg->tg_type_file, "  ('%s', '%%ds' %% %s, '%s'),\n",
            name, more, kind);
  else if( ! strcmp(type, "int") )
    fprintf(tg->tg_type_file, "  ('%s', 'i', '%s'),\n", name, kind);
  else if( ! strcmp(type, "int64_t") )
    fprintf(tg->tg_type_file, "  ('%s', 'q', '%s'),\n", name, kind);
  else if( ! strcmp(type, "uint64_t") )
    fprintf(tg->tg_type_file, "  ('%s', 'Q', '%s'),\n", name, kind);
  else if( ! strcmp(type, "double") )
    fprintf(tg->tg_type_file, "  ('%s', 'd', '%s'),\n", name, kind);
  else
    SC_TEST(0);/*??*/
}


void sc_montype_struct_end(struct sc_session* tg)
{
  if( tg->tg_write_stats_types )
    fprintf(tg->tg_type_file, "  ])\n");
}


void sc_montype_flush(struct sc_session* tg)
{
  fflush(tg->tg_type_file);
}
