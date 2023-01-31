/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_UTILS_H__
#define __SC_UTILS_H__


#include <stdbool.h>


#define SC_NS_IN_S 1000000000ULL
#define SC_US_IN_S 1000000ULL
#define SC_NS_IN_US 1000ULL
#define SC_MS_IN_S 1000ULL
#define SC_NS_IN_MS 1000000ULL


/* NB. pp_area is really a pointer-to-pointer but declaring as void* allows
 * us to avoid a cast in SC_REALLOC().
 */
extern void sc_realloc(void* pp_area, size_t new_size);

#define SC_REALLOC(pp_area, n)                          \
  sc_realloc((pp_area), (n) * sizeof(**(pp_area)))


/* Return true if [prefix] matches beginning of [str], and optionally store
 * a pointer to the suffix.
 */
extern bool sc_match_prefix(const char* str, const char* prefix,
                            const char** suffix_out_opt);


/* Similar to strtok_r(), except: Supports only a single delimiter, and the
 * delimiter can be escaped with a backslash.  Backslash escapes all
 * following characters.  ie. \c is replaced by c for all c except NUL.
 *
 * Example: "ab;cd\;ef;\\\h\\\" yields the tokens "ab", "cd;ef" and "\h\\".
 */
extern char* sc_strtok_r(char* str, char delim, char** saveptr);


/* Convert string to integer and perform range check.  Returns 0 if string
 * is an integer and in range.  Returns -EINVAL if not a string, and
 * -ERANGE if not in range.
 */
extern int sc_strtoi_range(int* res_out, const char* str, int base,
                           int min, int max);


/* Return true if fd is readable.  Requires a sys-call, so not hugely fast! */
extern bool sc_fd_is_readable(int fd);


#define ALIGN_FWD(p, align)               (((p)+(align)-1u) & ~((align)-1u))
#define SC_MIN(a, b)                      (((a) < (b)) ? (a) : (b))
#define SC_MAX(a, b)                      (((a) > (b)) ? (a) : (b))


/* Emit message to log unconditionally. */
extern void sc_log(struct sc_session*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));

/* Emit message to log depending on log level. */
extern void sc_err(struct sc_session*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));
extern void sc_warn(struct sc_session*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));
extern void sc_info(struct sc_session*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));
extern void sc_trace(struct sc_session*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));

extern void sc_errv(struct sc_session*, const char* fmt, va_list args);

/* Emit message to log only in debug builds (and appropriate log level. */
#ifdef NDEBUG
# define sc_tracefp(tg, ...)  do{ (void) (tg); }while(0)
#else
extern void sc_tracefp(struct sc_session*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));
#endif


extern int __sc_set_err(struct sc_session* tg, const char* file, int line,
                        const char* func, int errno_code, const char* fmt, ...)
  __attribute__((format(printf,6,7)));

extern int __sc_store_err(struct sc_session* tg, const char* file, int line,
                        const char* func, int errno_code, const char* fmt, ...)
  __attribute__((format(printf,6,7)));

extern int sc_commit_err(struct sc_session*);

extern void sc_undo_err(struct sc_session*);

extern int __sc_fwd_err(struct sc_session* tg, const char* file, int line,
                        const char* func, const char* fmt, ...)
  __attribute__((format(printf,5,6)));

#define sc_set_err(tg, errno_code, ...)                                 \
  __sc_set_err((tg), __FILE__, __LINE__, __func__, (errno_code), __VA_ARGS__)

#define sc_store_err(tg, errno_code, ...)                               \
  __sc_store_err((tg), __FILE__, __LINE__, __func__, (errno_code), __VA_ARGS__)

#define sc_fwd_err(tg, ...)                                     \
  __sc_fwd_err((tg), __FILE__, __LINE__, __func__, __VA_ARGS__)


#define SC_TRY(x)                                                       \
  do {                                                                  \
    int __rc = (x);                                                     \
    if( __rc < 0 ) {                                                    \
      fprintf(stderr, "ERROR: %s: SC_TRY(%s) failed\n", __func__, #x);  \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",                   \
              __rc, errno, strerror(errno));                            \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


#define SC_TEST(x)                                                      \
  do {                                                                  \
    if( ! (x) ) {                                                       \
      fprintf(stderr, "ERROR: %s: SC_TEST(%s) failed\n", __func__, #x); \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


static inline int sc_timespec_le(struct timespec a, struct timespec b)
{
  return a.tv_sec < b.tv_sec ||
    (a.tv_sec == b.tv_sec && a.tv_nsec <= b.tv_nsec);
}


static inline int64_t sc_timespec_diff_ns(struct timespec a, struct timespec b)
{
  assert(a.tv_nsec >= 0 && a.tv_nsec < 1000000000);
  assert(b.tv_nsec >= 0 && b.tv_nsec < 1000000000);
  return (a.tv_sec - b.tv_sec) * (int64_t) 1000000000
    + (a.tv_nsec - b.tv_nsec);
}


static inline void sc_timespec_add(struct timespec* a, struct timespec b)
{
  assert(a->tv_nsec >= 0 && a->tv_nsec < 1000000000);
  assert(b.tv_nsec >= 0 && b.tv_nsec < 1000000000);
  a->tv_sec += b.tv_sec;
  a->tv_nsec += b.tv_nsec;
  if( a->tv_nsec >= 1000000000 ) {
    a->tv_sec += 1;
    a->tv_nsec -= 1000000000;
  }
}


/* Fill a char buffer that holds a string, but should not be
 * nul-terminated when full.
 *
 * (You can use strncpy() to do this, but modern compilers complain
 * when the bound matches the dest buffer size).
 */
static inline char* sc_fill_char_buf(char* dest, size_t dest_size,
                                     const char* src)
{
  size_t src_len = strlen(src) + 1;
  return memcpy(dest, src, (src_len <= dest_size) ? src_len : dest_size);
}


struct sc_bitmask {
  uint64_t* bm_masks;
  int       bm_num_masks;
};

#define SC_BITMASK_PER_MASK_LEN (int)(sizeof(((struct sc_bitmask *)(0))->bm_masks) * 8)

extern void sc_bitmask_init(struct sc_bitmask* masks);

extern void sc_bitmask_free(struct sc_bitmask* masks);

extern void sc_bitmask_clear_all(struct sc_bitmask* masks);

extern void sc_bitmask_set(struct sc_bitmask* masks, int bit_id);

extern bool sc_bitmask_is_set(const struct sc_bitmask* masks, int bit_id);

extern void sc_bitmask_or(struct sc_bitmask* dest,
                          const struct sc_bitmask* src);

extern void sc_bitmask_and(struct sc_bitmask* dest,
                           const struct sc_bitmask* src);

extern int sc_bitmask_ffs(const struct sc_bitmask* masks);

extern char* sc_bitmask_fmt(const struct sc_bitmask* masks);

extern bool sc_bitmask_is_equal(const struct sc_bitmask* bm1,
                                const struct sc_bitmask* bm2);

extern bool sc_bitmask_is_single_bit(const struct sc_bitmask* masks,
                                     int bit_id);

/* [dest] is constructed by this call. */
extern void sc_bitmask_duplicate(struct sc_bitmask* dest,
                                 const struct sc_bitmask* src);

#endif  /* __SC_UTILS_H__ */
