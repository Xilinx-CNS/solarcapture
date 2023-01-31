/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 1
#include <solar_capture.h>
#include <solar_capture_ext.h>

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>

/*****************************************************************************/


#define NSEC_IN_SEC       1000000000

/*
 * Default values for the encoded distributions.
 *
 * Apart from being chosen so that the associated distribution generates
 * values greater than the recommended minimum in each case (see the function
 * characterisation comment prior to each distribution function for details
 * on what that minimum is), the specified values have no particular rational
 * for their selection.
 *
 */
#define CP_DELAY_DEFAULT  100    /* constant distribution */
#define DU_MIN_DEFAULT    200    /* uniform distribution */
#define DU_MAX_DEFAULT    2000   /* uniform distribution */
#define DN_MEAN_DEFAULT   1000   /* normal distribution */
#define DN_STDEV_DEFAULT  100    /* normal distribution */
#define DE_MEAN_DEFAULT   300    /* exponential distribution */

#define TRY(x)                                                  \
  do {                                                          \
    int __rc = (x);                                             \
    if( __rc < 0 ) {                                            \
      fprintf(stderr, "ERROR: TRY(%s) failed\n", #x);           \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",           \
              __rc, errno, strerror(errno));                    \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )


#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: TEST(%s) failed\n", #x);          \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )


/*****************************************************************************/


enum dists {
  DIST_TYPE_CONSTANT,
  DIST_TYPE_UNIFORM,
  DIST_TYPE_NORMAL,
  DIST_TYPE_EXPONENTIAL
};

struct dist_uniform {
  int du_min;
  int du_max;
};

struct dist_normal {
  int dn_mean;
  int dn_stdev;

  double dn_result1;
  double dn_result2;
  bool dn_use_result2;
};

struct dist_exponential {
  int de_mean;
  int de_lambda;
};

struct constant_params {
  int cp_delay;
};

struct distribution {
  enum dists dn_type;

  union {
    struct dist_uniform unif_params;
    struct dist_normal norm_params;
    struct dist_exponential exp_params;
    struct constant_params const_params;
  } params;

  unsigned int default_random_gen_seed;

  uint64_t (* rv_gen)(struct distribution* j);
};

struct jitter {
  struct distribution distro;

  bool first_pkt;
  uint64_t last_ts_sec;
  uint32_t last_ts_nsec;

  struct sc_node_link* next_hop;
};


/*****************************************************************************/


/*
 * module specific functions - statistical random
 * variate generators and command line parsers
 */

/*
 * generate constant inter-packet delay. Any uint64_t value is allowed
 */
static uint64_t rconst(struct distribution* j)
{
  return j->params.const_params.cp_delay;
}


/*
 * generate uniform random variate
 * function to return a random value, sampled from a uniform distribution
 * with parameters specified by jitter.unif. any range of uint64_t values
 * is allowed
 *
 * characterised behaviour of uniform distribution:
 * ------------------------------------------------
 * We want to check the amount of jitter this function is introducting.
 *
 * The characterisation observed a number of latency outliers of over 1
 * microsecond over the course of the experiment. However, as these events
 * typically occurred every 1 to 4 millisconds over the course of the
 * experiment, they were attributed so some external system process, and were
 * discounted.
 *
 * After discarding the observed microsecond latency outliers, the function
 * was observed to take sub 100 nanoseconds to run, except for a series of
 * outliers (85, over the course of the experiment).
 *
 * Conclusion: provided that this function is not expected to provide values
 * less than 100 nanoseconds inter-packet gap, it is sufficient for this purpose.
 * This translates to a packet rate of 10 million packets per second.
 *
 */
static uint64_t runif(struct distribution* ref)
{
  uint64_t range = ref->params.unif_params.du_max -
                   ref->params.unif_params.du_min;
  uint64_t rand_val = ((rand_r(&ref->default_random_gen_seed) % range) +
                      ref->params.unif_params.du_min);
  return rand_val;
}


/*
 * function to return a random value, sampled from a normal distribution.
 * actually calculates 2 samples, saves 2nd for next call. Uses the Box-
 * Muller transformation (Marsaglia polar method) to produce a pair of
 * random normal variates from a pair of uniform random variates.
 * 
 * Uses the Marsaglia polar method to generate two suitable random variates
 * both of which lie within the unit circle.
 *
 * characterised behaviour of normal distribution:
 * -----------------------------------------------
 * This function contains a non-deterministic do-while loop, so an
 * investigation was conducted to examine the performance of this function.
 * The experiment consisted of calling the function 500k times, and logging
 * the time (clock_gettime(CLOCK_MONOTONIC...) before and after each call.
 * The results are summarised here.
 *
 * The characterisation observed a number of latency outliers of over 1
 * microsecond over the course of the experiment. However, as these events
 * typically occurred every 1 or 2 millisconds over the course of the
 * experiment, they were attributed so some external system process, and were
 * discounted.
 *
 * After discounting the observed microsecond latency outliers, the function
 * was observed to take either sub 100 nanoseconds (50% of the time) or else
 * around 200 nanoseconds (skew normal distribution), with 99% of all
 * calculations taking less than 350 nanoseconds to complete.
 *
 * Conclusion: provided that this function is not expected to provide values
 * less than 350 nanoseconds inter-packet gap, it is sufficient for this
 * purpose. This translates to a packet rate of just under 2.9 million packets
 * per second.
 *
 */
static uint64_t rnorm(struct distribution* ref)
{
  double rand_unif_1, rand_unif_2, rad_sq, radial_proj;
  double rand_norm;
  rad_sq = 0;

  if( ref->params.norm_params.dn_use_result2 ) {
    ref->params.norm_params.dn_use_result2 = false;
    rand_norm = ref->params.norm_params.dn_mean +
                (ref->params.norm_params.dn_stdev *
                 ref->params.norm_params.dn_result2);
    if( rand_norm < 0 ) {
      return rnorm(ref);
    }
    else {
      return floor(rand_norm);
    }
  }

  do {
    rand_unif_1 = ((((double)rand_r(&ref->default_random_gen_seed)) / 
                  RAND_MAX) * 2) - 1.0;
    rand_unif_2 = ((((double)rand_r(&ref->default_random_gen_seed)) /
                  RAND_MAX) * 2) - 1.0;
    rad_sq = (rand_unif_1 * rand_unif_1) + (rand_unif_2 * rand_unif_2);
  } while( (rad_sq > 1) || (rad_sq == 0) );

  ref->params.norm_params.dn_use_result2 = true;

  /* Box-Muller transformations: */
  radial_proj = sqrt((-2.0 * log(rad_sq)) / rad_sq);
  ref->params.norm_params.dn_result1 = rand_unif_1 * radial_proj;
  ref->params.norm_params.dn_result2 = rand_unif_2 * radial_proj;

  rand_norm = ref->params.norm_params.dn_mean +
              ref->params.norm_params.dn_stdev *
              ref->params.norm_params.dn_result1;

  if( (rand_norm < 0) ) {
    return rnorm(ref);
  }
  else {
    return floor(rand_norm);
  }
}

/*
 * characterised behaviour of exponential distribution:
 * ----------------------------------------------------
 *  This function contains a recursive call to iteslf, so an investigation was
 *  conducted to examine the performance of this function. The experiment
 *  consisted of calling the function 500k times, and logging the time
 *  (clock_gettime(CLOCK_MONOTONIC...) before and after each call. The results
 *  are summarised here.
 *
 *  The characterisation observed a number of latency outliers of over 1
 *  microsecond over the course of the experiment. However, as these events
 *  typically occurred every 1 to 4 millisconds over the course of the
 *  experiment, they were attributed so some external system process, and were
 *  discounted.
 *
 *  After discarding the observed microsecond latency outliers, the function
 *  was observed to take either sub 90 nanoseconds (92% of the time) or between
 *  90 and 130 nanoseconds (the remaining 8%), with a few outliers between 130
 *  and 500 nanos.
 *
 *  Conclusion: provided that this function is not expected to provide values
 *  less than 130 nanoseconds inter-packet gap, it is sufficient for this purpose.
 *  This translates to a packet rate of just under 7.7 million packets per second.
 *
 */
static uint64_t rexp(struct distribution* ref)
{
  double rand_val = (double)rand_r(&ref->default_random_gen_seed);
  rand_val = ref->params.exp_params.de_lambda *
             exp(rand_val / ref->params.exp_params.de_lambda);
  if( rand_val < 0 ) {
    return rexp(ref);
  }
  else {
    return floor(rand_val);
  }
}


/*
 * set defaults for different distributions, if the node is invoked with a
 * distributionspecified, but the distribution parameters have not been set.
 *
 * (An alternative would be to require that the distribution parameters are
 * set, and to fail if they are not).
 *
 * Apart from being chosen so that the associated distribution generates
 * values greater than the recommended minimum in each case (see the function
 * characterisation comment prior to each distribution function for details
 * on what that minimum is), the specified values have no particular rational
 * for their selection.
 *
 */
static void init_jitter_struct(struct jitter* j)
{
  switch( j->distro.dn_type ) {
  case DIST_TYPE_CONSTANT:
    j->distro.params.const_params.cp_delay = CP_DELAY_DEFAULT;
    j->distro.rv_gen                       = rconst;
    break;
  case DIST_TYPE_UNIFORM:
    j->distro.params.unif_params.du_min    = DU_MIN_DEFAULT;
    j->distro.params.unif_params.du_max    = DU_MAX_DEFAULT;
    j->distro.rv_gen                       = runif;
    break;
  case DIST_TYPE_NORMAL:
    j->distro.params.norm_params.dn_mean   = DN_MEAN_DEFAULT;
    j->distro.params.norm_params.dn_stdev  = DN_STDEV_DEFAULT;
    j->distro.rv_gen                       = rnorm;
    break;
  case DIST_TYPE_EXPONENTIAL:
    j->distro.params.exp_params.de_mean    = DE_MEAN_DEFAULT;
    j->distro.params.exp_params.de_lambda  = 1 / 
        j->distro.params.exp_params.de_mean;
    j->distro.rv_gen                       = rexp;
    break;
  default:
    fprintf(stderr, "ERROR: Unsupported distribution specified.");
    TEST(0);
  }

  j->first_pkt    = true;
  j->last_ts_sec  = 0;
  j->last_ts_nsec = 0;

  srand(j->distro.default_random_gen_seed);
}


/*
 * determine distribution parameters
 */
static int get_distn_params(struct sc_node* node, const char* key,
                            int* target, int default_value)
{
  int val, rv;
  if( (rv = sc_node_init_get_arg_int(&val, node, key, default_value)) < 0 ) {
    fprintf(stderr, "sc_node_init_get_arg_int failed with error %d.\n", rv);
    return sc_node_set_error(node, EINVAL,
                             "jitter: ERROR: Unparseable %s in function %s\n",
                             key, __FUNCTION__);
  }
  *target = val;
  return 0;
}

static int sign_check(int val, enum dists target, char* str, const char* fn) {
  if( val < 0 ){
    fprintf(stderr,
            "ERROR: Line %d. Case %d. Negative %s provided in function %s\n",
            __LINE__, target, str, fn);
    return -1;
  }
  return 0;
}


/*
 * determine type of distribution to use
 */
static int get_distn(struct sc_node* node, const char* key,
                     enum dists* target, enum dists default_value)
{
  const char* cmd;
  int rv;
  if( (rv = sc_node_init_get_arg_str(&cmd, node, key, NULL)) < 0 ) {
    fprintf(stderr,
            "sc_node_init_get_arg_int failed with error %d in function %s.\n",
            rv, __FUNCTION__);
    return sc_node_set_error(node, EINVAL, 
                             "jitter: ERROR: Unparseable %s\n", key);
  }

  if( strcmp(cmd, "constant") == 0 ) {
    *target = DIST_TYPE_CONSTANT;
  }
  else if( strcmp(cmd, "uniform") == 0 ) {
    *target = DIST_TYPE_UNIFORM;
  }
  else if( strcmp(cmd, "normal") == 0 ) {
    *target = DIST_TYPE_NORMAL;
  }
  else if( (strcmp(cmd, "exp") == 0) || (strcmp(cmd, "exponential") == 0) ) {
    *target = DIST_TYPE_EXPONENTIAL;
  }
  else {
    fprintf(stderr, "ERROR: No distribution set.\n");
    TEST(0);
  }

  return 0;
}


/*****************************************************************************/


static void sct_jitter_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct jitter* js = (struct jitter*)node->nd_private;
  struct sc_packet* walk = pl->head;
  int step_by;

  while( walk ) {
    struct sc_packet* next = walk->next;
    /*
     * gap generator. modifies the incoming packet timestamps so that they will
     * be replayed with inter-packet gap coming from a statistical distribution
     */
    step_by = js->distro.rv_gen(&(js->distro));

    if( js->first_pkt ) {
      js->last_ts_sec   = walk->ts_sec;
      js->last_ts_nsec  = walk->ts_nsec;
      js->first_pkt     = false;
    }

    js->last_ts_sec     += step_by / NSEC_IN_SEC;
    js->last_ts_nsec    += step_by % NSEC_IN_SEC;
    if( js->last_ts_nsec > NSEC_IN_SEC ) {
      js->last_ts_sec   += 1;
      js->last_ts_nsec  -= NSEC_IN_SEC;
    }
    walk->ts_sec  = js->last_ts_sec;
    walk->ts_nsec = js->last_ts_nsec;
    walk = next;
  }

  sc_forward_list(node, js->next_hop, pl);
}


static void sct_jitter_end_of_stream(struct sc_node* node)
{
  struct jitter* js = node->nd_private;
  sc_node_link_end_of_stream(node, js->next_hop);
}


static int sct_jitter_prep(struct sc_node* node,
                           const struct sc_node_link*const* links,
               int n_links)
{
  struct jitter* js = node->nd_private;
  js->next_hop = (void*) sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sct_jitter_init(struct sc_node* node, const struct sc_attr* attr,
                           const struct sc_node_factory* factory)
{
  /* set up the private structure to hold data etc */
  struct jitter* js;
  js = malloc(sizeof(*js));
  if( js == NULL) {
    fprintf(stderr, "ERROR: malloc failed in %s with error %d",
             __FUNCTION__, errno);
    return -ENOMEM;
  }
  node->nd_private = js;

  static struct sc_node_type* nt;
  TEST(sc_node_type_alloc(&nt, NULL, factory) == 0);
  nt->nt_prep_fn = sct_jitter_prep;
  nt->nt_pkts_fn = sct_jitter_pkts;
  nt->nt_end_of_stream_fn = sct_jitter_end_of_stream;

  node->nd_type = nt;

  if( get_distn(node, "distn", &(js->distro.dn_type), 
                DIST_TYPE_CONSTANT) != 0 ) {
    fprintf(stderr, 
            "ERROR: failed to parse node options \"distn\" in %s",
            __FUNCTION__);
    goto err;
  }

  init_jitter_struct(js);

  switch( js->distro.dn_type ) {
    case DIST_TYPE_CONSTANT:
      js->distro.rv_gen = rconst;
      if( get_distn_params(node, "constant",
                           &(js->distro.params.const_params.cp_delay),
                            CP_DELAY_DEFAULT) != 0 ) {
        fprintf(stderr,
                "ERROR: Line %d. Case %d. Failed to parse const in %s",
                __LINE__, DIST_TYPE_CONSTANT, __FUNCTION__);
        goto err;
      }
      if( sign_check(js->distro.params.const_params.cp_delay,
                     DIST_TYPE_CONSTANT,
                     "cp_delay",
                     __FUNCTION__) != 0 ) {
         goto err;
      }
      break;
    case DIST_TYPE_UNIFORM:
      js->distro.rv_gen = runif;
      if( get_distn_params(node, "min",
                              &(js->distro.params.unif_params.du_min),
                              DU_MIN_DEFAULT) != 0 ) {
        fprintf(stderr,
                "ERROR: Line %d. Case %d. Failed to parse min in %s",
                __LINE__, DIST_TYPE_UNIFORM, __FUNCTION__);
        goto err;
      }
      if( sign_check(js->distro.params.unif_params.du_min,
                     DIST_TYPE_UNIFORM,
                     "min",
                     __FUNCTION__) != 0 ) {
         goto err;
      }
      if( get_distn_params(node, "max",
                  &(js->distro.params.unif_params.du_max),
                  DU_MAX_DEFAULT) != 0 ) {
        fprintf(stderr,
                "ERROR: Line %d. Case %d. Failed to parse max in %s",
                __LINE__, DIST_TYPE_UNIFORM, __FUNCTION__);
        goto err;
      }
      if( sign_check(js->distro.params.unif_params.du_max,
                     DIST_TYPE_UNIFORM,
                     "max",
                     __FUNCTION__) != 0 ) {
         goto err;
      }
      break;
    case DIST_TYPE_NORMAL:
      js->distro.rv_gen = rnorm;
      if( get_distn_params(node, "mean",
                  &(js->distro.params.norm_params.dn_mean),
                  DN_MEAN_DEFAULT) != 0 ) {
        fprintf(stderr,
                "ERROR: Line %d. Case %d. Failed to parse mean in %s",
                __LINE__, DIST_TYPE_NORMAL, __FUNCTION__);
        goto err;
      }
      if( sign_check(js->distro.params.norm_params.dn_mean,
                     DIST_TYPE_NORMAL,
                     "mean",
                     __FUNCTION__) != 0 ) {
          goto err;
      }
      if( get_distn_params(node, "stdev",
                           &(js->distro.params.norm_params.dn_stdev),
                           DN_STDEV_DEFAULT) != 0 ) {
        fprintf(stderr,
                "ERROR: Line %d. Case %d. Failed to parse stdev in %s",
                __LINE__, DIST_TYPE_NORMAL, __FUNCTION__);
        goto err;
      }
      if( sign_check(js->distro.params.norm_params.dn_stdev,
                     DIST_TYPE_NORMAL,
                     "stdev",
                     __FUNCTION__) != 0 ) {
     goto err;
      }
      break;
    case DIST_TYPE_EXPONENTIAL:
      js->distro.rv_gen = rexp;
      if( get_distn_params(node, "lambda",
                           (int *)&(js->distro.params.exp_params.de_mean),
                           DE_MEAN_DEFAULT) != 0 ) {
        fprintf(stderr,
                "ERROR: Line %d. Case %d. Failed to parse lambda in %s",
                __LINE__, DIST_TYPE_EXPONENTIAL, __FUNCTION__);
        goto err;
      }
      js->distro.params.exp_params.de_lambda = 
              1 / js->distro.params.exp_params.de_mean;
      break;
    default:
      TEST(0);
  }

  return 0;
 err:
  free(js);
  return -1;
}


const struct sc_node_factory sct_jitter_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_jitter",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_jitter_init,
};
