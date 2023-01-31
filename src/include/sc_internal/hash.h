/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_HASH_H__
#define __SC_HASH_H__

#ifdef WITH_SSE_HASH
# if (defined(__x86_64__) || defined(__i386__))
#  define _USE_SSE 1
# else
   /* Fall back to slow hash */
#  warning "Fast hash not supported by this machine target, falling back to a slow hash."
#  define _USE_SSE 0
# endif
#else
# define _USE_SSE 0
#endif


static inline uint32_t sc_hash_debug(const void* data, size_t len)
{
  if( len == 0 )
    return 0;
  uint32_t byte_to_repeat = *(uint8_t*)data;
  return byte_to_repeat | byte_to_repeat << 8 | byte_to_repeat << 16 | byte_to_repeat << 24;
}


static inline uint32_t sc_hash_djb2_xor(const void* data, size_t len)
{
  uint32_t hash = 5381;
  const uint8_t* data8 = data;
  size_t i;
  for( i = 0; i < len; ++i )
    hash = ((hash << 5u) + hash) ^ data8[i];
  return hash;
}

#ifdef UT_TEST

static inline uint32_t sc_hash(const void* data, size_t len)
{
  return sc_hash_debug(data, len);
}

#elif _USE_SSE

static inline uint32_t sc_crc32(uint32_t crc, const void* data, size_t len)
{
  const uint8_t* pdata = data;
  size_t i;
  for( i = 0; i < len / sizeof(uint32_t); ++i ) {
    crc = __builtin_ia32_crc32si(crc, *(const uint32_t*) pdata);
    pdata += sizeof(uint32_t);
  }
  switch( len & 3 ) {
  case 0:
    break;
  case 3:
    crc = __builtin_ia32_crc32qi(crc, *pdata++);
    crc = __builtin_ia32_crc32hi(crc, *(uint16_t*) pdata);
    break;
  case 2:
    crc = __builtin_ia32_crc32hi(crc, *(uint16_t*) pdata);
    break;
  case 1:
    crc = __builtin_ia32_crc32qi(crc, *pdata);
    break;
  }
  return crc;
}


static inline uint32_t sc_hash(const void* data, size_t len)
{
  return sc_crc32(0, data, len);
}

#else

static inline uint32_t sc_hash(const void* data, size_t len)
{
  return sc_hash_djb2_xor(data, len);
}

#endif/* _USE_SSE */


#undef _USE_SSE


#endif  /* __SC_HASH_H__ */
