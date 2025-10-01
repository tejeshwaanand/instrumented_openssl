/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_BENCH_UTILS_H
# define OPENSSL_BENCH_UTILS_H

# ifdef OPENSSL_BENCHMARK

#  include <openssl/evp.h>
#  include <openssl/bio.h>
#  include <sys/time.h>
#  include <stdint.h>

# ifdef __cplusplus
extern "C" {
# endif

/*
 * Benchmarking context structure to store measurements
 * before and after cryptographic operations
 */
typedef struct {
    /* Timing measurements */
    struct timeval start_time;
    struct timeval end_time;
    uint64_t start_cycles;
    uint64_t end_cycles;
    
    /* Memory measurements */
    size_t mem_start;
    size_t mem_end;
    size_t mem_peak;
    
    /* Power and thermal measurements */
    uint64_t energy_start_uj;
    uint64_t energy_end_uj;
    int temp_start_mc;  /* millicelsius */
    int temp_end_mc;    /* millicelsius */
    
    /* Cryptographic data sizes */
    size_t pk_size;     /* Public key size in bytes */
    size_t ct_size;     /* Ciphertext/output size in bytes */
    
    /* Function identification */
    const char *function_name;
} openssl_bench_ctx_t;

/*
 * Initialize benchmarking context and capture "before" measurements
 * 
 * @param ctx: Benchmarking context to initialize
 * @param function_name: Name of the function being benchmarked
 * @return: 0 on success, -1 on error
 */
int openssl_bench_start(openssl_bench_ctx_t *ctx, const char *function_name);

/*
 * Capture "after" measurements and log the complete benchmark data
 * 
 * @param ctx: Benchmarking context with start measurements
 * @param pkey: EVP_PKEY for public key size measurement (can be NULL)
 * @param ct_data: Pointer to ciphertext/output data (can be NULL)
 * @param ct_len: Length of ciphertext/output data
 * @return: 0 on success, -1 on error
 */
int openssl_bench_end(openssl_bench_ctx_t *ctx, EVP_PKEY *pkey, 
                      const unsigned char *ct_data, size_t ct_len);

/*
 * Helper function to read CPU cycles using rdtsc instruction
 * 
 * @return: Current CPU cycle count
 */
uint64_t openssl_bench_rdtsc(void);

/*
 * Helper function to read energy consumption from Intel RAPL
 * 
 * @return: Energy consumption in microjoules, or 0 on error
 */
uint64_t openssl_bench_read_energy(void);

/*
 * Helper function to read CPU temperature
 * 
 * @return: Temperature in millicelsius, or 0 on error
 */
int openssl_bench_read_temperature(void);

/*
 * Helper function to get public key size in DER format
 * 
 * @param pkey: EVP_PKEY to measure
 * @return: Size in bytes, or 0 on error
 */
size_t openssl_bench_get_pubkey_size(EVP_PKEY *pkey);

/*
 * Memory tracking functions for custom allocator integration
 */
void openssl_bench_mem_reset(void);
size_t openssl_bench_mem_current(void);
size_t openssl_bench_mem_peak(void);

# ifdef __cplusplus
}
# endif

# endif /* OPENSSL_BENCHMARK */

#endif /* OPENSSL_BENCH_UTILS_H */
