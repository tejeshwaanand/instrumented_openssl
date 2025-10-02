/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "bench_utils.h"

#ifdef OPENSSL_BENCHMARK

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "internal/cryptlib.h"

/* Global memory tracking variables */
static size_t g_current_mem = 0;
static size_t g_peak_mem = 0;
static void *(*orig_malloc)(size_t, const char *, int) = NULL;
static void *(*orig_realloc)(void *, size_t, const char *, int) = NULL;
static void (*orig_free)(void *, const char *, int) = NULL;

/*
 * Custom memory allocation functions for tracking
 */
static void *bench_malloc(size_t size, const char *file, int line)
{
    void *ptr = CRYPTO_malloc(size, file, line);
    if (ptr != NULL) {
        g_current_mem += size;
        if (g_current_mem > g_peak_mem) {
            g_peak_mem = g_current_mem;
        }
    }
    return ptr;
}

static void *bench_realloc(void *ptr, size_t size, const char *file, int line)
{
    /* Note: This is a simplified approach - in practice, we'd need to track
     * the original allocation size to properly account for realloc */
    void *new_ptr = CRYPTO_realloc(ptr, size, file, line);
    if (new_ptr != NULL && ptr == NULL) {
        /* This is essentially a malloc */
        g_current_mem += size;
        if (g_current_mem > g_peak_mem) {
            g_peak_mem = g_current_mem;
        }
    }
    return new_ptr;
}

static void bench_free(void *ptr, const char *file, int line)
{
    if (ptr != NULL) {
        /* Note: We can't accurately track the freed size without additional
         * bookkeeping, but this is a reasonable approximation for benchmarking */
        CRYPTO_free(ptr, file, line);
    }
}

static void print_mem_status() {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", getpid());
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "VmRSS") || strstr(line, "VmSize") || strstr(line, "VmPeak")) {
            printf("%s", line);
        }
    }
    fclose(fp);
}

static size_t get_peak_memory_kb() {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", getpid());
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    char line[256];
    size_t peak_kb = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "VmPeak:", 7) == 0) {
            sscanf(line + 7, "%zu", &peak_kb);
            break;
        }
    }
    fclose(fp);
    return peak_kb; // in kB
}

static size_t get_current_memory_kb() {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", getpid());
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    char line[256];
    size_t rss_kb = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%zu", &rss_kb);
            break;
        }
    }
    fclose(fp);
    return rss_kb; // in kB
}

uint64_t openssl_bench_rdtsc(void)
{
    uint64_t cycles;
#if defined(__x86_64__) || defined(__i386__)
    unsigned int lo, hi;
    __asm__ volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    cycles = ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    /* ARM64 - use virtual counter */
    __asm__ volatile ("mrs %0, cntvct_el0" : "=r" (cycles));
#else
    /* Fallback for other architectures */
    cycles = 0;
#endif
    return cycles;
}

uint64_t openssl_bench_read_energy(void)
{
    FILE *fp;
    uint64_t energy = 0;
    
    /* Try Intel RAPL interface */
    fp = fopen("/sys/class/powercap/intel-rapl:0/energy_uj", "r");
    if (fp != NULL) {
        if (fscanf(fp, "%lu", &energy) != 1) {
            energy = 0;
        }
        fclose(fp);
    }
    return energy;
}

int openssl_bench_read_temperature(void)
{
    FILE *fp;
    int temp = 0;
    
    /* Try thermal zone 0 first */
    fp = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
    if (fp != NULL) {
        if (fscanf(fp, "%d", &temp) != 1) {
            temp = 0;
        }
        fclose(fp);
    }
    return temp;
}

size_t openssl_bench_get_pubkey_size(EVP_PKEY *pkey)
{
    unsigned char *der_buf = NULL;
    int der_len;
    
    if (pkey == NULL) {
        return 0;
    }
    
    /* Get DER encoding of public key */
    der_len = i2d_PUBKEY(pkey, &der_buf);
    if (der_len <= 0) {
        return 0;
    }
    
    /* Clean up the allocated buffer */
    OPENSSL_free(der_buf);
    
    return (size_t)der_len;
}

void openssl_bench_mem_reset(void)
{
    g_current_mem = 0;
    g_peak_mem = 0;
}

size_t openssl_bench_mem_current(void)
{
    return g_current_mem;
}

size_t openssl_bench_mem_peak(void)
{
    return g_peak_mem;
}

int openssl_bench_start(openssl_bench_ctx_t *ctx, const char *function_name)
{
    if (ctx == NULL || function_name == NULL) {
        return -1;
    }
    
    /* Initialize the context */
    memset(ctx, 0, sizeof(*ctx));
    ctx->function_name = function_name;
    
    /* Setup memory tracking */
    openssl_bench_mem_reset();
    
    /* Capture starting measurements */
    gettimeofday(&ctx->start_time, NULL);
    ctx->start_cycles = openssl_bench_rdtsc();
    ctx->energy_start_uj = openssl_bench_read_energy();
    ctx->temp_start_mc = openssl_bench_read_temperature();
    // ctx->mem_start = openssl_bench_mem_current();
    
    // print_mem_status(); // Log memory at start
    // ctx->mem_start = get_current_memory_kb(); // Save current memory at start

    return 0;
}

int openssl_bench_end(openssl_bench_ctx_t *ctx, EVP_PKEY *pkey, 
                      const unsigned char *ct_data, size_t ct_len)
{
    double elapsed_time;
    uint64_t elapsed_cycles;
    uint64_t energy_consumed;
    size_t mem_used; //just to check
    
    if (ctx == NULL) {
        return -1;
    }
    
    /* Capture ending measurements */
    gettimeofday(&ctx->end_time, NULL);
    ctx->end_cycles = openssl_bench_rdtsc();
    ctx->energy_end_uj = openssl_bench_read_energy();
    ctx->temp_end_mc = openssl_bench_read_temperature();
    // print_mem_status(); // Log memory at end
    // ctx->mem_end = get_current_memory_kb(); // Save current memory at end
    // ctx->mem_peak = get_peak_memory_kb(); // Save peak memory at end
    
    /* Get cryptographic data sizes */
    ctx->pk_size = openssl_bench_get_pubkey_size(pkey);
    ctx->ct_size = ct_len;
    
    /* Calculate differences */
    elapsed_time = (ctx->end_time.tv_sec - ctx->start_time.tv_sec) +
                   (ctx->end_time.tv_usec - ctx->start_time.tv_usec) / 1000000.0;
    
    elapsed_cycles = ctx->end_cycles - ctx->start_cycles;
    
    energy_consumed = (ctx->energy_end_uj >= ctx->energy_start_uj) ?
                      (ctx->energy_end_uj - ctx->energy_start_uj) : 262143328850 -ctx->energy_start_uj + ctx->energy_end_uj;

    mem_used = get_current_memory_kb() * 1024;

    /* Log the benchmark results */
    printf("[OPENSSL-BENCH] %s: time=%.6fs, cycles=%lu, mem=%zu bytes, "
           "energy=%luuJ, temp_before=%.1fC, temp_after=%.1fC, "
           "size_pk=%zu bytes, size_ct=%zu bytes, start_time=%lld.%lld, end_time=%lld.%lld\n",
           ctx->function_name,
           elapsed_time,
           elapsed_cycles,
           mem_used,
           energy_consumed,
           ctx->temp_start_mc / 1000.0,
           ctx->temp_end_mc / 1000.0,
           ctx->pk_size,
           ctx->ct_size, ctx->start_time.tv_sec, ctx->start_time.tv_usec, ctx->end_time.tv_sec, ctx->end_time.tv_usec);
    
    /* Also log to OpenSSL's BIO system if available */
    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (bio_out != NULL) {
        BIO_printf(bio_out, "[OPENSSL-BENCH-BIO] %s: time=%.6fs, cycles=%lu, "
                   "mem=%zu bytes, energy=%luuJ, temp_before=%.1fC, "
                   "temp_after=%.1fC, size_pk=%zu bytes, size_ct=%zu bytes\n",
                   ctx->function_name,
                   elapsed_time,
                   elapsed_cycles,
                   mem_used,
                   energy_consumed,
                   ctx->temp_start_mc / 1000.0,
                   ctx->temp_end_mc / 1000.0,
                   ctx->pk_size,
                   ctx->ct_size);
        BIO_free(bio_out);
    }
    
    print_mem_status(); // Log memory at end
    
    return 0;
}

#endif /* OPENSSL_BENCHMARK */
