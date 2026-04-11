/*
 * ocled25519engine.h - Lightweight OpenCL engine for Ed25519 vanity generation
 *
 * Part of oclvanitygen-ed25519++
 */

#ifndef OCLED25519ENGINE_H
#define OCLED25519ENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#define CL_TARGET_OPENCL_VERSION 120
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#include <CL/cl.h>
#endif

typedef struct {
    cl_device_id     device;
    cl_context       ctx;
    cl_command_queue queue;
    cl_program       program;
    cl_kernel        kernel;
    cl_mem           seeds_buf;      /* global_size * 32 bytes */
    cl_mem           pubkeys_buf;    /* global_size * keys_per_item * 32 bytes */
    size_t           global_size;
    uint32_t         keys_per_item;
    int              verbose;
} ocl_ed25519_ctx_t;

/*
 * Initialize the OpenCL context.
 * kernel_path: path to calc_addrs_ed25519.cl (include dir is inferred from path)
 * platform_idx, device_idx: 0-based indices from ocl_ed25519_enumerate_devices()
 * global_size: number of parallel work items (0 = auto)
 * keys_per_item: number of keys each work item generates sequentially
 */
int  ocl_ed25519_init(ocl_ed25519_ctx_t *ctx,
                      const char *kernel_path,
                      int platform_idx,
                      int device_idx,
                      size_t global_size,
                      uint32_t keys_per_item,
                      int verbose);

/*
 * Run one batch: transfer seeds_in to GPU, execute kernel, read pubkeys_out back.
 * seeds_in:   ctx->global_size * 32 bytes
 * pubkeys_out: ctx->global_size * ctx->keys_per_item * 32 bytes
 * Returns 0 on success, -1 on error.
 */
int  ocl_ed25519_run(ocl_ed25519_ctx_t *ctx,
                     const uint8_t *seeds_in,
                     uint8_t *pubkeys_out);

/* Async pipeline: upload seeds and launch kernel (returns immediately). */
int  ocl_ed25519_launch(ocl_ed25519_ctx_t *ctx, const uint8_t *seeds_in);

/* Async pipeline: wait for kernel and download pubkeys. */
int  ocl_ed25519_await(ocl_ed25519_ctx_t *ctx, uint8_t *pubkeys_out);

/* Release all OpenCL resources. */
void ocl_ed25519_free(ocl_ed25519_ctx_t *ctx);

/* Print all available OpenCL platforms and devices to stderr. */
void ocl_ed25519_enumerate_devices(void);

/* Entry point for Ed25519 vanity generation (called from oclvanitygen.c) */
int ocl_ed25519_main(int argc, char *argv[]);

#endif /* OCLED25519ENGINE_H */
