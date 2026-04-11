/*
 * ocled25519engine.c - Lightweight OpenCL engine for Ed25519 vanity generation
 *
 * Part of oclvanitygen-ed25519++
 * Device management patterns borrowed from oclengine.c (same project).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ocled25519engine.h"

/* -------------------------------------------------------------------------
 * Error helpers
 * ------------------------------------------------------------------------- */

static const char *
ocl_strerror(cl_int ret)
{
#define OCL_STATUS(st) case st: return #st;
    switch (ret) {
        OCL_STATUS(CL_SUCCESS)
        OCL_STATUS(CL_DEVICE_NOT_FOUND)
        OCL_STATUS(CL_DEVICE_NOT_AVAILABLE)
        OCL_STATUS(CL_COMPILER_NOT_AVAILABLE)
        OCL_STATUS(CL_MEM_OBJECT_ALLOCATION_FAILURE)
        OCL_STATUS(CL_OUT_OF_RESOURCES)
        OCL_STATUS(CL_OUT_OF_HOST_MEMORY)
        OCL_STATUS(CL_BUILD_PROGRAM_FAILURE)
        OCL_STATUS(CL_INVALID_VALUE)
        OCL_STATUS(CL_INVALID_DEVICE_TYPE)
        OCL_STATUS(CL_INVALID_PLATFORM)
        OCL_STATUS(CL_INVALID_DEVICE)
        OCL_STATUS(CL_INVALID_CONTEXT)
        OCL_STATUS(CL_INVALID_QUEUE_PROPERTIES)
        OCL_STATUS(CL_INVALID_COMMAND_QUEUE)
        OCL_STATUS(CL_INVALID_HOST_PTR)
        OCL_STATUS(CL_INVALID_MEM_OBJECT)
        OCL_STATUS(CL_INVALID_BINARY)
        OCL_STATUS(CL_INVALID_BUILD_OPTIONS)
        OCL_STATUS(CL_INVALID_PROGRAM)
        OCL_STATUS(CL_INVALID_PROGRAM_EXECUTABLE)
        OCL_STATUS(CL_INVALID_KERNEL_NAME)
        OCL_STATUS(CL_INVALID_KERNEL_DEFINITION)
        OCL_STATUS(CL_INVALID_KERNEL)
        OCL_STATUS(CL_INVALID_ARG_INDEX)
        OCL_STATUS(CL_INVALID_ARG_VALUE)
        OCL_STATUS(CL_INVALID_ARG_SIZE)
        OCL_STATUS(CL_INVALID_KERNEL_ARGS)
        OCL_STATUS(CL_INVALID_WORK_DIMENSION)
        OCL_STATUS(CL_INVALID_WORK_GROUP_SIZE)
        OCL_STATUS(CL_INVALID_WORK_ITEM_SIZE)
        OCL_STATUS(CL_INVALID_GLOBAL_OFFSET)
        OCL_STATUS(CL_INVALID_EVENT_WAIT_LIST)
        OCL_STATUS(CL_INVALID_EVENT)
        OCL_STATUS(CL_INVALID_OPERATION)
        OCL_STATUS(CL_INVALID_GL_OBJECT)
        OCL_STATUS(CL_INVALID_BUFFER_SIZE)
        OCL_STATUS(CL_INVALID_MIP_LEVEL)
        OCL_STATUS(CL_INVALID_GLOBAL_WORK_SIZE)
#undef OCL_STATUS
    default: {
        static char tmp[64];
        snprintf(tmp, sizeof(tmp), "Unknown code %d", ret);
        return tmp;
    }
    }
}

/* -------------------------------------------------------------------------
 * Device / platform query helpers
 * ------------------------------------------------------------------------- */

static const char *
ocl_platform_getstr(cl_platform_id pid, cl_platform_info param)
{
    static char buf[1024];
    size_t sz;
    cl_int ret = clGetPlatformInfo(pid, param, sizeof(buf), buf, &sz);
    if (ret != CL_SUCCESS)
        snprintf(buf, sizeof(buf), "<clGetPlatformInfo error: %s>", ocl_strerror(ret));
    return buf;
}

static const char *
ocl_device_getstr(cl_device_id did, cl_device_info param)
{
    static char buf[1024];
    size_t sz;
    cl_int ret = clGetDeviceInfo(did, param, sizeof(buf), buf, &sz);
    if (ret != CL_SUCCESS)
        snprintf(buf, sizeof(buf), "<clGetDeviceInfo error: %s>", ocl_strerror(ret));
    return buf;
}

static cl_uint
ocl_device_getuint(cl_device_id did, cl_device_info param)
{
    cl_uint val = 0;
    size_t sz;
    clGetDeviceInfo(did, param, sizeof(val), &val, &sz);
    return val;
}

/* -------------------------------------------------------------------------
 * Public: enumerate all devices
 * ------------------------------------------------------------------------- */

void
ocl_ed25519_enumerate_devices(void)
{
    cl_platform_id platforms[16];
    cl_uint nplatforms = 0;
    cl_int ret;

    ret = clGetPlatformIDs(16, platforms, &nplatforms);
    if (ret != CL_SUCCESS) {
        fprintf(stderr, "clGetPlatformIDs: %s\n", ocl_strerror(ret));
        return;
    }
    if (nplatforms == 0) {
        fprintf(stderr, "No OpenCL platforms found.\n");
        return;
    }

    for (cl_uint p = 0; p < nplatforms; p++) {
        cl_device_id devices[64];
        cl_uint ndevices = 0;
        fprintf(stderr, "Platform %u: %s\n", p,
                ocl_platform_getstr(platforms[p], CL_PLATFORM_NAME));
        fprintf(stderr, "  Version: %s\n",
                ocl_platform_getstr(platforms[p], CL_PLATFORM_VERSION));

        ret = clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_ALL,
                             64, devices, &ndevices);
        if (ret != CL_SUCCESS) {
            fprintf(stderr, "  clGetDeviceIDs: %s\n", ocl_strerror(ret));
            continue;
        }
        for (cl_uint d = 0; d < ndevices; d++) {
            fprintf(stderr, "  Device %u: %s\n", d,
                    ocl_device_getstr(devices[d], CL_DEVICE_NAME));
            fprintf(stderr, "    Vendor: %s\n",
                    ocl_device_getstr(devices[d], CL_DEVICE_VENDOR));
            fprintf(stderr, "    Driver: %s\n",
                    ocl_device_getstr(devices[d], CL_DRIVER_VERSION));
            fprintf(stderr, "    Compute units: %u\n",
                    ocl_device_getuint(devices[d], CL_DEVICE_MAX_COMPUTE_UNITS));
        }
    }
}

/* -------------------------------------------------------------------------
 * Print build log on compile failure
 * ------------------------------------------------------------------------- */

static void
ocl_print_build_log(cl_program prog, cl_device_id did)
{
    size_t sz = 0;
    char *log;
    clGetProgramBuildInfo(prog, did, CL_PROGRAM_BUILD_LOG, 0, NULL, &sz);
    if (sz == 0) return;
    log = (char *)malloc(sz + 1);
    if (!log) return;
    clGetProgramBuildInfo(prog, did, CL_PROGRAM_BUILD_LOG, sz, log, NULL);
    log[sz] = '\0';
    fprintf(stderr, "OpenCL build log:\n%s\n", log);
    free(log);
}

/* -------------------------------------------------------------------------
 * Extract directory from a file path (for -I include flag)
 * Returns "." if path has no directory component.
 * Uses a static buffer; not thread-safe but called once at init.
 * ------------------------------------------------------------------------- */

static const char *
path_dirname(const char *path)
{
    static char buf[1024];
    const char *last = strrchr(path, '/');
    if (!last) {
        buf[0] = '.';
        buf[1] = '\0';
    } else {
        size_t len = (size_t)(last - path);
        if (len == 0) len = 1;   /* root "/" case */
        if (len >= sizeof(buf)) len = sizeof(buf) - 1;
        memcpy(buf, path, len);
        buf[len] = '\0';
    }
    return buf;
}

/* -------------------------------------------------------------------------
 * Public: init
 * ------------------------------------------------------------------------- */

int
ocl_ed25519_init(ocl_ed25519_ctx_t *ctx,
                 const char *kernel_path,
                 int platform_idx,
                 int device_idx,
                 size_t global_size,
                 uint32_t keys_per_item,
                 int verbose)
{
    cl_platform_id platforms[16];
    cl_uint nplatforms = 0;
    cl_device_id devices[64];
    cl_uint ndevices = 0;
    cl_int ret;
    FILE *kfp;
    char *src;
    size_t src_sz, src_read;
    char build_opts[512];

    memset(ctx, 0, sizeof(*ctx));
    ctx->verbose      = verbose;
    ctx->global_size  = global_size;
    ctx->keys_per_item = keys_per_item;

    /* Select platform */
    ret = clGetPlatformIDs(16, platforms, &nplatforms);
    if (ret != CL_SUCCESS || nplatforms == 0) {
        fprintf(stderr, "No OpenCL platforms found: %s\n", ocl_strerror(ret));
        return -1;
    }
    if (platform_idx < 0 || (cl_uint)platform_idx >= nplatforms) {
        fprintf(stderr, "Platform index %d out of range (0..%u)\n",
                platform_idx, nplatforms - 1);
        return -1;
    }
    cl_platform_id platform = platforms[platform_idx];

    /* Select device */
    ret = clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 64, devices, &ndevices);
    if (ret != CL_SUCCESS || ndevices == 0) {
        fprintf(stderr, "No OpenCL devices on platform %d: %s\n",
                platform_idx, ocl_strerror(ret));
        return -1;
    }
    if (device_idx < 0 || (cl_uint)device_idx >= ndevices) {
        fprintf(stderr, "Device index %d out of range (0..%u)\n",
                device_idx, ndevices - 1);
        return -1;
    }
    ctx->device = devices[device_idx];

    if (verbose) {
        fprintf(stderr, "Using device: %s\n",
                ocl_device_getstr(ctx->device, CL_DEVICE_NAME));
        fprintf(stderr, "  Vendor: %s\n",
                ocl_device_getstr(ctx->device, CL_DEVICE_VENDOR));
        fprintf(stderr, "  Compute units: %u\n",
                ocl_device_getuint(ctx->device, CL_DEVICE_MAX_COMPUTE_UNITS));
    }

    /* Auto work size: 64 work items per compute unit if not specified */
    if (ctx->global_size == 0) {
        cl_uint cu = ocl_device_getuint(ctx->device, CL_DEVICE_MAX_COMPUTE_UNITS);
        ctx->global_size = (size_t)cu * 64;
        if (ctx->global_size < 256) ctx->global_size = 256;
        if (verbose)
            fprintf(stderr, "Auto global size: %zu\n", ctx->global_size);
    }

    /* Create context */
    ctx->ctx = clCreateContext(NULL, 1, &ctx->device, NULL, NULL, &ret);
    if (!ctx->ctx) {
        fprintf(stderr, "clCreateContext: %s\n", ocl_strerror(ret));
        return -1;
    }

    /* Create command queue */
    ctx->queue = clCreateCommandQueue(ctx->ctx, ctx->device, 0, &ret);
    if (!ctx->queue) {
        fprintf(stderr, "clCreateCommandQueue: %s\n", ocl_strerror(ret));
        clReleaseContext(ctx->ctx);
        return -1;
    }

    /* Load kernel source */
    kfp = fopen(kernel_path, "r");
    if (!kfp) {
        fprintf(stderr, "Cannot open kernel file '%s': %s\n",
                kernel_path, strerror(errno));
        clReleaseCommandQueue(ctx->queue);
        clReleaseContext(ctx->ctx);
        return -1;
    }
    src_sz = 1024 * 1024;   /* 1 MB initial buffer */
    src = (char *)malloc(src_sz);
    if (!src) {
        fclose(kfp);
        clReleaseCommandQueue(ctx->queue);
        clReleaseContext(ctx->ctx);
        return -1;
    }
    src_read = fread(src, 1, src_sz - 1, kfp);
    fclose(kfp);
    if (src_read == 0) {
        fprintf(stderr, "Empty kernel file: %s\n", kernel_path);
        free(src);
        clReleaseCommandQueue(ctx->queue);
        clReleaseContext(ctx->ctx);
        return -1;
    }
    src[src_read] = '\0';

    /* Build options: include dir for precomp_data_ocl.h */
    snprintf(build_opts, sizeof(build_opts), "-I %s", path_dirname(kernel_path));

    /* Compile */
    const char *src_ptr = src;
    ctx->program = clCreateProgramWithSource(ctx->ctx, 1, &src_ptr, &src_read, &ret);
    free(src);
    if (!ctx->program) {
        fprintf(stderr, "clCreateProgramWithSource: %s\n", ocl_strerror(ret));
        clReleaseCommandQueue(ctx->queue);
        clReleaseContext(ctx->ctx);
        return -1;
    }

    if (verbose)
        fprintf(stderr, "Compiling kernel %s (this may take a moment)...\n", kernel_path);

    ret = clBuildProgram(ctx->program, 1, &ctx->device, build_opts, NULL, NULL);
    if (ret != CL_SUCCESS) {
        fprintf(stderr, "clBuildProgram: %s\n", ocl_strerror(ret));
        ocl_print_build_log(ctx->program, ctx->device);
        clReleaseProgram(ctx->program);
        clReleaseCommandQueue(ctx->queue);
        clReleaseContext(ctx->ctx);
        return -1;
    }
    if (verbose)
        fprintf(stderr, "Kernel compiled successfully.\n");

    /* Create kernel object */
    ctx->kernel = clCreateKernel(ctx->program, "ed25519_generate", &ret);
    if (!ctx->kernel) {
        fprintf(stderr, "clCreateKernel(ed25519_generate): %s\n", ocl_strerror(ret));
        clReleaseProgram(ctx->program);
        clReleaseCommandQueue(ctx->queue);
        clReleaseContext(ctx->ctx);
        return -1;
    }

    /* Allocate buffers */
    size_t seed_bytes   = ctx->global_size * 32;
    size_t pubkey_bytes = ctx->global_size * (size_t)ctx->keys_per_item * 32;

    ctx->seeds_buf = clCreateBuffer(ctx->ctx, CL_MEM_READ_ONLY,
                                    seed_bytes, NULL, &ret);
    if (!ctx->seeds_buf) {
        fprintf(stderr, "clCreateBuffer(seeds): %s\n", ocl_strerror(ret));
        clReleaseKernel(ctx->kernel);
        clReleaseProgram(ctx->program);
        clReleaseCommandQueue(ctx->queue);
        clReleaseContext(ctx->ctx);
        return -1;
    }

    ctx->pubkeys_buf = clCreateBuffer(ctx->ctx, CL_MEM_WRITE_ONLY,
                                      pubkey_bytes, NULL, &ret);
    if (!ctx->pubkeys_buf) {
        fprintf(stderr, "clCreateBuffer(pubkeys): %s\n", ocl_strerror(ret));
        clReleaseMemObject(ctx->seeds_buf);
        clReleaseKernel(ctx->kernel);
        clReleaseProgram(ctx->program);
        clReleaseCommandQueue(ctx->queue);
        clReleaseContext(ctx->ctx);
        return -1;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * Public: run one batch
 * ------------------------------------------------------------------------- */

int
ocl_ed25519_run(ocl_ed25519_ctx_t *ctx,
                const uint8_t *seeds_in,
                uint8_t *pubkeys_out)
{
    cl_int ret;
    size_t seed_bytes   = ctx->global_size * 32;
    size_t pubkey_bytes = ctx->global_size * (size_t)ctx->keys_per_item * 32;

    /* Upload seeds */
    ret = clEnqueueWriteBuffer(ctx->queue, ctx->seeds_buf, CL_TRUE,
                               0, seed_bytes, seeds_in,
                               0, NULL, NULL);
    if (ret != CL_SUCCESS) {
        fprintf(stderr, "clEnqueueWriteBuffer(seeds): %s\n", ocl_strerror(ret));
        return -1;
    }

    /* Set kernel args */
    cl_uint kpi = ctx->keys_per_item;
    clSetKernelArg(ctx->kernel, 0, sizeof(cl_mem), &ctx->seeds_buf);
    clSetKernelArg(ctx->kernel, 1, sizeof(cl_mem), &ctx->pubkeys_buf);
    clSetKernelArg(ctx->kernel, 2, sizeof(cl_uint), &kpi);

    /* Launch */
    ret = clEnqueueNDRangeKernel(ctx->queue, ctx->kernel,
                                 1, NULL, &ctx->global_size, NULL,
                                 0, NULL, NULL);
    if (ret != CL_SUCCESS) {
        fprintf(stderr, "clEnqueueNDRangeKernel: %s\n", ocl_strerror(ret));
        return -1;
    }

    /* Read back pubkeys */
    ret = clEnqueueReadBuffer(ctx->queue, ctx->pubkeys_buf, CL_TRUE,
                              0, pubkey_bytes, pubkeys_out,
                              0, NULL, NULL);
    if (ret != CL_SUCCESS) {
        fprintf(stderr, "clEnqueueReadBuffer(pubkeys): %s\n", ocl_strerror(ret));
        return -1;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * Public: async launch (upload seeds + start kernel, return immediately)
 * ------------------------------------------------------------------------- */

int
ocl_ed25519_launch(ocl_ed25519_ctx_t *ctx, const uint8_t *seeds_in)
{
    cl_int ret;
    size_t seed_bytes = ctx->global_size * 32;

    ret = clEnqueueWriteBuffer(ctx->queue, ctx->seeds_buf, CL_TRUE,
                               0, seed_bytes, seeds_in,
                               0, NULL, NULL);
    if (ret != CL_SUCCESS) {
        fprintf(stderr, "clEnqueueWriteBuffer(seeds): %s\n", ocl_strerror(ret));
        return -1;
    }

    cl_uint kpi = ctx->keys_per_item;
    clSetKernelArg(ctx->kernel, 0, sizeof(cl_mem), &ctx->seeds_buf);
    clSetKernelArg(ctx->kernel, 1, sizeof(cl_mem), &ctx->pubkeys_buf);
    clSetKernelArg(ctx->kernel, 2, sizeof(cl_uint), &kpi);

    ret = clEnqueueNDRangeKernel(ctx->queue, ctx->kernel,
                                 1, NULL, &ctx->global_size, NULL,
                                 0, NULL, NULL);
    if (ret != CL_SUCCESS) {
        fprintf(stderr, "clEnqueueNDRangeKernel: %s\n", ocl_strerror(ret));
        return -1;
    }
    clFlush(ctx->queue);
    return 0;
}

/* -------------------------------------------------------------------------
 * Public: async await (wait for kernel + download pubkeys)
 * ------------------------------------------------------------------------- */

int
ocl_ed25519_await(ocl_ed25519_ctx_t *ctx, uint8_t *pubkeys_out)
{
    cl_int ret;
    size_t pubkey_bytes = ctx->global_size * (size_t)ctx->keys_per_item * 32;

    ret = clEnqueueReadBuffer(ctx->queue, ctx->pubkeys_buf, CL_TRUE,
                              0, pubkey_bytes, pubkeys_out,
                              0, NULL, NULL);
    if (ret != CL_SUCCESS) {
        fprintf(stderr, "clEnqueueReadBuffer(pubkeys): %s\n", ocl_strerror(ret));
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Public: free
 * ------------------------------------------------------------------------- */

void
ocl_ed25519_free(ocl_ed25519_ctx_t *ctx)
{
    if (ctx->pubkeys_buf) { clReleaseMemObject(ctx->pubkeys_buf); ctx->pubkeys_buf = NULL; }
    if (ctx->seeds_buf)   { clReleaseMemObject(ctx->seeds_buf);   ctx->seeds_buf   = NULL; }
    if (ctx->kernel)      { clReleaseKernel(ctx->kernel);         ctx->kernel      = NULL; }
    if (ctx->program)     { clReleaseProgram(ctx->program);       ctx->program     = NULL; }
    if (ctx->queue)       { clReleaseCommandQueue(ctx->queue);    ctx->queue       = NULL; }
    if (ctx->ctx)         { clReleaseContext(ctx->ctx);           ctx->ctx         = NULL; }
}
