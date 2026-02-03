/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
/*
 * Minimal CUPTI type definitions for wprof.
 *
 * This header provides just enough CUPTI type definitions for wprof to work
 * without depending on the full NVIDIA CUDA/CUPTI SDK headers. All types and
 * struct layouts are designed to be binary-compatible with the actual CUPTI
 * library (libcupti.so).
 */
#ifndef __WPROF_CUPTI_H__
#define __WPROF_CUPTI_H__

#include <stdint.h>
#include <stddef.h>

#define CUPTIAPI
#define CUPTI_PACKED_ALIGNMENT __attribute__((__packed__)) __attribute__((aligned(8)))

struct CUptx_st;
struct CUpti_Subscriber_st;
typedef struct CUctx_st *CUcontext;
typedef struct CUpti_Subscriber_st *CUpti_SubscriberHandle;

typedef enum {
	CUPTI_SUCCESS                                   = 0,
	CUPTI_ERROR_MAX_LIMIT_REACHED                   = 12,
	CUPTI_ERROR_MULTIPLE_SUBSCRIBERS_NOT_SUPPORTED  = 39,
} CUptiResult;

typedef enum {
	CUPTI_ACTIVITY_KIND_INVALID             = 0,
	CUPTI_ACTIVITY_KIND_MEMCPY              = 1,
	CUPTI_ACTIVITY_KIND_MEMSET              = 2,
	CUPTI_ACTIVITY_KIND_KERNEL              = 3,
	CUPTI_ACTIVITY_KIND_DRIVER              = 4,
	CUPTI_ACTIVITY_KIND_RUNTIME             = 5,
	CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL   = 10,
	CUPTI_ACTIVITY_KIND_MEMCPY2             = 22,
	CUPTI_ACTIVITY_KIND_CUDA_EVENT          = 36,
	CUPTI_ACTIVITY_KIND_SYNCHRONIZATION     = 38,
	CUPTI_ACTIVITY_KIND_MEMORY2             = 49,
} CUpti_ActivityKind;

typedef enum {
	CUPTI_ACTIVITY_THREAD_ID_TYPE_DEFAULT   = 0,
	CUPTI_ACTIVITY_THREAD_ID_TYPE_SYSTEM    = 1,
	CUPTI_ACTIVITY_THREAD_ID_TYPE_SIZE      = 2,
} CUpti_ActivityThreadIdType;

typedef enum {
	CUPTI_ACTIVITY_FLAG_NONE                = 0,
	CUPTI_ACTIVITY_FLAG_DEVICE_CONCURRENT_KERNELS = 1 << 0,
	CUPTI_ACTIVITY_FLAG_MEMCPY_ASYNC        = 1 << 0,
	CUPTI_ACTIVITY_FLAG_MEMSET_ASYNC        = 1 << 0,
	CUPTI_ACTIVITY_FLAG_FLUSH_FORCED        = 1 << 0,
} CUpti_ActivityFlag;

typedef enum {
	CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_UNKNOWN         = 0,
	CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_EVENT_SYNCHRONIZE = 1,
	CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_STREAM_WAIT_EVENT = 2,
	CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_STREAM_SYNCHRONIZE = 3,
	CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_CONTEXT_SYNCHRONIZE = 4,
} CUpti_ActivitySynchronizationType;

typedef int CUpti_ActivityPartitionedGlobalCacheConfig;

typedef enum {
	CUPTI_API_ENTER     = 0,
	CUPTI_API_EXIT      = 1,
} CUpti_ApiCallbackSite;

typedef enum {
	CUPTI_CB_DOMAIN_DRIVER_API  = 1,
	CUPTI_CB_DOMAIN_RUNTIME_API = 2,
} CUpti_CallbackDomain;

typedef uint32_t CUpti_CallbackId;

typedef struct {
	CUpti_ApiCallbackSite callbackSite;
	const char *functionName;
	const void *functionParams;
	void *functionReturnValue;
	const char *symbolName;
	CUcontext context;
	uint32_t contextUid;
	uint64_t *correlationData;
	uint32_t correlationId;
} CUpti_CallbackData;

typedef void (*CUpti_CallbackFunc)(void *userdata, CUpti_CallbackDomain domain, CUpti_CallbackId cbid, const void *cbdata);
typedef void (*CUpti_BuffersCallbackRequestFunc)(uint8_t **buffer, size_t *size, size_t *maxNumRecords);
typedef void (*CUpti_BuffersCallbackCompleteFunc)(CUcontext context, uint32_t streamId, uint8_t *buffer, size_t size, size_t validSize);

typedef struct CUPTI_PACKED_ALIGNMENT {
	CUpti_ActivityKind kind;
} CUpti_Activity;

typedef struct CUPTI_PACKED_ALIGNMENT {
	CUpti_ActivityKind kind;

	union {
		uint8_t both;
		struct {
			uint8_t requested:4;
			uint8_t executed:4;
		} config;
	} cacheConfig;

	uint8_t sharedMemoryConfig;
	uint16_t registersPerThread;

	CUpti_ActivityPartitionedGlobalCacheConfig partitionedGlobalCacheRequested;
	CUpti_ActivityPartitionedGlobalCacheConfig partitionedGlobalCacheExecuted;

	uint64_t start;
	uint64_t end;
	uint64_t completed;

	uint32_t deviceId;
	uint32_t contextId;
	uint32_t streamId;

	int32_t gridX;
	int32_t gridY;
	int32_t gridZ;
	int32_t blockX;
	int32_t blockY;
	int32_t blockZ;

	int32_t staticSharedMemory;
	int32_t dynamicSharedMemory;
	uint32_t localMemoryPerThread;
	uint32_t localMemoryTotal;

	uint32_t correlationId;
	int64_t gridId;

	const char *name;
	void *reserved0;

	uint64_t queued;
	uint64_t submitted;

	uint8_t launchType;
	uint8_t isSharedMemoryCarveoutRequested;
	uint8_t sharedMemoryCarveoutRequested;
	uint8_t padding;

	uint32_t sharedMemoryExecuted;
} CUpti_ActivityKernel4;

typedef struct CUPTI_PACKED_ALIGNMENT {
	CUpti_ActivityKind kind;

	uint8_t copyKind;
	uint8_t srcKind;
	uint8_t dstKind;
	uint8_t flags;

	uint64_t bytes;
	uint64_t start;
	uint64_t end;

	uint32_t deviceId;
	uint32_t contextId;
	uint32_t streamId;
	uint32_t correlationId;
	uint32_t runtimeCorrelationId;

	uint32_t pad;

	void *reserved0;
} CUpti_ActivityMemcpy;

typedef struct CUPTI_PACKED_ALIGNMENT {
	CUpti_ActivityKind kind;

	uint32_t value;
	uint64_t bytes;
	uint64_t start;
	uint64_t end;

	uint32_t deviceId;
	uint32_t contextId;
	uint32_t streamId;
	uint32_t correlationId;

	uint16_t flags;
	uint16_t memoryKind;

	uint32_t pad;

	void *reserved0;
} CUpti_ActivityMemset;

typedef struct CUPTI_PACKED_ALIGNMENT {
	CUpti_ActivityKind kind;

	CUpti_CallbackId cbid;

	uint64_t start;
	uint64_t end;

	uint32_t processId;
	uint32_t threadId;
	uint32_t correlationId;
	uint32_t returnValue;
} CUpti_ActivityAPI;

typedef struct CUPTI_PACKED_ALIGNMENT {
	CUpti_ActivityKind kind;

	CUpti_ActivitySynchronizationType type;

	uint64_t start;
	uint64_t end;

	uint32_t correlationId;
	uint32_t contextId;
	uint32_t streamId;
	uint32_t cudaEventId;
} CUpti_ActivitySynchronization;

enum CUpti_driver_api_trace_cbid {
	/* uninteresting high-frequency APIs */
	CUPTI_DRIVER_TRACE_CBID_cuCtxGetCurrent             = 304,
	CUPTI_DRIVER_TRACE_CBID_cuPointerGetAttribute       = 310,
	CUPTI_DRIVER_TRACE_CBID_cuDevicePrimaryCtxGetState  = 392,
	CUPTI_DRIVER_TRACE_CBID_cuPointerGetAttributes      = 450,
	CUPTI_DRIVER_TRACE_CBID_cuKernelGetAttribute        = 686,

	/* call stack producing APIs */
	CUPTI_DRIVER_TRACE_CBID_cuCtxSynchronize = 17,
	CUPTI_DRIVER_TRACE_CBID_cuLaunch = 115,
	CUPTI_DRIVER_TRACE_CBID_cuLaunchGrid = 116,
	CUPTI_DRIVER_TRACE_CBID_cuLaunchGridAsync = 117,
	CUPTI_DRIVER_TRACE_CBID_cuEventSynchronize = 121,
	CUPTI_DRIVER_TRACE_CBID_cuStreamSynchronize = 126,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD8Async = 216,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD16Async = 218,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD32Async = 220,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D8Async = 222,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D16Async = 224,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D32Async = 226,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD8_v2 = 249,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD16_v2 = 250,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD32_v2 = 251,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D8_v2 = 252,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D16_v2 = 253,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D32_v2 = 254,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoD_v2 = 276,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoDAsync_v2 = 277,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoH_v2 = 278,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoHAsync_v2 = 279,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoD_v2 = 280,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoDAsync_v2 = 281,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoH_v2 = 282,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoHAsync_v2 = 283,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoD_v2 = 284,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoA_v2 = 285,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoA_v2 = 286,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy2D_v2 = 287,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy2DUnaligned_v2 = 288,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy2DAsync_v2 = 289,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy3D_v2 = 290,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy3DAsync_v2 = 291,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoA_v2 = 292,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoAAsync_v2 = 293,
	CUPTI_DRIVER_TRACE_CBID_cuStreamWaitEvent = 295,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy = 305,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyAsync = 306,
	CUPTI_DRIVER_TRACE_CBID_cuLaunchKernel = 307,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyPeer = 318,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyPeerAsync = 319,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy3DPeer = 320,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy3DPeerAsync = 321,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoD_v2_ptds = 397,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoH_v2_ptds = 398,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoD_v2_ptds = 399,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoA_v2_ptds = 400,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoD_v2_ptds = 401,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoA_v2_ptds = 402,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoH_v2_ptds = 403,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoA_v2_ptds = 404,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy2D_v2_ptds = 405,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy2DUnaligned_v2_ptds = 406,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy3D_v2_ptds = 407,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy_ptds = 408,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyPeer_ptds = 409,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy3DPeer_ptds = 410,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD8_v2_ptds = 411,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD16_v2_ptds = 412,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD32_v2_ptds = 413,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D8_v2_ptds = 414,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D16_v2_ptds = 415,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D32_v2_ptds = 416,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyAsync_ptsz = 418,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoAAsync_v2_ptsz = 419,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoHAsync_v2_ptsz = 420,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoDAsync_v2_ptsz = 421,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoHAsync_v2_ptsz = 422,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoDAsync_v2_ptsz = 423,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy2DAsync_v2_ptsz = 424,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy3DAsync_v2_ptsz = 425,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyPeerAsync_ptsz = 426,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpy3DPeerAsync_ptsz = 427,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD8Async_ptsz = 428,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD16Async_ptsz = 429,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD32Async_ptsz = 430,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D8Async_ptsz = 431,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D16Async_ptsz = 432,
	CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D32Async_ptsz = 433,
	CUPTI_DRIVER_TRACE_CBID_cuStreamWaitEvent_ptsz = 436,
	CUPTI_DRIVER_TRACE_CBID_cuStreamSynchronize_ptsz = 440,
	CUPTI_DRIVER_TRACE_CBID_cuLaunchKernel_ptsz = 442,
	CUPTI_DRIVER_TRACE_CBID_cuLaunchCooperativeKernel = 477,
	CUPTI_DRIVER_TRACE_CBID_cuLaunchCooperativeKernel_ptsz = 478,
	CUPTI_DRIVER_TRACE_CBID_cuLaunchCooperativeKernelMultiDevice = 480,
	CUPTI_DRIVER_TRACE_CBID_cuGraphInstantiate = 513,
	CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch = 514,
	CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch_ptsz = 515,
	CUPTI_DRIVER_TRACE_CBID_cuLaunchHostFunc = 527,
	CUPTI_DRIVER_TRACE_CBID_cuLaunchHostFunc_ptsz = 528,
	CUPTI_DRIVER_TRACE_CBID_cuGraphExecUpdate = 561,
	CUPTI_DRIVER_TRACE_CBID_cuGraphUpload = 580,
	CUPTI_DRIVER_TRACE_CBID_cuGraphUpload_ptsz = 581,
	CUPTI_DRIVER_TRACE_CBID_cuGraphInstantiateWithFlags = 643,
	CUPTI_DRIVER_TRACE_CBID_cuLaunchKernelEx = 652,
	CUPTI_DRIVER_TRACE_CBID_cuLaunchKernelEx_ptsz = 653,
	CUPTI_DRIVER_TRACE_CBID_cuGraphInstantiateWithParams = 656,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyBatchAsync = 776,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyBatchAsync_ptsz = 777,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyBatch3DAsync = 778,
	CUPTI_DRIVER_TRACE_CBID_cuMemcpyBatch3DAsync_ptsz = 779,
};

enum CUpti_runtime_api_trace_cbid {
	/* uninteresting high-frequency APIs */
	CUPTI_RUNTIME_TRACE_CBID_cudaGetLastError_v3020 = 10,
	CUPTI_RUNTIME_TRACE_CBID_cudaPeekAtLastError_v3020 = 11,
	CUPTI_RUNTIME_TRACE_CBID_cudaGetDevice_v3020 = 17,
	CUPTI_RUNTIME_TRACE_CBID_cudaStreamIsCapturing_v10000 = 317,

	/* call stack producing APIs */
	CUPTI_RUNTIME_TRACE_CBID_cudaLaunch_v3020 = 13,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy_v3020 = 31,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2D_v3020 = 32,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToArray_v3020 = 33,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DToArray_v3020 = 34,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromArray_v3020 = 35,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DFromArray_v3020 = 36,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyArrayToArray_v3020 = 37,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DArrayToArray_v3020 = 38,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToSymbol_v3020 = 39,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromSymbol_v3020 = 40,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyAsync_v3020 = 41,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToArrayAsync_v3020 = 42,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromArrayAsync_v3020 = 43,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DAsync_v3020 = 44,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DToArrayAsync_v3020 = 45,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DFromArrayAsync_v3020 = 46,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToSymbolAsync_v3020 = 47,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromSymbolAsync_v3020 = 48,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemset_v3020 = 49,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemset2D_v3020 = 50,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemsetAsync_v3020 = 51,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemset2DAsync_v3020 = 52,
	CUPTI_RUNTIME_TRACE_CBID_cudaThreadSynchronize_v3020 = 126,
	CUPTI_RUNTIME_TRACE_CBID_cudaStreamSynchronize_v3020 = 131,
	CUPTI_RUNTIME_TRACE_CBID_cudaEventSynchronize_v3020 = 137,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemset3D_v3020 = 142,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemset3DAsync_v3020 = 143,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3D_v3020 = 144,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3DAsync_v3020 = 145,
	CUPTI_RUNTIME_TRACE_CBID_cudaStreamWaitEvent_v3020 = 147,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyPeer_v4000 = 160,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyPeerAsync_v4000 = 161,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3DPeer_v4000 = 162,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3DPeerAsync_v4000 = 163,
	CUPTI_RUNTIME_TRACE_CBID_cudaDeviceSynchronize_v3020 = 165,
	CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_v7000 = 211,
	CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_ptsz_v7000 = 214,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy_ptds_v7000 = 215,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2D_ptds_v7000 = 216,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToArray_ptds_v7000 = 217,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DToArray_ptds_v7000 = 218,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromArray_ptds_v7000 = 219,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DFromArray_ptds_v7000 = 220,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToSymbol_ptds_v7000 = 223,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromSymbol_ptds_v7000 = 224,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyAsync_ptsz_v7000 = 225,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToArrayAsync_ptsz_v7000 = 226,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromArrayAsync_ptsz_v7000 = 227,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DAsync_ptsz_v7000 = 228,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DToArrayAsync_ptsz_v7000 = 229,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DFromArrayAsync_ptsz_v7000 = 230,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToSymbolAsync_ptsz_v7000 = 231,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromSymbolAsync_ptsz_v7000 = 232,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemset_ptds_v7000 = 233,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemset2D_ptds_v7000 = 234,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemsetAsync_ptsz_v7000 = 235,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemset2DAsync_ptsz_v7000 = 236,
	CUPTI_RUNTIME_TRACE_CBID_cudaStreamSynchronize_ptsz_v7000 = 239,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemset3D_ptds_v7000 = 243,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemset3DAsync_ptsz_v7000 = 244,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3D_ptds_v7000 = 245,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3DAsync_ptsz_v7000 = 246,
	CUPTI_RUNTIME_TRACE_CBID_cudaStreamWaitEvent_ptsz_v7000 = 247,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3DPeer_ptds_v7000 = 249,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3DPeerAsync_ptsz_v7000 = 250,
	CUPTI_RUNTIME_TRACE_CBID_cudaLaunchCooperativeKernel_v9000 = 269,
	CUPTI_RUNTIME_TRACE_CBID_cudaLaunchCooperativeKernel_ptsz_v9000 = 270,
	CUPTI_RUNTIME_TRACE_CBID_cudaLaunchCooperativeKernelMultiDevice_v9000 = 272,
	CUPTI_RUNTIME_TRACE_CBID_cudaLaunchHostFunc_v10000 = 284,
	CUPTI_RUNTIME_TRACE_CBID_cudaLaunchHostFunc_ptsz_v10000 = 285,
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphInstantiate_v10000 = 310,
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_v10000 = 311,
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_ptsz_v10000 = 312,
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphExecUpdate_v10020 = 335,
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphUpload_v10000 = 348,
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphUpload_ptsz_v10000 = 349,
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphInstantiateWithFlags_v11040 = 418,
	CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernelExC_v11060 = 430,
	CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernelExC_ptsz_v11060 = 431,
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphInstantiateWithParams_v12000 = 436,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyBatchAsync_v12080 = 482,
	CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyBatchAsync_ptsz_v12080 = 483,
};

enum cuda_api_category {
    CUDA_CAT_OTHER = 0,
    CUDA_CAT_LAUNCH,
    CUDA_CAT_MEM,
    CUDA_CAT_SYNC,
};

static inline enum cuda_api_category cuda_api_category(CUpti_CallbackDomain domain, CUpti_CallbackId cbid)
{
	if (domain == CUPTI_CB_DOMAIN_RUNTIME_API) {
		switch (cbid) {
		case CUPTI_RUNTIME_TRACE_CBID_cudaDeviceSynchronize_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaThreadSynchronize_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaStreamSynchronize_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaStreamSynchronize_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaStreamWaitEvent_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaStreamWaitEvent_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaEventSynchronize_v3020:
			return CUDA_CAT_SYNC;

		case CUPTI_RUNTIME_TRACE_CBID_cudaLaunch_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchCooperativeKernel_v9000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchCooperativeKernel_ptsz_v9000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchCooperativeKernelMultiDevice_v9000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernelExC_v11060:
		case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernelExC_ptsz_v11060:
		case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchHostFunc_v10000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaLaunchHostFunc_ptsz_v10000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_v10000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_ptsz_v10000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaGraphUpload_v10000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaGraphUpload_ptsz_v10000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaGraphInstantiate_v10000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaGraphInstantiateWithFlags_v11040:
		case CUPTI_RUNTIME_TRACE_CBID_cudaGraphInstantiateWithParams_v12000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaGraphExecUpdate_v10020:
			return CUDA_CAT_LAUNCH;

		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyAsync_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyAsync_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2D_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DAsync_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2D_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DAsync_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3D_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3DAsync_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3D_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3DAsync_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyPeer_v4000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyPeerAsync_v4000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3DPeer_v4000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3DPeerAsync_v4000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3DPeer_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy3DPeerAsync_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToSymbol_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToSymbolAsync_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromSymbol_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromSymbolAsync_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToSymbol_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToSymbolAsync_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromSymbol_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromSymbolAsync_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToArray_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToArrayAsync_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromArray_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromArrayAsync_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyArrayToArray_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DToArray_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DToArrayAsync_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DFromArray_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DFromArrayAsync_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DArrayToArray_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToArray_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyToArrayAsync_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromArray_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyFromArrayAsync_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DToArray_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DToArrayAsync_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DFromArray_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpy2DFromArrayAsync_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyBatchAsync_v12080:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemcpyBatchAsync_ptsz_v12080:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemset_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemsetAsync_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemset_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemsetAsync_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemset2D_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemset2DAsync_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemset2D_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemset2DAsync_ptsz_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemset3D_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemset3DAsync_v3020:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemset3D_ptds_v7000:
		case CUPTI_RUNTIME_TRACE_CBID_cudaMemset3DAsync_ptsz_v7000:
			return CUDA_CAT_MEM;

		default:
			return CUDA_CAT_OTHER;
		}
	} else if (domain == CUPTI_CB_DOMAIN_DRIVER_API) {
		switch (cbid) {
		case CUPTI_DRIVER_TRACE_CBID_cuCtxSynchronize:
		case CUPTI_DRIVER_TRACE_CBID_cuStreamSynchronize:
		case CUPTI_DRIVER_TRACE_CBID_cuStreamSynchronize_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuStreamWaitEvent:
		case CUPTI_DRIVER_TRACE_CBID_cuStreamWaitEvent_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuEventSynchronize:
			return CUDA_CAT_SYNC;

		case CUPTI_DRIVER_TRACE_CBID_cuLaunch:
		case CUPTI_DRIVER_TRACE_CBID_cuLaunchGrid:
		case CUPTI_DRIVER_TRACE_CBID_cuLaunchGridAsync:
		case CUPTI_DRIVER_TRACE_CBID_cuLaunchKernel:
		case CUPTI_DRIVER_TRACE_CBID_cuLaunchKernel_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuLaunchCooperativeKernel:
		case CUPTI_DRIVER_TRACE_CBID_cuLaunchCooperativeKernel_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuLaunchCooperativeKernelMultiDevice:
		case CUPTI_DRIVER_TRACE_CBID_cuLaunchKernelEx:
		case CUPTI_DRIVER_TRACE_CBID_cuLaunchKernelEx_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuLaunchHostFunc:
		case CUPTI_DRIVER_TRACE_CBID_cuLaunchHostFunc_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch:
		case CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuGraphUpload:
		case CUPTI_DRIVER_TRACE_CBID_cuGraphUpload_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuGraphInstantiate:
		case CUPTI_DRIVER_TRACE_CBID_cuGraphInstantiateWithFlags:
		case CUPTI_DRIVER_TRACE_CBID_cuGraphInstantiateWithParams:
		case CUPTI_DRIVER_TRACE_CBID_cuGraphExecUpdate:
			return CUDA_CAT_LAUNCH;

		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyAsync:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyAsync_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoD_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoDAsync_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoD_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoDAsync_v2_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoH_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoHAsync_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoH_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoHAsync_v2_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoD_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoDAsync_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoD_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoDAsync_v2_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy2D_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy2DAsync_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy2D_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy2DAsync_v2_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy2DUnaligned_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy2DUnaligned_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy3D_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy3DAsync_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy3D_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy3DAsync_v2_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyPeer:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyPeerAsync:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyPeer_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyPeerAsync_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy3DPeer:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy3DPeerAsync:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy3DPeer_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpy3DPeerAsync_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoH_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoHAsync_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoH_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoHAsync_v2_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoA_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoAAsync_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoA_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyHtoAAsync_v2_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoD_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoD_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoA_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyDtoA_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoA_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyAtoA_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyBatchAsync:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyBatchAsync_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyBatch3DAsync:
		case CUPTI_DRIVER_TRACE_CBID_cuMemcpyBatch3DAsync_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD8_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD8Async:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD8_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD8Async_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD16_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD16Async:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD16_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD16Async_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD32_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD32Async:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD32_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD32Async_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D8_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D8Async:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D8_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D8Async_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D16_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D16Async:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D16_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D16Async_ptsz:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D32_v2:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D32Async:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D32_v2_ptds:
		case CUPTI_DRIVER_TRACE_CBID_cuMemsetD2D32Async_ptsz:
			return CUDA_CAT_MEM;

		default:
			return CUDA_CAT_OTHER;
		}
	}

	return CUDA_CAT_OTHER;
}

#endif /* __WPROF_CUPTI_H__ */
