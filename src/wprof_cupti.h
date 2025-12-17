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
	CUPTI_DRIVER_TRACE_CBID_cuCtxGetCurrent             = 304,
	CUPTI_DRIVER_TRACE_CBID_cuPointerGetAttribute       = 310,
	CUPTI_DRIVER_TRACE_CBID_cuDevicePrimaryCtxGetState  = 392,
	CUPTI_DRIVER_TRACE_CBID_cuPointerGetAttributes      = 450,
	CUPTI_DRIVER_TRACE_CBID_cuKernelGetAttribute        = 686,
};

enum CUpti_runtime_api_trace_cbid {
	CUPTI_RUNTIME_TRACE_CBID_cudaGetLastError_v3020     = 10,
	CUPTI_RUNTIME_TRACE_CBID_cudaPeekAtLastError_v3020  = 11,
	CUPTI_RUNTIME_TRACE_CBID_cudaGetDevice_v3020        = 17,
	CUPTI_RUNTIME_TRACE_CBID_cudaStreamIsCapturing_v10000 = 317,
};


#endif /* __WPROF_CUPTI_H__ */
