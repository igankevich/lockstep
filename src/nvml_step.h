/*
Lockstep — log resources consumed by userland Linux processes.
© 2018 Ivan Gankevich

This file is part of Lockstep.

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
*/

#ifndef NVML_STEP_H
#define NVML_STEP_H

#include <nvml.h>

typedef unsigned int nvml_pid_t;

typedef struct {
    unsigned int gpu_utilisation;
    unsigned int memory_utilization;
    unsigned long long max_memory_usage;
    unsigned long long time_ms;
} nvml_step_t;

nvmlDevice_t nvml_devices[4096 / sizeof(nvmlDevice_t)];
unsigned int nvml_device_count = 0;

static int
collect_nvml(pid_t pid, nvml_step_t* nvml) {
	int ret = 0;
	nvmlDevice_t* first = nvml_devices;
	nvmlDevice_t* last = first + nvml_device_count;
    nvmlReturn_t result;
	nvmlAccountingStats_t stats;
	int first_update = 1;
	while (first != last) {
		result = nvmlDeviceGetAccountingStats(*first, pid, &stats);
		switch (result) {
			case NVML_SUCCESS:
				if (first_update) {
					memset(nvml, 0, sizeof(nvml_step_t));
					first_update = 0;
				}
				nvml->gpu_utilisation += stats.gpuUtilization;
				nvml->memory_utilization += stats.memoryUtilization;
				nvml->max_memory_usage += stats.maxMemoryUsage;
				nvml->time_ms += stats.time;
				break;
			case NVML_ERROR_NOT_FOUND:
				if (first_update) {
					memset(nvml, 0, sizeof(nvml_step_t));
				}
				break;
			default:
				fprintf(stderr, "failed to get nvml pid stats: %s\n", nvmlErrorString(result));
				return -1;
		}
		++first;
	}
	return ret;
}

#endif // vim:filetype=c
