#ifndef GPU_H
#define GPU_H

#include <nvml.h>

typedef unsigned int gpu_pid_t;

typedef struct {
    unsigned int gpu_utilisation;
    unsigned int memory_utilization;
    unsigned long long max_memory_usage;
    unsigned long long time_ms;
} gpu_step_t;

nvmlDevice_t gpu_devices[4096 / sizeof(nvmlDevice_t)];
unsigned int gpu_device_count = 0;

static int
collect_gpu(pid_t pid, gpu_step_t* gpu) {
	int ret = 0;
	nvmlDevice_t* first = gpu_devices;
	nvmlDevice_t* last = first + gpu_device_count;
    nvmlReturn_t result;
	nvmlAccountingStats_t stats;
	int first_update = 1;
	while (first != last) {
		result = nvmlDeviceGetAccountingStats(*first, pid, &stats);
		switch (result) {
			case NVML_SUCCESS:
				if (first_update) {
					memset(gpu, 0, sizeof(gpu_step_t));
					first_update = 0;
				}
				gpu->gpu_utilisation += stats.gpuUtilization;
				gpu->memory_utilization += stats.memoryUtilization;
				gpu->max_memory_usage += stats.maxMemoryUsage;
				gpu->time_ms += stats.time;
				break;
			case NVML_ERROR_NOT_FOUND:
				if (first_update) {
					memset(gpu, 0, sizeof(gpu_step_t));
				}
				break;
			default:
				fprintf(stderr, "failed to get GPU pid stats: %s\n", nvmlErrorString(result));
				return -1;
		}
		++first;
	}
	return ret;
}

#endif // vim:filetype=c
