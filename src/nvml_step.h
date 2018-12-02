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
