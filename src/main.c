#define _GNU_SOURCE

#include <sys/types.h>

#include <sys/stat.h>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#if defined(LOCKSTEP_WITH_NVML)
#include "nvml_step.h"
#endif
#include "step.h"
#include "field.h"


#define STAT_FORMAT \
		"%d (%16[^)]) %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld " \
		"%ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d " \
		"%u %u %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %d"

#define CREDENTIALS_FORMAT "%d %d"

#define UPTIME_FORMAT "%lf %lf"

#define NETSTAT_FORMAT "IpExt: %*u %*u %*u %*u %*u %*u %lu %lu %*u %*u %*u %*u %*u %*u %*u %*u %*u"

#define IO_FORMAT "rchar: %*u\nwchar: %*u\nsyscr: %*u\nsyscw: %*u\nread_bytes: %lu\nwrite_bytes: %lu\ncancelled_write_bytes: %lu"

#define STEP_FORMAT \
		"%d|%s|%c|%d|%d|%d|%d|%d|%u|%lu|%lu|%lu|%lu|%lu|%lu|%ld|%ld|%ld|%ld|%ld|" \
		"%ld|%llu|%lu|%ld|%lu|%lu|%lu|%lu|%lu|%lu|%lu|%lu|%lu|%lu|%lu|%lu|%lu|%d|%d|" \
		"%u|%u|%llu|%lu|%ld|%lu|%lu|%lu|%lu|%lu|%lu|%lu|%d|" \
		"%d|%d|" \
		"%lf|%lf|" \
		"%lu"

char buf[4096*4];
useconds_t interval = 1000000;
uid_t min_uid = 1000;
int running = 1;

field_t step_fields[] = {
	{"pid", "%d", offsetof(step_t, process_id)},
	{"state", "%c", offsetof(step_t, state)},
	{"ppid", "%d", offsetof(step_t, parent_process_id)},
	{"pgrp", "%d", offsetof(step_t, process_group_id)},
	{"session", "%d", offsetof(step_t, session_id)},
	{"tty_number", "%d", offsetof(step_t, tty_number)},
	{"tty_process_group_id", "%d", offsetof(step_t, tty_process_group_id)},
	{"flags", "%u", offsetof(step_t, flags)},
	{"minor_faults", "%lu", offsetof(step_t, minor_faults)},
	{"child_minor_faults", "%lu", offsetof(step_t, child_minor_faults)},
	{"major_faults", "%lu", offsetof(step_t, major_faults)},
	{"child_major_faults", "%lu", offsetof(step_t, child_major_faults)},
	{"userspace_time", "%lu", offsetof(step_t, userspace_time)},
	{"kernel_time", "%lu", offsetof(step_t, kernel_time)},
	{"child_userspace_time", "%ld", offsetof(step_t, child_userspace_time)},
	{"child_kernel_time", "%ld", offsetof(step_t, child_kernel_time)},
	{"priority", "%ld", offsetof(step_t, priority)},
	{"nice", "%ld", offsetof(step_t, nice)},
	{"num_threads", "%ld", offsetof(step_t, num_threads)},
	{"itrealvalue", "%ld", offsetof(step_t, unused)},
	{"start_time", "%llu", offsetof(step_t, start_time)},
	{"virtual_memory_size", "%lu", offsetof(step_t, virtual_memory_size)},
	{"resident_set_size", "%ld", offsetof(step_t, resident_set_size)},
	{"resident_set_limit", "%lu", offsetof(step_t, resident_set_limit)},
	{"code_segment_start", "%lu", offsetof(step_t, code_segment_start)},
	{"code_segment_end", "%lu", offsetof(step_t, code_segment_end)},
	{"stack_start", "%lu", offsetof(step_t, stack_start)},
	{"stack_pointer", "%lu", offsetof(step_t, stack_pointer)},
	{"instruction_pointer", "%lu", offsetof(step_t, instruction_pointer)},
	{"signals", "%lu", offsetof(step_t, signals)},
	{"blocked_signals", "%lu", offsetof(step_t, blocked_signals)},
	{"ignored_signal", "%lu", offsetof(step_t, ignored_signal)},
	{"caught_signal", "%lu", offsetof(step_t, caught_signal)},
	{"wait_channel", "%lu", offsetof(step_t, wait_channel)},
	{"num_swapped_pages", "%lu", offsetof(step_t, num_swapped_pages)},
	{"children_num_swapped_pages", "%lu", offsetof(step_t, children_num_swapped_pages)},
	{"exit_signal", "%d", offsetof(step_t, exit_signal)},
	{"processor", "%d", offsetof(step_t, processor)},
	{"realtime_priority", "%u", offsetof(step_t, realtime_priority)},
	{"policy", "%u", offsetof(step_t, policy)},
	{"cumulative_block_input_output_delay", "%llu", offsetof(step_t, cumulative_block_input_output_delay)},
	{"guest_time", "%lu", offsetof(step_t, guest_time)},
	{"child_guest_time", "%ld", offsetof(step_t, child_guest_time)},
	{"data_start", "%lu", offsetof(step_t, data_start)},
	{"data_end", "%lu", offsetof(step_t, data_end)},
	{"brk_start", "%lu", offsetof(step_t, brk_start)},
	{"arg_start", "%lu", offsetof(step_t, arg_start)},
	{"arg_end", "%lu", offsetof(step_t, arg_end)},
	{"env_start", "%lu", offsetof(step_t, env_start)},
	{"env_end", "%lu", offsetof(step_t, env_end)},
	{"exit_code", "%d", offsetof(step_t, exit_code)},
	{"user", "%d", offsetof(step_t, user_id)},
	{"group", "%d", offsetof(step_t, group_id)},
	{"uptime", "%lf", offsetof(step_t, uptime)},
	{"idle_time", "%lf", offsetof(step_t, idle_time)},
	{"timestamp", "%lu", offsetof(step_t, timestamp)},
	{"ticks_per_second", "%ld", offsetof(step_t, ticks_per_second)},
	{"command", "%s", offsetof(step_t, command)},
	{"executable", "%s", offsetof(step_t, executable)},
	{"read_bytes", "%lu", offsetof(step_t, io) + offsetof(io_step_t, read_bytes)},
	{"write_bytes", "%lu", offsetof(step_t, io) + offsetof(io_step_t, write_bytes)},
	{"cancelled_write_bytes", "%lu", offsetof(step_t, io) + offsetof(io_step_t, cancelled_write_bytes)},
	{"in_octets", "%lu", offsetof(step_t, network) + offsetof(network_step_t, in_octets)},
	{"out_octets", "%lu", offsetof(step_t, network) + offsetof(network_step_t, out_octets)}
	#if defined(LOCKSTEP_WITH_NVML)
	, {"nvml_gpu_utilisation", "%u", offsetof(step_t, nvml) + offsetof(nvml_step_t, gpu_utilisation)}
	, {"nvml_memory_utilisation", "%u", offsetof(step_t, nvml) + offsetof(nvml_step_t, memory_utilization)}
	, {"nvml_max_memory_usage", "%lu", offsetof(step_t, nvml) + offsetof(nvml_step_t, max_memory_usage)}
	, {"nvml_time_ms", "%lu", offsetof(step_t, nvml) + offsetof(nvml_step_t, time_ms)}
	#endif
};

int output_fields[sizeof(step_fields) / sizeof(field_t)];
int nfields = 0;

static inline field_t*
find_field(const char* name) {
	field_t* first = step_fields;
	field_t* last = step_fields + sizeof(step_fields) / sizeof(field_t);
	while (first != last) {
		if (strcmp(first->name, name) == 0) {
			return first;
		}
		++first;
	}
	return NULL;
}

static inline char*
print_field(char* buf, step_t* step, field_t* field) {
	void* ptr = ((char*)step) + field->offset;
	int ret = 0;
	switch (field->format[1]) {
		case 's':
			ret = sprintf(buf, field->format, (char*)ptr);
			break;
		case 'd':
			ret = sprintf(buf, field->format, *((int*)ptr));
			break;
		case 'u':
			ret = sprintf(buf, field->format, *((unsigned int*)ptr));
			break;
		case 'c':
			ret = sprintf(buf, field->format, *((char*)ptr));
			break;
		case 'l':
			switch (field->format[2]) {
				case 0:
					ret = sprintf(buf, field->format, *((long*)ptr));
					break;
				case 'd':
					ret = sprintf(buf, field->format, *((long int*)ptr));
					break;
				case 'u':
					ret = sprintf(buf, field->format, *((long unsigned int*)ptr));
					break;
				case 'f':
					ret = sprintf(buf, field->format, *((double*)ptr));
					break;
				case 'l':
					switch (field->format[3]) {
						case 0:
							ret = sprintf(buf, field->format, *((long long*)ptr));
							break;
						case 'd':
							ret = sprintf(buf, field->format, *((long long int*)ptr));
							break;
						case 'u':
							ret = sprintf(buf, field->format, *((long long unsigned int*)ptr));
							break;
						default:
							fprintf(stderr, "bad format character: %c\n", field->format[3]);
							break;
					}
					break;
				default:
					fprintf(stderr, "bad format character: %c\n", field->format[2]);
					break;
			}
			break;
		default:
			fprintf(stderr, "bad format character: %c\n", field->format[1]);
			break;
	}
	if (ret != -1) {
		buf += ret;
	}
	return buf;
}

static inline void
step_write(step_t* s) {
	char* first = buf;
	for (int i=0; i<nfields; ++i) {
		field_t* field = step_fields + output_fields[i];
		first = print_field(first, s, field);
		if (i != nfields-1) {
			*first++ = '|';
		}
	}
	*first = 0;
	puts(buf);
}

static inline int
is_number(const char* first) {
	while (*first != '\0') {
		if (*first < '0' || *first > '9') {
			return 0;
		}
		++first;
	}
	return 1;
}

static int
collect_executable(int process_dir_fd, const char* directory, step_t* s) {
	int ret = 0;
	int nbytes = readlinkat(
		process_dir_fd,
		"exe",
		s->executable,
		sizeof(s->executable)
	);
	if (nbytes == -1) {
		fprintf(stderr, "unable to read /proc/%s/exe link\n", directory);
		ret = -1;
		goto end;
	}
	s->executable[nbytes] = 0;
end:
	return ret;
}

static int
collect_stat(int process_dir_fd, const char* directory, step_t* s) {
	int ret = 0;
	int fd = openat(process_dir_fd, "stat", O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "unable to open /proc/%s/stat file\n", directory);
		return -1;
	}
	ssize_t nbytes = read(fd, buf, sizeof(buf)-1);
	if (nbytes == -1) {
		fprintf(stderr, "unable to read from /proc/%s/stat file\n", directory);
		ret = -1;
		goto close_fd;
	}
	buf[nbytes] = 0;
//	printf(buf);
	sscanf(
		buf,
		STAT_FORMAT,
		&s->process_id,
		s->command,
		&s->state,
		&s->parent_process_id,
		&s->process_group_id,
		&s->session_id,
		&s->tty_number,
		&s->tty_process_group_id,
		&s->flags,
		&s->minor_faults,
		&s->child_minor_faults,
		&s->major_faults,
		&s->child_major_faults,
		&s->userspace_time,
		&s->kernel_time,
		&s->child_userspace_time,
		&s->child_kernel_time,
		&s->priority,
		&s->nice,
		&s->num_threads,
		&s->unused,
		&s->start_time,
		&s->virtual_memory_size,
		&s->resident_set_size,
		&s->resident_set_limit,
		&s->code_segment_start,
		&s->code_segment_end,
		&s->stack_start,
		&s->stack_pointer,
		&s->instruction_pointer,
		&s->signals,
		&s->blocked_signals,
		&s->ignored_signal,
		&s->caught_signal,
		&s->wait_channel,
		&s->num_swapped_pages,
		&s->children_num_swapped_pages,
		&s->exit_signal,
		&s->processor,
		&s->realtime_priority,
		&s->policy,
		&s->cumulative_block_input_output_delay,
		&s->guest_time,
		&s->child_guest_time,
		&s->data_start,
		&s->data_end,
		&s->brk_start,
		&s->arg_start,
		&s->arg_end,
		&s->env_start,
		&s->env_end,
		&s->exit_code
	);
	if (collect_executable(process_dir_fd, directory, s) == -1) {
		fprintf(stderr, "failed to collect executable name\n");
		ret = -1;
		goto close_fd;
	}
close_fd:
	if (close(fd) == -1) {
		fprintf(stderr, "unable to close /proc/%s/stat file\n", directory);
		ret = -1;
		return -1;
	}
	return ret;
}

static int
collect_uptime(int proc_fd, step_t* s) {
	int fd = openat(proc_fd, "uptime", O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "unable to open /proc/uptime file\n");
		return -1;
	}
	char buf[128];
	ssize_t nbytes = read(fd, buf, sizeof(buf)-1);
	if (nbytes == -1) {
		fprintf(stderr, "unable to read from /proc/uptime file\n");
		goto close_fd;
	}
	buf[nbytes] = 0;
	sscanf(buf, UPTIME_FORMAT, &s->uptime, &s->idle_time);
close_fd:
	if (close(fd) == -1) {
		fprintf(stderr, "unable to close /proc/uptime file\n");
		return -1;
	}
	return 0;
}

static int
collect_io(int process_dir_fd, const char* directory, step_t* s) {
	int ret = 0;
	int fd = openat(process_dir_fd, "io", O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "unable to open /proc/%s/io file\n", directory);
		return -1;
	}
	char buf[4096];
	ssize_t nbytes = read(fd, buf, sizeof(buf)-1);
	if (nbytes == -1) {
		fprintf(stderr, "unable to read from /proc/%s/io file\n", directory);
		ret = -1;
		goto close_fd;
	}
	buf[nbytes] = 0;
	sscanf(
		buf,
		IO_FORMAT,
		&s->io.read_bytes,
		&s->io.write_bytes,
		&s->io.cancelled_write_bytes
	);
close_fd:
	if (close(fd) == -1) {
		fprintf(stderr, "unable to close /proc/%s/io file\n", directory);
		return -1;
	}
	return ret;
}

static char*
find_newline(char* first, char* last) {
	while (first != last) {
		if (*first++ == '\n') {
			break;
		}
	}
	return first;
}

static int
collect_network(int proc_fd, step_t* s) {
	int ret = 0;
	int fd = openat(proc_fd, "net/netstat", O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "unable to open /proc/net/netstat file\n");
		return -1;
	}
	char buf[4096];
	ssize_t nbytes = read(fd, buf, sizeof(buf)-1);
	if (nbytes == -1) {
		fprintf(stderr, "unable to read from /proc/net/netstat file\n");
		ret = -1;
		goto close_fd;
	}
	buf[nbytes] = 0;
	char* first = buf;
	char* last = first + nbytes;
	for	(int i=0; i<3; ++i) {
		first = find_newline(first, last);
	}
	if (first == last) {
		ret = -1;
		goto close_fd;
	}
	sscanf(first, NETSTAT_FORMAT, &s->network.in_octets, &s->network.out_octets);
close_fd:
	if (close(fd) == -1) {
		fprintf(stderr, "unable to close /proc/net/netstat file\n");
		return -1;
	}
	return ret;
}

static void
collect_all() {
	DIR* proc = opendir("/proc");
	if (proc == NULL) {
		perror("unable to open /proc directory");
	}
	int proc_fd = dirfd(proc);
	if (proc_fd == -1) {
		perror("unable to open /proc directory");
	}
	long ticks_per_second = sysconf(_SC_CLK_TCK);
	if (ticks_per_second == -1) {
		ticks_per_second = 100;
		fprintf(stderr, "failed to get ticks per second, using default value: %ld\n", ticks_per_second);
	}
	struct dirent* entry;
	pid_t self = getpid();
	while (1) {
		entry = readdir(proc);
		if (entry == NULL) {
			break;
		}
		step_t s;
		s.ticks_per_second = ticks_per_second;
		s.timestamp = time(NULL);
		if (collect_uptime(proc_fd, &s) == -1) {
			fprintf(stderr, "failed to collect uptime data for %s\n", entry->d_name);
		}
		struct stat st;
		if (fstatat(proc_fd, entry->d_name, &st, 0) == -1) {
			fprintf(stderr, "failed to stat %s\n", entry->d_name);
			continue;
		}
		s.user_id = st.st_uid;
		s.group_id = st.st_gid;
		if ((st.st_mode & S_IFMT) == S_IFDIR && is_number(entry->d_name)) {
			pid_t pid = atoi(entry->d_name);
			if (pid == 0) {
				continue;
			}
			if (st.st_uid < min_uid && pid != self) {
				continue;
			}
			const char* proc_dir_name = entry->d_name;
			int process_dir_fd = openat(proc_fd, proc_dir_name, O_PATH);
			if (process_dir_fd == -1) {
				fprintf(stderr, "unable to open /proc/%s directory\n", proc_dir_name);
				continue;
			}
			if (collect_stat(process_dir_fd, proc_dir_name, &s) == -1) {
				fprintf(stderr, "failed to collect data for %s\n", proc_dir_name);
				goto close_process_dir;
			}
			if (collect_io(process_dir_fd, proc_dir_name, &s) == -1) {
				fprintf(stderr, "failed to collect io data for %s\n", proc_dir_name);
				goto close_process_dir;
			}
			if (collect_network(process_dir_fd, &s) == -1) {
				fprintf(stderr, "failed to collect network data for %s\n", proc_dir_name);
				goto close_process_dir;
			}
			#if defined(LOCKSTEP_WITH_NVML)
			if (collect_nvml(pid, &s.nvml) == -1) {
				fprintf(stderr, "failed to collect nvml data for %s\n", proc_dir_name);
				goto close_process_dir;
			}
			#endif
close_process_dir:
			if (close(process_dir_fd) == -1) {
				fprintf(stderr, "unable to close /proc/%s directory\n", proc_dir_name);
			}
			if (nfields > 0) {
				step_write(&s);
			}
		}
	}
	if (closedir(proc) == -1) {
		perror("unable to close /proc directory");
	}
}

static void
help_message(const char* argv0) {
	printf("usage: %s [-i INTERVAL] [-f FIELD1,FIELD2,...] [-o FILE]\n", argv0);
	printf("  -i INTERVAL    interval in microseconds\n");
	printf("  -f FIELD1,...  fields\n");
	printf("  -o FILE        redirect output to FILE\n");
	printf("  -h             help\n");
	printf("\navailable fields:\n");
	field_t* first = step_fields;
	field_t* last = step_fields + sizeof(step_fields) / sizeof(field_t);
	while (first != last) {
		printf("  %s\n", first->name);
		++first;
	}
}

static void
parse_fields(char* fields_argument) {
	char* first = fields_argument;
	char* last = first + strlen(fields_argument);
	char* field_begin = first;
	nfields = 0;
	*last = ',';
	while (first != last+1) {
		if (*first == ',') {
			*first = 0;
			field_t* result = find_field(field_begin);
			if (result == NULL) {
				fprintf(stderr, "bad field: %s\n", field_begin);
				exit(1);
			}
			output_fields[nfields++] = result - step_fields;
			*first = ',';
			field_begin = first + 1;
		}
		++first;
	}
	*last = 0;
//	for (int i=0; i<nfields; ++i) {
//		fprintf(stderr, "field %s\n", step_fields[output_fields[i]].name);
//	}
}

static void
parse_options(int argc, char* argv[]) {
	int opt = 0;
	int help = 0;
	while ((opt = getopt(argc, argv, "i:f:o:h")) != -1) {
		if (opt == 'i') {
			useconds_t new_interval = atoi(optarg);
			if (new_interval <= 0) {
				fprintf(stderr, "bad interval %u\n", new_interval);
				exit(1);
			}
			interval = new_interval;
		}
		if (opt == 'f') {
			parse_fields(optarg);
		}
		if (opt == 'h') {
			help = 1;
		}
		if (opt == 'o') {
			int fd = open(optarg, O_CREAT|O_APPEND|O_WRONLY, 0644);
			if (dup2(fd, STDOUT_FILENO) == -1) {
				fprintf(stderr, "failed to redirect output to %s\n", optarg);
				close(fd);
				exit(1);
			}
		}
		if (opt == '?') {
			help_message(argv[0]);
			exit(1);
		}
	}
	if (help) {
		help_message(argv[0]);
		exit(0);
	}
}

static void
stop(int signal) {
	running = 0;
}

static void
signal_handlers() {
	int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGPIPE, SIGUSR1, SIGUSR2, SIGALRM};
	const int nsignals = sizeof(signals) / sizeof(int);
	for (int i=0; i<nsignals; ++i) {
		struct sigaction s = {0};
		s.sa_handler = stop;
		if (sigaction(signals[i], &s, NULL) == -1) {
			perror("failed to install signal handler");
			exit(1);
		}
	}
}

int main(int argc, char* argv[]) {
	signal_handlers();
	setlinebuf(stdout);
	parse_options(argc, argv);
	#if defined(LOCKSTEP_WITH_NVML)
    nvmlReturn_t result;
	result = nvmlInit();
	if (result != NVML_SUCCESS) {
		fprintf(stderr, "failed to initialise NVML: %s\n", nvmlErrorString(result));
		return 1;
	}
    result = nvmlDeviceGetCount(&nvml_device_count);
	if (result != NVML_SUCCESS) {
		fprintf(stderr, "failed to get device count: %s\n", nvmlErrorString(result));
		goto nvml_shutdown;
	}
	for (unsigned int i=0; i<nvml_device_count; ++i) {
		result = nvmlDeviceGetHandleByIndex(i, nvml_devices + i);
		if (result != NVML_SUCCESS) {
			fprintf(stderr, "failed to get device handle: %s\n", nvmlErrorString(result));
			goto nvml_shutdown;
		}
		nvmlEnableState_t state;
		result = nvmlDeviceGetAccountingMode(nvml_devices[i], &state);
		if (result != NVML_SUCCESS) {
			fprintf(stderr, "failed to get accounting mode: %s\n", nvmlErrorString(result));
			goto nvml_shutdown;
		}
		if (state == NVML_FEATURE_DISABLED) {
			result = nvmlDeviceSetAccountingMode(nvml_devices[i], NVML_FEATURE_ENABLED);
			if (result != NVML_SUCCESS) {
				fprintf(stderr, "failed to enable accounting mode: %s\n", nvmlErrorString(result));
				if (result == NVML_ERROR_NO_PERMISSION) {
					fprintf(stderr, "run as root or enable it manually\n");
				}
				goto nvml_shutdown;
			}
			fprintf(stderr, "accounting mode is enabled\n");
		}
	}
	#endif
	while (running) {
		collect_all();
		usleep(interval);
	}
	#if defined(LOCKSTEP_WITH_NVML)
nvml_shutdown:
	result = nvmlShutdown();
	if (result != NVML_SUCCESS) {
		fprintf(stderr, "failed to shutdowm NVML: %s\n", nvmlErrorString(result));
		return 1;
	}
	#endif
	return 0;
}
