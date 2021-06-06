/*
Lockstep — log resources consumed by userland Linux processes.
© 2018, 2019, 2020 Ivan Gankevich

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

#define _GNU_SOURCE

#include <sys/types.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#if defined(LOCKSTEP_WITH_NVML)
#include <nvml_step.h>
#endif
#include <field.h>
#include <step.h>


#define STAT_FORMAT \
        "%d (%16[^)]) %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld " \
        "%ld %s %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d " \
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

static char buf[4096*4];
static unsigned long interval = 1000000;
static unsigned long syslog_interval = 5*60*1000000;
static int enable_syslog = 0;
static int syslog_facility = LOG_USER;
static int syslog_level = LOG_INFO;
static uid_t min_uid = 1000;
static int running = 1;
static int process_out_fd = -1;
static int system_out_fd = -1;
typedef enum {
    SYSTEM_HWMON = 1,
    SYSTEM_DRM = 2,
    SYSTEM_THERMAL = 4,
} system_fields_type;
static system_fields_type system_fields = 0;
static system_fields_type syslog_system_fields = 0;
static char*const* child_argv = 0;
static pid_t child_pid = 0;

static field_type step_fields[] = {
    {"pid", "%d", offsetof(step_type, process_id)},
    {"state", "%c", offsetof(step_type, state)},
    {"ppid", "%d", offsetof(step_type, parent_process_id)},
    {"pgrp", "%d", offsetof(step_type, process_group_id)},
    {"session", "%d", offsetof(step_type, session_id)},
    {"tty_number", "%d", offsetof(step_type, tty_number)},
    {"tty_process_group_id", "%d", offsetof(step_type, tty_process_group_id)},
    {"flags", "%u", offsetof(step_type, flags)},
    {"minor_faults", "%lu", offsetof(step_type, minor_faults)},
    {"child_minor_faults", "%lu", offsetof(step_type, child_minor_faults)},
    {"major_faults", "%lu", offsetof(step_type, major_faults)},
    {"child_major_faults", "%lu", offsetof(step_type, child_major_faults)},
    {"userspace_time", "%lu", offsetof(step_type, userspace_time)},
    {"kernel_time", "%lu", offsetof(step_type, kernel_time)},
    {"child_userspace_time", "%ld", offsetof(step_type, child_userspace_time)},
    {"child_kernel_time", "%ld", offsetof(step_type, child_kernel_time)},
    {"priority", "%ld", offsetof(step_type, priority)},
    {"nice", "%ld", offsetof(step_type, nice)},
    {"num_threads", "%ld", offsetof(step_type, num_threads)},
    {"itrealvalue", "%ld", offsetof(step_type, unused)},
    {"start_time", "%s", offsetof(step_type, start_time)},
    {"virtual_memory_size", "%lu", offsetof(step_type, virtual_memory_size)},
    {"resident_set_size", "%ld", offsetof(step_type, resident_set_size)},
    {"resident_set_limit", "%lu", offsetof(step_type, resident_set_limit)},
    {"code_segment_start", "%lu", offsetof(step_type, code_segment_start)},
    {"code_segment_end", "%lu", offsetof(step_type, code_segment_end)},
    {"stack_start", "%lu", offsetof(step_type, stack_start)},
    {"stack_pointer", "%lu", offsetof(step_type, stack_pointer)},
    {"instruction_pointer", "%lu", offsetof(step_type, instruction_pointer)},
    {"signals", "%lu", offsetof(step_type, signals)},
    {"blocked_signals", "%lu", offsetof(step_type, blocked_signals)},
    {"ignored_signal", "%lu", offsetof(step_type, ignored_signal)},
    {"caught_signal", "%lu", offsetof(step_type, caught_signal)},
    {"wait_channel", "%lu", offsetof(step_type, wait_channel)},
    {"num_swapped_pages", "%lu", offsetof(step_type, num_swapped_pages)},
    {"children_num_swapped_pages", "%lu", offsetof(step_type, children_num_swapped_pages)},
    {"exit_signal", "%d", offsetof(step_type, exit_signal)},
    {"processor", "%d", offsetof(step_type, processor)},
    {"realtime_priority", "%u", offsetof(step_type, realtime_priority)},
    {"policy", "%u", offsetof(step_type, policy)},
    {"cumulative_block_input_output_delay", "%llu", offsetof(step_type, cumulative_block_input_output_delay)},
    {"guest_time", "%lu", offsetof(step_type, guest_time)},
    {"child_guest_time", "%ld", offsetof(step_type, child_guest_time)},
    {"data_start", "%lu", offsetof(step_type, data_start)},
    {"data_end", "%lu", offsetof(step_type, data_end)},
    {"brk_start", "%lu", offsetof(step_type, brk_start)},
    {"arg_start", "%lu", offsetof(step_type, arg_start)},
    {"arg_end", "%lu", offsetof(step_type, arg_end)},
    {"env_start", "%lu", offsetof(step_type, env_start)},
    {"env_end", "%lu", offsetof(step_type, env_end)},
    {"exit_code", "%d", offsetof(step_type, exit_code)},
    {"user", "%d", offsetof(step_type, user_id)},
    {"group", "%d", offsetof(step_type, group_id)},
    {"uptime", "%lf", offsetof(step_type, uptime)},
    {"idle_time", "%lf", offsetof(step_type, idle_time)},
    {"timestamp", "%lu", offsetof(step_type, timestamp)},
    {"ticks_per_second", "%ld", offsetof(step_type, ticks_per_second)},
    {"command", "%s", offsetof(step_type, command)},
    {"executable", "%s", offsetof(step_type, executable)},
    {"read_bytes", "%lu", offsetof(step_type, io) + offsetof(io_step_t, read_bytes)},
    {"write_bytes", "%lu", offsetof(step_type, io) + offsetof(io_step_t, write_bytes)},
    {"cancelled_write_bytes", "%lu", offsetof(step_type, io) + offsetof(io_step_t, cancelled_write_bytes)},
    {"in_octets", "%lu", offsetof(step_type, network) + offsetof(network_step_t, in_octets)},
    {"out_octets", "%lu", offsetof(step_type, network) + offsetof(network_step_t, out_octets)}
    #if defined(LOCKSTEP_WITH_NVML)
    , {"nvml_gpu_utilisation", "%u", offsetof(step_type, nvml) + offsetof(nvml_step_t, gpu_utilisation)}
    , {"nvml_memory_utilisation", "%u", offsetof(step_type, nvml) + offsetof(nvml_step_t, memory_utilization)}
    , {"nvml_max_memory_usage", "%lu", offsetof(step_type, nvml) + offsetof(nvml_step_t, max_memory_usage)}
    , {"nvml_time_ms", "%lu", offsetof(step_type, nvml) + offsetof(nvml_step_t, time_ms)}
    #endif
};

static int process_fields[sizeof(step_fields) / sizeof(field_type)];
static int num_process_fields = 0;

static inline field_type*
find_field(const char* name) {
    field_type* first = step_fields;
    field_type* last = step_fields + sizeof(step_fields) / sizeof(field_type);
    while (first != last) {
        if (strcmp(first->name, name) == 0) {
            return first;
        }
        ++first;
    }
    return NULL;
}

static inline char*
print_field(char* buf, step_type* step, field_type* field) {
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
write_buffer(int fd, const char* first, size_t n, system_fields_type fields) {
    if (enable_syslog && (syslog_system_fields & fields)) {
        syslog(syslog_facility|syslog_level, "%s", first);
    }
    while (n != 0) {
        ssize_t nwritten = write(fd, first, n);
        if (nwritten == -1) { perror("write"); break; }
        n -= nwritten;
        first += nwritten;
    }
}

static inline void
step_write(step_type* s) {
    char* first = buf;
    for (int i=0; i<num_process_fields; ++i) {
        field_type* field = step_fields + process_fields[i];
        first = print_field(first, s, field);
        if (i != num_process_fields-1) {
            *first++ = '|';
        }
    }
    *first++ = '\n';
    *first = 0;
    write_buffer(process_out_fd, buf, first-buf, 0);
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
collect_executable(int process_dir_fd, const char* directory, step_type* s) {
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
collect_stat(int process_dir_fd, const char* directory, step_type* s) {
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
//  printf(buf);
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
        s->start_time,
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
collect_uptime(int proc_fd, step_type* s) {
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
collect_io(int process_dir_fd, const char* directory, step_type* s) {
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
collect_network(int proc_fd, step_type* s) {
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
    for (int i=0; i<3; ++i) {
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
collect_proc(time_t timestamp) {
    DIR* proc = opendir("/proc");
    if (proc == NULL) {
        perror("unable to open /proc directory");
        return;
    }
    int proc_fd = dirfd(proc);
    if (proc_fd == -1) {
        perror("unable to open /proc directory");
        return;
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
        step_type s;
        s.ticks_per_second = ticks_per_second;
        s.timestamp = timestamp;
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
            step_write(&s);
        }
    }
    if (closedir(proc) == -1) {
        perror("unable to close /proc directory");
        return;
    }
}

static void
collect_hwmon(time_t timestamp) {
    DIR* hwmon = opendir("/sys/class/hwmon");
    if (hwmon == NULL) {
        perror("unable to open /sys/class/hwmon directory");
        return;
    }
    int hwmon_fd = dirfd(hwmon);
    if (hwmon_fd == -1) {
        perror("unable to open /sys/class/hwmon directory");
        return;
    }
    for (struct dirent* entry = readdir(hwmon);
         entry != NULL;
         entry = readdir(hwmon)) {
        const char* name = entry->d_name;
        if (strncmp(name, "hwmon", 5) != 0) {
            continue;
        }
        int hwmon_subdir_fd = openat(hwmon_fd, name, O_RDONLY);
        if (hwmon_subdir_fd == -1) {
            fprintf(stderr, "unable to open /sys/class/hwmon/%s directory\n", name);
            continue;
        }
        DIR* hwmon_sub = fdopendir(hwmon_subdir_fd);
        if (hwmon_sub == NULL) {
            fprintf(stderr, "unable to open /sys/class/hwmon/%s directory", name);
            continue;
        }
        for (struct dirent* entry2 = readdir(hwmon_sub);
             entry2 != NULL;
             entry2 = readdir(hwmon_sub)) {
            char* name2 = entry2->d_name;
            size_t len = strlen(name2);
            size_t prefix_len = len-6;
            if (!(len >= 6 && strcmp(name2+prefix_len, "_input") == 0)) { continue; }
            int fd = openat(hwmon_subdir_fd, name2, O_RDONLY);
            if (fd == -1) {
                fprintf(stderr, "unable to open /sys/class/hwmon/%s/%s file\n", name, name2);
                continue;
            }
            char* first = buf;
            int nwritten = sprintf(first, "%lu|/sys/class/hwmon/%s/%s|", timestamp, name, name2);
            if (nwritten == -1) { goto close_fd; }
            first += nwritten;
            ssize_t nbytes = read(fd, first, sizeof(buf)-4-(first-buf));
            if (nbytes == -1) {
                fprintf(stderr, "unable to read from /sys/class/hwmon/%s/%s file\n", name, name2);
                goto close_fd;
            }
            for (ssize_t i=0; i<nbytes && *first != '\n'; ++i, ++first);
            *first++ = '|';
            // check for *_label
            memcpy(name2+prefix_len+1, "label", 5);
            int fd2 = openat(hwmon_subdir_fd, name2, O_RDONLY);
            if (fd2 != -1) {
                ssize_t nbytes = read(fd2, first, sizeof(buf)-3-(first-buf));
                if (nbytes == -1) {
                    fprintf(stderr, "unable to read from /sys/class/hwmon/%s/%s file\n", name, name2);
                    goto close_fd_2;
                }
                for (ssize_t i=0; i<nbytes && *first != '\n'; ++i, ++first);
            }
            *first++ = '|';
            // check for name
            int fd3 = openat(hwmon_subdir_fd, "name", O_RDONLY);
            if (fd3 != -1) {
                ssize_t nbytes = read(fd3, first, sizeof(buf)-2-(first-buf));
                if (nbytes == -1) {
                    perror("read");
                    goto close_fd_3;
                }
                for (ssize_t i=0; i<nbytes && *first != '\n'; ++i, ++first);
            }
            *first++ = '\n';
            *first = 0;
            write_buffer(system_out_fd, buf, first-buf, SYSTEM_HWMON);
            //printf("%lu|/sys/class/hwmon/%s/%s|%s\n", timestamp, name, name2, buf);
close_fd_3:
            if (fd3 != -1 && close(fd3) == -1) { perror("close"); }
close_fd_2:
            if (fd2 != -1 && close(fd2) == -1) { perror("close"); }
close_fd:
            if (close(fd) == -1) { perror("close"); }
        }
        if (closedir(hwmon_sub) == -1) {
            fprintf(stderr, "unable to close /sys/class/hwmon/%s directory", name);
            continue;
        }
    }
    if (closedir(hwmon) == -1) {
        perror("unable to close /sys/class/hwmon directory");
        return;
    }
}

static void
collect_thermal(time_t timestamp) {
    DIR* thermal = opendir("/sys/class/thermal");
    if (thermal == NULL) {
        perror("unable to open /sys/class/thermal directory");
        return;
    }
    int thermal_fd = dirfd(thermal);
    if (thermal_fd == -1) {
        perror("unable to open /sys/class/thermal directory");
        return;
    }
    for (struct dirent* entry = readdir(thermal);
         entry != NULL;
         entry = readdir(thermal)) {
        const char* name = entry->d_name;
        if (strncmp(name, "thermal_zone", 12) != 0) {
            continue;
        }
        int thermal_subdir_fd = openat(thermal_fd, name, O_RDONLY);
        if (thermal_subdir_fd == -1) {
            fprintf(stderr, "unable to open /sys/class/thermal/%s directory\n", name);
            continue;
        }
        int fd = openat(thermal_subdir_fd, "temp", O_RDONLY);
        if (fd == -1) {
            fprintf(stderr, "unable to open /sys/class/thermal/%s/temp file\n", name);
            continue;
        }
        char* first = buf;
        int nwritten = sprintf(first, "%lu|/sys/class/thermal/%s/temp|", timestamp, name);
        if (nwritten == -1) { goto close_fd; }
        first += nwritten;
        ssize_t nbytes = read(fd, first, sizeof(buf)-4-(first-buf));
        if (nbytes == -1) {
            fprintf(stderr, "unable to read from /sys/class/thermal/%s/temp file\n", name);
            goto close_fd;
        }
        for (ssize_t i=0; i<nbytes && *first != '\n'; ++i, ++first);
        *first++ = '|';
close_fd:
        if (close(fd) == -1) { perror("close"); }
        fd = openat(thermal_subdir_fd, "type", O_RDONLY);
        if (fd == -1) {
            fprintf(stderr, "unable to open /sys/class/thermal/%s/type file\n", name);
            continue;
        }
        nbytes = read(fd, first, sizeof(buf)-3-(first-buf));
        if (nbytes == -1) {
            fprintf(stderr, "unable to read from /sys/class/thermal/%s/type file\n", name);
            goto close_fd_2;
        }
        for (ssize_t i=0; i<nbytes && *first != '\n'; ++i, ++first);
close_fd_2:
        if (close(fd) == -1) { perror("close"); }
        *first++ = '\n';
        *first = 0;
        write_buffer(system_out_fd, buf, first-buf, SYSTEM_THERMAL);
    }
    if (closedir(thermal) == -1) {
        perror("unable to close /sys/class/thermal directory");
        return;
    }
}

static void
collect_drm(time_t timestamp) {
    const char* fields[] = {
        "mem_info_gtt_total",
        "mem_info_gtt_used",
        "mem_info_vis_vram_total",
        "mem_info_vis_vram_used",
        "mem_info_vram_total",
        "mem_info_vram_used",
    };
    char path[4096];
    DIR* drm = opendir("/sys/class/drm");
    if (drm == NULL) {
        perror("unable to open /sys/class/drm directory");
        return;
    }
    for (struct dirent* entry = readdir(drm); entry != NULL; entry = readdir(drm)) {
        const char* name = entry->d_name;
        if (strncmp(name, "card", 4) != 0) { continue; }
        for (int i=0; i<sizeof(fields)/sizeof(const char*); ++i) {
            const char* name2 = fields[i];
            snprintf(path, sizeof(path), "/sys/class/drm/%s/device/%s", name, name2);
            int fd = open(path, O_RDONLY);
            if (fd == -1) {
                //fprintf(stderr, "unable to open /sys/class/drm/%s/device/%s file\n",
                //        name, name2);
                continue;
            }
            char* first = buf;
            int nwritten =
                sprintf(first, "%lu|/sys/class/drm/%s/device/%s|", timestamp, name, name2);
            if (nwritten == -1) { goto close_fd; }
            first += nwritten;
            ssize_t nbytes = read(fd, first, sizeof(buf)-4-(first-buf));
            if (nbytes == -1) {
                fprintf(stderr, "unable to read from /sys/class/drm/%s/device/%s file\n",
                        name, name2);
                goto close_fd;
            }
            for (ssize_t i=0; i<nbytes && *first != '\n'; ++i, ++first);
            *first++ = '\n';
            *first = 0;
            write_buffer(system_out_fd, buf, first-buf, SYSTEM_DRM);
close_fd:
            if (close(fd) == -1) { perror("close"); }
        }
    }
    if (closedir(drm) == -1) {
        perror("unable to close /sys/class/drm directory");
        return;
    }
}

static void
help_message(const char* argv0) {
    printf("usage: %s [-c file] [-i interval] [-f field...] [-o file] [-F field...] [-O file] [-h] [--] [command]\n", argv0);
    fputs("  -c file      configuration file\n", stdout);
    fputs("  -i interval  interval in microseconds\n", stdout);
    fputs("  -f field...  process fields\n", stdout);
    fputs("  -o file      write process statistics to file\n", stdout);
    fputs("  -F field...  system fields\n", stdout);
    fputs("  -O file      write system statistics to file\n", stdout);
    fputs("  -h           help\n", stdout);
    fputs("\nprocess fields:\n", stdout);
    field_type* first = step_fields;
    field_type* last = step_fields + sizeof(step_fields) / sizeof(field_type);
    field_type* old_first = first;
    fputs("  ", stdout);
    while (first != last) {
        fputs(first->name, stdout);
        fputc(' ', stdout);
        if ((first-old_first)%4 == 0 && first-old_first >= 4) {
            fputs("\n  ", stdout);
        }
        ++first;
    }
    fputc('\n', stdout);
    fputs("\nsystem fields:\n", stdout);
    fputs("  hwmon thermal drm\n", stdout);
}

static void
parse_process_fields(char* fields_argument) {
    char* first = fields_argument;
    char* last = first + strlen(fields_argument);
    char* field_begin = first;
    num_process_fields = 0;
    *last = ',';
    while (first != last+1) {
        if (*first == ',') {
            *first = 0;
            field_type* result = find_field(field_begin);
            if (result == NULL) {
                fprintf(stderr, "bad field: %s\n", field_begin);
                exit(1);
            }
            process_fields[num_process_fields++] = result - step_fields;
            *first = ',';
            field_begin = first + 1;
        }
        ++first;
    }
    *last = 0;
}

static int
compare_chars(const char* first, const char* last, const char* str) {
    const size_t n1 = last-first;
    const size_t n2 = strlen(str);
    if (n1 != n2) { return -1; }
    return strncmp(first, str, n1);
}

static system_fields_type
parse_system_fields(const char* first, const char* last) {
    system_fields_type result = 0;
    const char* field_begin = first;
    while (first != last) {
        if (*first == ',') {
            const size_t n = first - field_begin;
            if (compare_chars(field_begin, first, "hwmon") == 0) {
                result |= SYSTEM_HWMON;
            } else if (compare_chars(field_begin, first, "drm") == 0) {
                result |= SYSTEM_DRM;
            } else if (compare_chars(field_begin, first, "thermal") == 0) {
                result |= SYSTEM_THERMAL;
            } else {
                fputs("bad field: ", stderr);
                fwrite(field_begin, 1, n, stderr);
                fputs("\n", stderr);
                exit(1);
            }
            field_begin = first + 1;
        }
        ++first;
    }
    return result;
}

static unsigned long
parse_unsigned_long(const char* first, const char* last) {
    unsigned long i = 0;
    unsigned long power = 1;
    while (first != last) {
        --last;
        if (*last < '0' || *last > '9') { perror("parse_unsigned_long"); }
        unsigned long addon = power * ((*last)-'0');
        if (ULONG_MAX - addon < i) { return ULONG_MAX; }
        i += addon;
        power *= 10;
    }
    return i;
}

static unsigned long
parse_duration(const char* first, const char* last) {
    const char* suffix_first = last;
    while (suffix_first != first && !isdigit(*(suffix_first-1))) {
        --suffix_first;
    }
    unsigned long interval = parse_unsigned_long(first, suffix_first);
    if (compare_chars(suffix_first, last, "m") == 0) { interval *= 60UL*100000UL; }
    else if (compare_chars(suffix_first, last, "s") == 0) { interval *= 1000000UL; }
    else if (compare_chars(suffix_first, last, "ms") == 0) { interval *= 1000UL; }
    else if (compare_chars(suffix_first, last, "us") == 0) {}
    else if (compare_chars(suffix_first, last, "ns") == 0) { interval /= 1000UL; }
    else { return ULONG_MAX; }
    if (interval <= 0) {
        fprintf(stderr, "bad interval %lu\n", interval);
        exit(1);
    }
    return interval;
}

static int
parse_syslog_facility(const char* first, const char* last) {
    int facility = LOG_USER;
    if (compare_chars(first, last, "auth") == 0) { facility = LOG_AUTH; }
    else if (compare_chars(first, last, "authpriv") == 0) { facility = LOG_AUTHPRIV; }
    else if (compare_chars(first, last, "cron") == 0) { facility = LOG_CRON; }
    else if (compare_chars(first, last, "daemon") == 0) { facility = LOG_DAEMON; }
    else if (compare_chars(first, last, "ftp") == 0) { facility = LOG_FTP; }
    else if (compare_chars(first, last, "kern") == 0) { facility = LOG_KERN; }
    else if (compare_chars(first, last, "local0") == 0) { facility = LOG_LOCAL0; }
    else if (compare_chars(first, last, "local1") == 0) { facility = LOG_LOCAL1; }
    else if (compare_chars(first, last, "local2") == 0) { facility = LOG_LOCAL2; }
    else if (compare_chars(first, last, "local3") == 0) { facility = LOG_LOCAL3; }
    else if (compare_chars(first, last, "local4") == 0) { facility = LOG_LOCAL4; }
    else if (compare_chars(first, last, "local5") == 0) { facility = LOG_LOCAL5; }
    else if (compare_chars(first, last, "local6") == 0) { facility = LOG_LOCAL6; }
    else if (compare_chars(first, last, "local7") == 0) { facility = LOG_LOCAL7; }
    else if (compare_chars(first, last, "lpr") == 0) { facility = LOG_LPR; }
    else if (compare_chars(first, last, "mail") == 0) { facility = LOG_MAIL; }
    else if (compare_chars(first, last, "news") == 0) { facility = LOG_NEWS; }
    else if (compare_chars(first, last, "syslog") == 0) { facility = LOG_SYSLOG; }
    else if (compare_chars(first, last, "user") == 0) { facility = LOG_USER; }
    else if (compare_chars(first, last, "uucp") == 0) { facility = LOG_UUCP; }
    return facility;
}

static int
parse_syslog_level(const char* first, const char* last) {
    int level = LOG_INFO;
    if (compare_chars(first, last, "emerg") == 0) { level = LOG_EMERG; }
    else if (compare_chars(first, last, "alert") == 0) { level = LOG_ALERT; }
    else if (compare_chars(first, last, "crit") == 0) { level = LOG_CRIT; }
    else if (compare_chars(first, last, "err") == 0) { level = LOG_ERR; }
    else if (compare_chars(first, last, "warning") == 0) { level = LOG_WARNING; }
    else if (compare_chars(first, last, "notice") == 0) { level = LOG_NOTICE; }
    else if (compare_chars(first, last, "info") == 0) { level = LOG_INFO; }
    else if (compare_chars(first, last, "debug") == 0) { level = LOG_DEBUG; }
    return level;
}

static void
read_configuration_line(const char* first, const char* last,
                        const char* path, int line_number) {
    // skip comments
    const char* middle = first;
    while (middle != last && *middle != '#') { ++middle; }
    last = middle;
    // trim whitespace
    while (first != last && isspace(*first)) { ++first; }
    while (first != last && isspace(*(last-1))) { --last; }
    // skip empty lines
    if (first == last) { return; }
    // find separator
    middle = first;
    while (middle != last && *middle != '=') { ++middle; }
    if (middle == last) {
        fprintf(stderr, "%s:%d error: no separator", path, line_number);
    }
    const char* key_first = first;
    const char* key_last = middle;
    while (key_first != key_last && isspace(*(key_last-1))) { --key_last; }
    const char* value_first = middle+1;
    const char* value_last = last;
    while (value_first != value_last && isspace(*value_first)) { ++value_first; }
    const size_t key_size = key_last-key_first;
    // parse keys and values
    if (compare_chars(key_first, key_last, "syslog.system.fields") == 0) {
        syslog_system_fields = parse_system_fields(value_first, value_last);
    } else if (compare_chars(key_first, key_last, "syslog.interval") == 0) {
        syslog_interval = parse_duration(value_first, value_last);
        if (syslog_interval == 0 || syslog_interval == ULONG_MAX) {
            fprintf(stderr, "%s:%d error: bad interval", path, line_number);
            exit(1);
        }
    } else if (compare_chars(key_first, key_last, "syslog.facility") == 0) {
        syslog_facility = parse_syslog_facility(value_first, value_last);
    } else if (compare_chars(key_first, key_last, "syslog.level") == 0) {
        syslog_level = parse_syslog_level(value_first, value_last);
    } else if (compare_chars(key_first, key_last, "interval") == 0) {
        interval = parse_duration(value_first, value_last);
        if (interval == 0 || interval == ULONG_MAX) {
            fprintf(stderr, "%s:%d error: bad interval", path, line_number);
            exit(1);
        }
    } else {
        fprintf(stderr, "%s:%d error: bad field ", path, line_number);
        fwrite(key_first, 1, key_size, stderr);
        fputs("\n", stderr);
        exit(1);
    }
}

static void read_configuration(const char* path) {
    int fd = open(path, O_RDONLY|O_CLOEXEC);
    if (fd == -1) {
        fprintf(stderr, "failed to open %s for reading\n", path);
        exit(1);
    }
    struct stat status = {0};
    if (stat(path, &status) == -1) {
        fprintf(stderr, "failed to get %s file status\n", path);
        exit(1);
    }
    const char* buffer = (const char*)mmap(0, status.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (buffer == 0) { perror("mmap"); }
    const char* line_start = buffer;
    int line_number = 1;
    for (size_t i=0; i<status.st_size; ++i) {
        char ch = buffer[i];
        if (ch == '\n') {
            read_configuration_line(line_start, buffer+i, path, line_number);
            line_start = buffer + i + 1;
            ++line_number;
        }
    }
    if (close(fd) == -1) { perror("close"); }
    if (munmap((void*)buffer, status.st_size) == -1) { perror("munmap"); }
}

static void
parse_options(int argc, char* argv[]) {
    int opt = 0;
    int help = 0;
    while ((opt = getopt(argc, argv, "c:i:f:o:F:O:h")) != -1) {
        if (opt == 'i') {
            unsigned long new_interval = atol(optarg);
            if (new_interval <= 0) {
                fprintf(stderr, "bad interval %lu\n", new_interval);
                exit(1);
            }
            interval = new_interval;
        }
        if (opt == 'f') {
            parse_process_fields(optarg);
        }
        if (opt == 'h') {
            help = 1;
        }
        if (opt == 'o') {
            process_out_fd = open(optarg, O_CREAT|O_APPEND|O_WRONLY, 0644);
            if (process_out_fd == -1) {
                fprintf(stderr, "failed to open %s for writing\n", optarg);
                exit(1);
            }
        }
        if (opt == 'F') {
            system_fields = parse_system_fields(optarg, optarg + strlen(optarg));
        }
        if (opt == 'O') {
            system_out_fd = open(optarg, O_CREAT|O_APPEND|O_WRONLY, 0644);
            if (system_out_fd == -1) {
                fprintf(stderr, "failed to open %s for writing\n", optarg);
                exit(1);
            }
        }
        if (opt == 'c') {
            read_configuration(optarg);
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
    if (optind != argc) { child_argv = argv+optind; }
    if (process_out_fd == -1) { process_out_fd = STDOUT_FILENO; }
    if (system_out_fd == -1) { system_out_fd = STDOUT_FILENO; }
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
    if (child_argv != 0) {
        child_pid = fork();
        if (child_pid == -1) { perror("fork"); exit(1); }
        if (child_pid == 0) {
            if (execvp(child_argv[0], child_argv) == -1) {
                fprintf(stderr, "failed to execute %s\n", child_argv[0]);
                exit(1);
            }
        }
    }
    int status = 0;
    int waited = 0;
    int main_ret = 0;
    const unsigned long syslog_interval_multiple = syslog_interval / interval;
    unsigned long syslog_interval_multiple_count = 0;
    while (running) {
        time_t timestamp = time(NULL);
        if (num_process_fields != 0) { collect_proc(timestamp); }
        if ((system_fields | syslog_system_fields) & SYSTEM_HWMON) { collect_hwmon(timestamp); }
        if ((system_fields | syslog_system_fields) & SYSTEM_DRM) { collect_drm(timestamp); }
        if ((system_fields | syslog_system_fields) & SYSTEM_THERMAL) { collect_thermal(timestamp); }
        if (child_pid != 0) {
            int ret = waitpid(child_pid, &status, WNOHANG);
            if (ret == -1) { perror("waitpid"); }
            if (ret == child_pid) {
                running = 0;
                waited = 1;
                if (WIFEXITED(status)) { main_ret = WEXITSTATUS(status); }
                else if (WIFSIGNALED(status)) { main_ret = WTERMSIG(status); }
            }
        }
        struct timespec t;
        t.tv_sec = interval / 1000000UL;
        t.tv_nsec = (interval % 1000000UL) * 1000UL;
        if (nanosleep(&t, 0) == -1 && errno != EINTR) { perror("nanosleep"); }
        ++syslog_interval_multiple_count;
        if (syslog_interval_multiple_count == syslog_interval_multiple) {
            enable_syslog = 1;
            syslog_interval_multiple_count = 0;
        } else {
            enable_syslog = 0;
        }
    }
    if (child_pid != 0 && !waited) {
        if (kill(child_pid, SIGTERM) == -1 && errno != ESRCH) { perror("kill"); }
        if (waitpid(child_pid, &status, 0) == -1) { perror("waitpid"); }
    }
    #if defined(LOCKSTEP_WITH_NVML)
nvml_shutdown:
    result = nvmlShutdown();
    if (result != NVML_SUCCESS) {
        fprintf(stderr, "failed to shutdowm NVML: %s\n", nvmlErrorString(result));
        return 1;
    }
    #endif
    if (process_out_fd > 2) {
        if (close(process_out_fd) == -1) { perror("close"); }
    }
    if (system_out_fd > 2) {
        if (close(system_out_fd) == -1) { perror("close"); }
    }
    return main_ret;
}
