#ifndef STEP_H
#define STEP_H

typedef struct {
	int process_id;
	char state;
	int parent_process_id;
	int process_group_id;
	int session_id;
	int tty_number;
	int tty_process_group_id;
	unsigned int flags;
	unsigned long int minor_faults;
	unsigned long int child_minor_faults;
	unsigned long int major_faults;
	unsigned long int child_major_faults;
	unsigned long int userspace_time;
	unsigned long int kernel_time;
	long int child_userspace_time;
	long int child_kernel_time;
	long int priority;
	long int nice;
	long int num_threads;
	long int unused;
	unsigned long long int start_time;
	unsigned long int virtual_memory_size;
	long int resident_set_size;
	unsigned long int resident_set_limit;
	unsigned long int code_segment_start;
	unsigned long int code_segment_end;
	unsigned long int stack_start;
	unsigned long int stack_pointer;
	unsigned long int instruction_pointer;
	unsigned long int signals;
	unsigned long int blocked_signals;
	unsigned long int ignored_signal;
	unsigned long int caught_signal;
	unsigned long int wait_channel;
	unsigned long int num_swapped_pages;
	unsigned long int children_num_swapped_pages;
	int exit_signal;
	int processor;
	unsigned int realtime_priority;
	unsigned int policy;
	unsigned long long int cumulative_block_input_output_delay;
	unsigned long int guest_time;
	long int child_guest_time;
	unsigned long int data_start;
	unsigned long int data_end;
	unsigned long int brk_start;
	unsigned long int arg_start;
	unsigned long int arg_end;
	unsigned long int env_start;
	unsigned long int env_end;
	int exit_code;
	uid_t user_id;
	gid_t group_id;
	double uptime;
	double idle_time;
	long ticks_per_second;
	time_t timestamp;
	char command[4096];
} step_t;


#endif // vim:filetype=c