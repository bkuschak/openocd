// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2011 by Broadcom Corporation                            *
 *   Evan Hunter - ehunter@broadcom.com                                    *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <helper/time_support.h>
#include <jtag/jtag.h>
#include "target/target.h"
#include "rtos.h"
#include "helper/log.h"
#include "helper/types.h"
#include "rtos_standard_stackings.h"

static const struct rtos_register_stacking *get_stacking_info(const struct rtos *rtos, int64_t stack_ptr);
static const struct rtos_register_stacking *get_stacking_info_arm926ejs(const struct rtos *rtos, int64_t stack_ptr);

static int is_thread_id_valid(const struct rtos *rtos, int64_t thread_id);
static int is_thread_id_valid_arm926ejs(const struct rtos *rtos, int64_t thread_id);

static bool threadx_detect_rtos(struct target *target);
static int threadx_create(struct target *target);
static int threadx_update_threads(struct rtos *rtos);
static int threadx_get_thread_reg_list(struct rtos *rtos, int64_t thread_id, struct rtos_reg **reg_list, int *num_regs);
static int threadx_get_symbol_list_to_lookup(struct symbol_table_elem *symbol_list[]);



struct threadx_thread_state {
	int value;
	const char *desc;
};

static const struct threadx_thread_state threadx_thread_states[] = {
	{ 0,  "Ready" },
	{ 1,  "Completed" },
	{ 2,  "Terminated" },
	{ 3,  "Suspended" },
	{ 4,  "Sleeping" },
	{ 5,  "Waiting - Queue" },
	{ 6,  "Waiting - Semaphore" },
	{ 7,  "Waiting - Event flag" },
	{ 8,  "Waiting - Memory" },
	{ 9,  "Waiting - Memory" },
	{ 10, "Waiting - I/O" },
	{ 11, "Waiting - Filesystem" },
	{ 12, "Waiting - Network" },
	{ 13, "Waiting - Mutex" },
};

#define THREADX_NUM_STATES ARRAY_SIZE(threadx_thread_states)

#define ARM926EJS_REGISTERS_SIZE_SOLICITED (11 * 4)
static const struct stack_register_offset rtos_threadx_arm926ejs_stack_offsets_solicited[] = {
	{ 0,  -1,   32 },		/* r0        */
	{ 1,  -1,   32 },		/* r1        */
	{ 2,  -1,   32 },		/* r2        */
	{ 3,  -1,   32 },		/* r3        */
	{ 4,  0x08, 32 },		/* r4        */
	{ 5,  0x0C, 32 },		/* r5        */
	{ 6,  0x10, 32 },		/* r6        */
	{ 7,  0x14, 32 },		/* r7        */
	{ 8,  0x18, 32 },		/* r8        */
	{ 9,  0x1C, 32 },		/* r9        */
	{ 10, 0x20, 32 },		/* r10       */
	{ 11, 0x24, 32 },		/* r11       */
	{ 12, -1,   32 },		/* r12       */
	{ 13, -2,   32 },		/* sp (r13)  */
	{ 14, 0x28, 32 },		/* lr (r14)  */
	{ 15, -1,   32 },		/* pc (r15)  */
	/*{ 16, -1,   32 },*/		/* lr (r14)  */
	/*{ 17, 0x28, 32 },*/		/* pc (r15)  */
	{ 16, 0x04, 32 },		/* xPSR      */
};
#define ARM926EJS_REGISTERS_SIZE_INTERRUPT (17 * 4)
static const struct stack_register_offset rtos_threadx_arm926ejs_stack_offsets_interrupt[] = {
	{ 0,  0x08, 32 },		/* r0        */
	{ 1,  0x0C, 32 },		/* r1        */
	{ 2,  0x10, 32 },		/* r2        */
	{ 3,  0x14, 32 },		/* r3        */
	{ 4,  0x18, 32 },		/* r4        */
	{ 5,  0x1C, 32 },		/* r5        */
	{ 6,  0x20, 32 },		/* r6        */
	{ 7,  0x24, 32 },		/* r7        */
	{ 8,  0x28, 32 },		/* r8        */
	{ 9,  0x2C, 32 },		/* r9        */
	{ 10, 0x30, 32 },		/* r10       */
	{ 11, 0x34, 32 },		/* r11       */
	{ 12, 0x38, 32 },		/* r12       */
	{ 13, -2,   32 },		/* sp (r13)  */
	{ 14, 0x3C, 32 },		/* lr (r14)  */
	{ 15, 0x40, 32 },		/* pc (r15)  */
	{ 16, 0x04, 32 },		/* xPSR      */
};

static const struct rtos_register_stacking rtos_threadx_arm926ejs_stacking[] = {
{
	.stack_registers_size = ARM926EJS_REGISTERS_SIZE_SOLICITED,
	.stack_growth_direction = -1,
	.num_output_registers = 17,
	.register_offsets = rtos_threadx_arm926ejs_stack_offsets_solicited
},
{
	.stack_registers_size = ARM926EJS_REGISTERS_SIZE_INTERRUPT,
	.stack_growth_direction = -1,
	.num_output_registers = 17,
	.register_offsets = rtos_threadx_arm926ejs_stack_offsets_interrupt
},
};

struct threadx_params {
	const char *target_name;
	unsigned char pointer_width;
	unsigned char thread_stack_offset;
	unsigned char thread_name_offset;
	unsigned char thread_state_offset;
	unsigned char thread_next_offset;
	const struct rtos_register_stacking *stacking_info;
	size_t stacking_info_nb;
	const struct rtos_register_stacking* (*fn_get_stacking_info)(const struct rtos *rtos, int64_t stack_ptr);
	int (*fn_is_thread_id_valid)(const struct rtos *rtos, int64_t thread_id);
};

static const struct threadx_params threadx_params_list[] = {
	{
	"cortex_m",				/* target_name */
	4,							/* pointer_width; */
	8,							/* thread_stack_offset; */
	40,							/* thread_name_offset; */
	48,							/* thread_state_offset; */
	136,						/* thread_next_offset */
	&rtos_standard_cortex_m3_stacking,	/* stacking_info */
	1,							/* stacking_info_nb */
	NULL,						/* fn_get_stacking_info */
	NULL,						/* fn_is_thread_id_valid */
	},
	{
	"cortex_r4",				/* target_name */
	4,							/* pointer_width; */
	8,							/* thread_stack_offset; */
	40,							/* thread_name_offset; */
	48,							/* thread_state_offset; */
	136,						/* thread_next_offset */
	&rtos_standard_cortex_r4_stacking,	/* stacking_info */
	1,							/* stacking_info_nb */
	NULL,						/* fn_get_stacking_info */
	NULL,						/* fn_is_thread_id_valid */
	},
	{
	"arm926ejs",				/* target_name */
	4,							/* pointer_width; */
	8,							/* thread_stack_offset; */
	40,							/* thread_name_offset; */
	48,							/* thread_state_offset; */
	136,						/* thread_next_offset */
	rtos_threadx_arm926ejs_stacking,	/* stacking_info */
	2,									/* stacking_info_nb */
	get_stacking_info_arm926ejs,		/* fn_get_stacking_info */
	is_thread_id_valid_arm926ejs,		/* fn_is_thread_id_valid */
	},
	{
	"hla_target",				/* target_name */
	4,							/* pointer_width; */
	8,							/* thread_stack_offset; */
	40,							/* thread_name_offset; */
	48,							/* thread_state_offset; */
	136,						/* thread_next_offset */
	&rtos_standard_cortex_m3_stacking,	/* stacking_info */
	1,							/* stacking_info_nb */
	NULL,						/* fn_get_stacking_info */
	NULL,						/* fn_is_thread_id_valid */
	},
};

enum threadx_symbol_values {
	THREADX_VAL_TX_THREAD_CURRENT_PTR = 0,
	THREADX_VAL_TX_THREAD_CREATED_PTR = 1,
	THREADX_VAL_TX_THREAD_CREATED_COUNT = 2,
};

static const char * const threadx_symbol_list[] = {
	"_tx_thread_current_ptr",
	"_tx_thread_created_ptr",
	"_tx_thread_created_count",
	NULL
};

const struct rtos_type threadx_rtos = {
	.name = "ThreadX",

	.detect_rtos = threadx_detect_rtos,
	.create = threadx_create,
	.update_threads = threadx_update_threads,
	.get_thread_reg_list = threadx_get_thread_reg_list,
	.get_symbol_list_to_lookup = threadx_get_symbol_list_to_lookup,
};

static const struct rtos_register_stacking *get_stacking_info(const struct rtos *rtos, int64_t stack_ptr)
{
	const struct threadx_params *param = (const struct threadx_params *) rtos->rtos_specific_params;

	if (param->fn_get_stacking_info)
		return param->fn_get_stacking_info(rtos, stack_ptr);

	return param->stacking_info + 0;
}

static int is_thread_id_valid(const struct rtos *rtos, int64_t thread_id)
{
	const struct threadx_params *param;

	if (!rtos->rtos_specific_params)
		return 0; /* invalid */

	param = (const struct threadx_params *) rtos->rtos_specific_params;

	if (param->fn_is_thread_id_valid)
		return param->fn_is_thread_id_valid(rtos, thread_id);

	return (thread_id != 0);
}

static const struct rtos_register_stacking *get_stacking_info_arm926ejs(const struct rtos *rtos, int64_t stack_ptr)
{
	const struct threadx_params *param = (const struct threadx_params *) rtos->rtos_specific_params;
	int	retval;
	uint32_t flag;

	retval = target_read_buffer(rtos->target,
			stack_ptr,
			sizeof(flag),
			(uint8_t *)&flag);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error reading stack data from ThreadX thread: stack_ptr=0x%" PRIx64, stack_ptr);
		return NULL;
	}

	if (flag == 0) {
		LOG_DEBUG("  solicited stack");
		return param->stacking_info + 0;
	} else {
		LOG_DEBUG("  interrupt stack: %" PRIu32, flag);
		return param->stacking_info + 1;
	}
}

static int is_thread_id_valid_arm926ejs(const struct rtos *rtos, int64_t thread_id)
{
	return (thread_id != 0 && thread_id != 1);
}

static int threadx_update_threads(struct rtos *rtos)
{
	int retval;
	int tasks_found = 0;
	int thread_list_size = 0;
	const struct threadx_params *param;

	if (!rtos)
		return -1;

	if (!rtos->rtos_specific_params)
		return -3;

	param = (const struct threadx_params *) rtos->rtos_specific_params;

	if (!rtos->symbols) {
		LOG_ERROR("No symbols for ThreadX");
		return -4;
	}

	if (rtos->symbols[THREADX_VAL_TX_THREAD_CREATED_COUNT].address == 0) {
		LOG_ERROR("Don't have the number of threads in ThreadX");
		return -2;
	}

	/* read the number of threads */
	retval = target_read_buffer(rtos->target,
			rtos->symbols[THREADX_VAL_TX_THREAD_CREATED_COUNT].address,
			4,
			(uint8_t *)&thread_list_size);

	if (retval != ERROR_OK) {
		LOG_ERROR("Could not read ThreadX thread count from target");
		return retval;
	}

	/* wipe out previous thread details if any */
	rtos_free_threadlist(rtos);

	/* read the current thread id */
	retval = target_read_buffer(rtos->target,
			rtos->symbols[THREADX_VAL_TX_THREAD_CURRENT_PTR].address,
			4,
			(uint8_t *)&rtos->current_thread);

	if (retval != ERROR_OK) {
		LOG_ERROR("Could not read ThreadX current thread from target");
		return retval;
	}

	if ((thread_list_size  == 0) || (rtos->current_thread == 0)) {
		/* Either : No RTOS threads - there is always at least the current execution though */
		/* OR     : No current thread - all threads suspended - show the current execution
		 * of idling */
		char tmp_str[] = "Current Execution";
		thread_list_size++;
		tasks_found++;
		rtos->thread_details = malloc(
				sizeof(struct thread_detail) * thread_list_size);
		rtos->thread_details->threadid = 1;
		rtos->thread_details->exists = true;
		rtos->thread_details->extra_info_str = NULL;
		rtos->thread_details->thread_name_str = malloc(sizeof(tmp_str));
		strcpy(rtos->thread_details->thread_name_str, tmp_str);

		/* If we just invented thread 1 to represent the current execution, we
		 * need to make sure the RTOS object also claims it's the current thread
		 * so that threadx_get_thread_reg_list() doesn't attempt to read a
		 * thread control block at 0x00000001. */
		rtos->current_thread = 1;

		if (thread_list_size == 0) {
			rtos->thread_count = 1;
			return ERROR_OK;
		}
	} else {
		/* create space for new thread details */
		rtos->thread_details = malloc(
				sizeof(struct thread_detail) * thread_list_size);
	}

	/* Read the pointer to the first thread */
	int64_t thread_ptr = 0;
	retval = target_read_buffer(rtos->target,
			rtos->symbols[THREADX_VAL_TX_THREAD_CREATED_PTR].address,
			param->pointer_width,
			(uint8_t *)&thread_ptr);
	if (retval != ERROR_OK) {
		LOG_ERROR("Could not read ThreadX thread location from target");
		return retval;
	}

	/* loop over all threads */
	int64_t prev_thread_ptr = 0;
	while ((thread_ptr != prev_thread_ptr) && (tasks_found < thread_list_size)) {

		#define THREADX_THREAD_NAME_STR_SIZE (200)
		char tmp_str[THREADX_THREAD_NAME_STR_SIZE];
		unsigned int i = 0;
		int64_t name_ptr = 0;

		/* Save the thread pointer */
		rtos->thread_details[tasks_found].threadid = thread_ptr;

		/* read the name pointer */
		retval = target_read_buffer(rtos->target,
				thread_ptr + param->thread_name_offset,
				param->pointer_width,
				(uint8_t *)&name_ptr);
		if (retval != ERROR_OK) {
			LOG_ERROR("Could not read ThreadX thread name pointer from target");
			return retval;
		}

		/* Read the thread name */
		tmp_str[0] = '\x00';

		/* Check if thread has a valid name */
		if (name_ptr != 0) {
			retval =
				target_read_buffer(rtos->target,
					name_ptr,
					THREADX_THREAD_NAME_STR_SIZE,
					(uint8_t *)&tmp_str);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error reading thread name from ThreadX target");
				return retval;
			}
			tmp_str[THREADX_THREAD_NAME_STR_SIZE - 1] = '\x00';
		}

		if (tmp_str[0] == '\x00')
			strcpy(tmp_str, "No Name");

		rtos->thread_details[tasks_found].thread_name_str =
			malloc(strlen(tmp_str)+1);
		strcpy(rtos->thread_details[tasks_found].thread_name_str, tmp_str);

		/* Read the thread status */
		int64_t thread_status = 0;
		retval = target_read_buffer(rtos->target,
				thread_ptr + param->thread_state_offset,
				4,
				(uint8_t *)&thread_status);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error reading thread state from ThreadX target");
			return retval;
		}

		for (i = 0; (i < THREADX_NUM_STATES) &&
				(threadx_thread_states[i].value != thread_status); i++) {
			/* empty */
		}

		const char *state_desc;
		if  (i < THREADX_NUM_STATES)
			state_desc = threadx_thread_states[i].desc;
		else
			state_desc = "Unknown state";

		rtos->thread_details[tasks_found].extra_info_str = malloc(strlen(
					state_desc)+8);
		sprintf(rtos->thread_details[tasks_found].extra_info_str, "State: %s", state_desc);

		rtos->thread_details[tasks_found].exists = true;

		tasks_found++;
		prev_thread_ptr = thread_ptr;

		/* Get the location of the next thread structure. */
		thread_ptr = 0;
		retval = target_read_buffer(rtos->target,
				prev_thread_ptr + param->thread_next_offset,
				param->pointer_width,
				(uint8_t *) &thread_ptr);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error reading next thread pointer in ThreadX thread list");
			return retval;
		}
	}

	rtos->thread_count = tasks_found;

	return 0;
}

static int threadx_get_thread_reg_list(struct rtos *rtos, int64_t thread_id,
		struct rtos_reg **reg_list, int *num_regs)
{
	int retval;
	const struct threadx_params *param;

	if (!rtos)
		return -1;

	if (!is_thread_id_valid(rtos, thread_id))
		return -2;

	if (!rtos->rtos_specific_params)
		return -3;

	param = (const struct threadx_params *) rtos->rtos_specific_params;

	/* Read the stack pointer */
	int64_t stack_ptr = 0;
	retval = target_read_buffer(rtos->target,
			thread_id + param->thread_stack_offset,
			param->pointer_width,
			(uint8_t *)&stack_ptr);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error reading stack frame from ThreadX thread");
		return retval;
	}

	LOG_INFO("thread: 0x%" PRIx64 ", stack_ptr=0x%" PRIx64, (uint64_t)thread_id, (uint64_t)stack_ptr);

	if (stack_ptr == 0) {
		LOG_ERROR("null stack pointer in thread");
		return -5;
	}

	const struct rtos_register_stacking *stacking_info =
			get_stacking_info(rtos, stack_ptr);

	if (!stacking_info) {
		LOG_ERROR("Unknown stacking info for thread id=0x%" PRIx64, (uint64_t)thread_id);
		return -6;
	}

	return rtos_generic_stack_read(rtos->target, stacking_info, stack_ptr, reg_list, num_regs);
}

static int threadx_get_symbol_list_to_lookup(struct symbol_table_elem *symbol_list[])
{
	unsigned int i;
	*symbol_list = calloc(
			ARRAY_SIZE(threadx_symbol_list), sizeof(struct symbol_table_elem));

	for (i = 0; i < ARRAY_SIZE(threadx_symbol_list); i++)
		(*symbol_list)[i].symbol_name = threadx_symbol_list[i];

	return 0;
}

static bool threadx_detect_rtos(struct target *target)
{
	if ((target->rtos->symbols) &&
			(target->rtos->symbols[THREADX_VAL_TX_THREAD_CREATED_PTR].address != 0)) {
		/* looks like ThreadX */
		return true;
	}
	return false;
}

#if 0

static int threadx_set_current_thread(struct rtos *rtos, threadid_t thread_id)
{
	return 0;
}

static int threadx_get_thread_detail(struct rtos *rtos,
	threadid_t thread_id,
	struct thread_detail *detail)
{
	unsigned int i = 0;
	int retval;

#define THREADX_THREAD_NAME_STR_SIZE (200)
	char tmp_str[THREADX_THREAD_NAME_STR_SIZE];

	const struct threadx_params *param;

	if (!rtos)
		return -1;

	if (thread_id == 0)
		return -2;

	if (!rtos->rtos_specific_params)
		return -3;

	param = (const struct threadx_params *) rtos->rtos_specific_params;

	if (!rtos->symbols) {
		LOG_ERROR("No symbols for ThreadX");
		return -3;
	}

	detail->threadid = thread_id;

	int64_t name_ptr = 0;
	/* read the name pointer */
	retval = target_read_buffer(rtos->target,
			thread_id + param->thread_name_offset,
			param->pointer_width,
			(uint8_t *)&name_ptr);
	if (retval != ERROR_OK) {
		LOG_ERROR("Could not read ThreadX thread name pointer from target");
		return retval;
	}

	/* Read the thread name */
	retval = target_read_buffer(rtos->target,
			name_ptr,
			THREADX_THREAD_NAME_STR_SIZE,
			(uint8_t *)&tmp_str);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error reading thread name from ThreadX target");
		return retval;
	}
	tmp_str[THREADX_THREAD_NAME_STR_SIZE-1] = '\x00';

	if (tmp_str[0] == '\x00')
		strcpy(tmp_str, "No Name");

	detail->thread_name_str = malloc(strlen(tmp_str)+1);

	/* Read the thread status */
	int64_t thread_status = 0;
	retval =
		target_read_buffer(rtos->target,
			thread_id + param->thread_state_offset,
			4,
			(uint8_t *)&thread_status);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error reading thread state from ThreadX target");
		return retval;
	}

	for (i = 0; (i < THREADX_NUM_STATES) &&
			(threadx_thread_states[i].value != thread_status); i++) {
		/* empty */
	}

	char *state_desc;
	if  (i < THREADX_NUM_STATES)
		state_desc = threadx_thread_states[i].desc;
	else
		state_desc = "Unknown state";

	detail->extra_info_str = malloc(strlen(state_desc)+1);

	detail->exists = true;

	return 0;
}

#endif

static int threadx_create(struct target *target)
{
	for (unsigned int i = 0; i < ARRAY_SIZE(threadx_params_list); i++)
		if (strcmp(threadx_params_list[i].target_name, target_type_name(target)) == 0) {
			target->rtos->rtos_specific_params = (void *)&threadx_params_list[i];
			target->rtos->current_thread = 0;
			target->rtos->thread_details = NULL;
			return ERROR_OK;
		}

	LOG_ERROR("Could not find target in ThreadX compatibility list");
	return ERROR_FAIL;
}
