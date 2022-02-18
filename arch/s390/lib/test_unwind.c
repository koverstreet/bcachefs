// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test module for unwind_for_each_frame
 */

#include <kunit/test.h>
#include <asm/unwind.h>
#include <linux/completion.h>
#include <linux/kallsyms.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/wait.h>
#include <asm/irq.h>

struct kunit *current_test;

#define BT_BUF_SIZE (PAGE_SIZE * 4)

/*
 * To avoid printk line limit split backtrace by lines
 */
static void print_backtrace(char *bt)
{
	char *p;

	while (true) {
		p = strsep(&bt, "\n");
		if (!p)
			break;
		kunit_err(current_test, "%s\n", p);
	}
}

/*
 * Calls unwind_for_each_frame(task, regs, sp) and verifies that the result
 * contains unwindme_func2 followed by unwindme_func1.
 */
static noinline int test_unwind(struct task_struct *task, struct pt_regs *regs,
				unsigned long sp)
{
	int frame_count, prev_is_func2, seen_func2_func1;
	const int max_frames = 128;
	struct unwind_state state;
	size_t bt_pos = 0;
	int ret = 0;
	char *bt;

	bt = kmalloc(BT_BUF_SIZE, GFP_ATOMIC);
	if (!bt) {
		kunit_err(current_test, "failed to allocate backtrace buffer\n");
		return -ENOMEM;
	}
	/* Unwind. */
	frame_count = 0;
	prev_is_func2 = 0;
	seen_func2_func1 = 0;
	unwind_for_each_frame(&state, task, regs, sp) {
		unsigned long addr = unwind_get_return_address(&state);
		char sym[KSYM_SYMBOL_LEN];

		if (frame_count++ == max_frames)
			break;
		if (state.reliable && !addr) {
			kunit_err(current_test, "unwind state reliable but addr is 0\n");
			ret = -EINVAL;
			break;
		}
		sprint_symbol(sym, addr);
		if (bt_pos < BT_BUF_SIZE) {
			bt_pos += snprintf(bt + bt_pos, BT_BUF_SIZE - bt_pos,
					   state.reliable ? " [%-7s%px] %pSR\n" :
							    "([%-7s%px] %pSR)\n",
					   stack_type_name(state.stack_info.type),
					   (void *)state.sp, (void *)state.ip);
			if (bt_pos >= BT_BUF_SIZE)
				kunit_err(current_test, "backtrace buffer is too small\n");
		}
		frame_count += 1;
		if (prev_is_func2 && str_has_prefix(sym, "unwindme_func1"))
			seen_func2_func1 = 1;
		prev_is_func2 = str_has_prefix(sym, "unwindme_func2");
	}

	/* Check the results. */
	if (unwind_error(&state)) {
		kunit_err(current_test, "unwind error\n");
		ret = -EINVAL;
	}
	if (!seen_func2_func1) {
		kunit_err(current_test, "unwindme_func2 and unwindme_func1 not found\n");
		ret = -EINVAL;
	}
	if (frame_count == max_frames) {
		kunit_err(current_test, "Maximum number of frames exceeded\n");
		ret = -EINVAL;
	}
	if (ret)
		print_backtrace(bt);
	kfree(bt);
	return ret;
}

/* State of the task being unwound. */
struct unwindme {
	int flags;
	int ret;
	struct task_struct *task;
	struct completion task_ready;
	wait_queue_head_t task_wq;
	unsigned long sp;
};

static struct unwindme *unwindme;

/* Values of unwindme.flags. */
#define UWM_DEFAULT		0x0
#define UWM_THREAD		0x1	/* Unwind a separate task. */
#define UWM_REGS		0x2	/* Pass regs to test_unwind(). */
#define UWM_SP			0x4	/* Pass sp to test_unwind(). */
#define UWM_CALLER		0x8	/* Unwind starting from caller. */
#define UWM_SWITCH_STACK	0x10	/* Use call_on_stack. */
#define UWM_IRQ			0x20	/* Unwind from irq context. */
#define UWM_PGM			0x40	/* Unwind from program check handler. */

static __always_inline unsigned long get_psw_addr(void)
{
	unsigned long psw_addr;

	asm volatile(
		"basr	%[psw_addr],0\n"
		: [psw_addr] "=d" (psw_addr));
	return psw_addr;
}

#ifdef CONFIG_KPROBES
static int pgm_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct unwindme *u = unwindme;

	u->ret = test_unwind(NULL, (u->flags & UWM_REGS) ? regs : NULL,
			     (u->flags & UWM_SP) ? u->sp : 0);
	return 0;
}
#endif

/* This function may or may not appear in the backtrace. */
static noinline int unwindme_func4(struct unwindme *u)
{
	if (!(u->flags & UWM_CALLER))
		u->sp = current_frame_address();
	if (u->flags & UWM_THREAD) {
		complete(&u->task_ready);
		wait_event(u->task_wq, kthread_should_park());
		kthread_parkme();
		return 0;
#ifdef CONFIG_KPROBES
	} else if (u->flags & UWM_PGM) {
		struct kprobe kp;
		int ret;

		unwindme = u;
		memset(&kp, 0, sizeof(kp));
		kp.symbol_name = "do_report_trap";
		kp.pre_handler = pgm_pre_handler;
		ret = register_kprobe(&kp);
		if (ret < 0) {
			kunit_err(current_test, "register_kprobe failed %d\n", ret);
			return -EINVAL;
		}

		/*
		 * Trigger operation exception; use insn notation to bypass
		 * llvm's integrated assembler sanity checks.
		 */
		asm volatile(
			"	.insn	e,0x0000\n"	/* illegal opcode */
			"0:	nopr	%%r7\n"
			EX_TABLE(0b, 0b)
			:);

		unregister_kprobe(&kp);
		unwindme = NULL;
		return u->ret;
#endif
	} else {
		struct pt_regs regs;

		memset(&regs, 0, sizeof(regs));
		regs.psw.addr = get_psw_addr();
		regs.gprs[15] = current_stack_pointer();
		return test_unwind(NULL,
				   (u->flags & UWM_REGS) ? &regs : NULL,
				   (u->flags & UWM_SP) ? u->sp : 0);
	}
}

/* This function may or may not appear in the backtrace. */
static noinline int unwindme_func3(struct unwindme *u)
{
	u->sp = current_frame_address();
	return unwindme_func4(u);
}

/* This function must appear in the backtrace. */
static noinline int unwindme_func2(struct unwindme *u)
{
	unsigned long flags;
	int rc;

	if (u->flags & UWM_SWITCH_STACK) {
		local_irq_save(flags);
		local_mcck_disable();
		rc = call_on_stack(1, S390_lowcore.nodat_stack,
				   int, unwindme_func3, struct unwindme *, u);
		local_mcck_enable();
		local_irq_restore(flags);
		return rc;
	} else {
		return unwindme_func3(u);
	}
}

/* This function must follow unwindme_func2 in the backtrace. */
static noinline int unwindme_func1(void *u)
{
	return unwindme_func2((struct unwindme *)u);
}

static void unwindme_timer_fn(struct timer_list *unused)
{
	struct unwindme *u = READ_ONCE(unwindme);

	if (u) {
		unwindme = NULL;
		u->task = NULL;
		u->ret = unwindme_func1(u);
		complete(&u->task_ready);
	}
}

static struct timer_list unwind_timer;

static int test_unwind_irq(struct unwindme *u)
{
	unwindme = u;
	init_completion(&u->task_ready);
	timer_setup(&unwind_timer, unwindme_timer_fn, 0);
	mod_timer(&unwind_timer, jiffies + 1);
	wait_for_completion(&u->task_ready);
	return u->ret;
}

/* Spawns a task and passes it to test_unwind(). */
static int test_unwind_task(struct kunit *test, struct unwindme *u)
{
	struct task_struct *task;
	int ret;

	/* Initialize thread-related fields. */
	init_completion(&u->task_ready);
	init_waitqueue_head(&u->task_wq);

	/*
	 * Start the task and wait until it reaches unwindme_func4() and sleeps
	 * in (task_ready, unwind_done] range.
	 */
	task = kthread_run(unwindme_func1, u, "%s", __func__);
	if (IS_ERR(task)) {
		kunit_err(test, "kthread_run() failed\n");
		return PTR_ERR(task);
	}
	/*
	 * Make sure task reaches unwindme_func4 before parking it,
	 * we might park it before kthread function has been executed otherwise
	 */
	wait_for_completion(&u->task_ready);
	kthread_park(task);
	/* Unwind. */
	ret = test_unwind(task, NULL, (u->flags & UWM_SP) ? u->sp : 0);
	kthread_stop(task);
	return ret;
}

struct test_params {
	int flags;
	char *name;
};

/*
 * Create required parameter list for tests
 */
static const struct test_params param_list[] = {
	{.flags = UWM_DEFAULT, .name = "UWM_DEFAULT"},
	{.flags = UWM_SP, .name = "UWM_SP"},
	{.flags = UWM_REGS, .name = "UWM_REGS"},
	{.flags = UWM_SWITCH_STACK,
		.name = "UWM_SWITCH_STACK"},
	{.flags = UWM_SP | UWM_REGS,
		.name = "UWM_SP | UWM_REGS"},
	{.flags = UWM_CALLER | UWM_SP,
		.name = "WM_CALLER | UWM_SP"},
	{.flags = UWM_CALLER | UWM_SP | UWM_REGS,
		.name = "UWM_CALLER | UWM_SP | UWM_REGS"},
	{.flags = UWM_CALLER | UWM_SP | UWM_REGS | UWM_SWITCH_STACK,
		.name = "UWM_CALLER | UWM_SP | UWM_REGS | UWM_SWITCH_STACK"},
	{.flags = UWM_THREAD, .name = "UWM_THREAD"},
	{.flags = UWM_THREAD | UWM_SP,
		.name = "UWM_THREAD | UWM_SP"},
	{.flags = UWM_THREAD | UWM_CALLER | UWM_SP,
		.name = "UWM_THREAD | UWM_CALLER | UWM_SP"},
	{.flags = UWM_IRQ, .name = "UWM_IRQ"},
	{.flags = UWM_IRQ | UWM_SWITCH_STACK,
		.name = "UWM_IRQ | UWM_SWITCH_STACK"},
	{.flags = UWM_IRQ | UWM_SP,
		.name = "UWM_IRQ | UWM_SP"},
	{.flags = UWM_IRQ | UWM_REGS,
		.name = "UWM_IRQ | UWM_REGS"},
	{.flags = UWM_IRQ | UWM_SP | UWM_REGS,
		.name = "UWM_IRQ | UWM_SP | UWM_REGS"},
	{.flags = UWM_IRQ | UWM_CALLER | UWM_SP,
		.name = "UWM_IRQ | UWM_CALLER | UWM_SP"},
	{.flags = UWM_IRQ | UWM_CALLER | UWM_SP | UWM_REGS,
		.name = "UWM_IRQ | UWM_CALLER | UWM_SP | UWM_REGS"},
	{.flags = UWM_IRQ | UWM_CALLER | UWM_SP | UWM_REGS | UWM_SWITCH_STACK,
		.name = "UWM_IRQ | UWM_CALLER | UWM_SP | UWM_REGS | UWM_SWITCH_STACK"},
	#ifdef CONFIG_KPROBES
	{.flags = UWM_PGM, .name = "UWM_PGM"},
	{.flags = UWM_PGM | UWM_SP,
		.name = "UWM_PGM | UWM_SP"},
	{.flags = UWM_PGM | UWM_REGS,
		.name = "UWM_PGM | UWM_REGS"},
	{.flags = UWM_PGM | UWM_SP | UWM_REGS,
		.name = "UWM_PGM | UWM_SP | UWM_REGS"},
	#endif
};

/*
 * Parameter description generator: required for KUNIT_ARRAY_PARAM()
 */
static void get_desc(const struct test_params *params, char *desc)
{
	strscpy(desc, params->name, KUNIT_PARAM_DESC_SIZE);
}

/*
 * Create test_unwind_gen_params
 */
KUNIT_ARRAY_PARAM(test_unwind, param_list, get_desc);

static void test_unwind_flags(struct kunit *test)
{
	struct unwindme u;
	const struct test_params *params;

	current_test = test;
	params = (const struct test_params *)test->param_value;
	u.flags = params->flags;
	if (u.flags & UWM_THREAD)
		KUNIT_EXPECT_EQ(test, 0, test_unwind_task(test, &u));
	else if (u.flags & UWM_IRQ)
		KUNIT_EXPECT_EQ(test, 0, test_unwind_irq(&u));
	else
		KUNIT_EXPECT_EQ(test, 0, unwindme_func1(&u));
}

static struct kunit_case unwind_test_cases[] = {
	KUNIT_CASE_PARAM(test_unwind_flags, test_unwind_gen_params),
	{}
};

static struct kunit_suite test_unwind_suite = {
	.name = "test_unwind",
	.test_cases = unwind_test_cases,
};

kunit_test_suites(&test_unwind_suite);

MODULE_LICENSE("GPL");
