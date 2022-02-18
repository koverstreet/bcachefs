// SPDX-License-Identifier: GPL-2.0
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "test_util.h"

#include "kvm_util.h"
#include "processor.h"

#define VCPU_ID			1

static void guest_ins_port80(uint8_t *buffer, unsigned int count)
{
	unsigned long end;

	if (count == 2)
		end = (unsigned long)buffer + 1;
	else
		end = (unsigned long)buffer + 8192;

	asm volatile("cld; rep; insb" : "+D"(buffer), "+c"(count) : "d"(0x80) : "memory");
	GUEST_ASSERT_1(count == 0, count);
	GUEST_ASSERT_2((unsigned long)buffer == end, buffer, end);
}

static void guest_code(void)
{
	uint8_t buffer[8192];
	int i;

	/*
	 * Special case tests.  main() will adjust RCX 2 => 1 and 3 => 8192 to
	 * test that KVM doesn't explode when userspace modifies the "count" on
	 * a userspace I/O exit.  KVM isn't required to play nice with the I/O
	 * itself as KVM doesn't support manipulating the count, it just needs
	 * to not explode or overflow a buffer.
	 */
	guest_ins_port80(buffer, 2);
	guest_ins_port80(buffer, 3);

	/* Verify KVM fills the buffer correctly when not stuffing RCX. */
	memset(buffer, 0, sizeof(buffer));
	guest_ins_port80(buffer, 8192);
	for (i = 0; i < 8192; i++)
		GUEST_ASSERT_2(buffer[i] == 0xaa, i, buffer[i]);

	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	struct kvm_regs regs;
	struct kvm_run *run;
	struct kvm_vm *vm;
	struct ucall uc;
	int rc;

	/* Tell stdout not to buffer its content */
	setbuf(stdout, NULL);

	/* Create VM */
	vm = vm_create_default(VCPU_ID, 0, guest_code);
	run = vcpu_state(vm, VCPU_ID);

	memset(&regs, 0, sizeof(regs));

	while (1) {
		rc = _vcpu_run(vm, VCPU_ID);

		TEST_ASSERT(rc == 0, "vcpu_run failed: %d\n", rc);
		TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
			    "Unexpected exit reason: %u (%s),\n",
			    run->exit_reason,
			    exit_reason_str(run->exit_reason));

		if (get_ucall(vm, VCPU_ID, &uc))
			break;

		TEST_ASSERT(run->io.port == 0x80,
			    "Expected I/O at port 0x80, got port 0x%x\n", run->io.port);

		/*
		 * Modify the rep string count in RCX: 2 => 1 and 3 => 8192.
		 * Note, this abuses KVM's batching of rep string I/O to avoid
		 * getting stuck in an infinite loop.  That behavior isn't in
		 * scope from a testing perspective as it's not ABI in any way,
		 * i.e. it really is abusing internal KVM knowledge.
		 */
		vcpu_regs_get(vm, VCPU_ID, &regs);
		if (regs.rcx == 2)
			regs.rcx = 1;
		if (regs.rcx == 3)
			regs.rcx = 8192;
		memset((void *)run + run->io.data_offset, 0xaa, 4096);
		vcpu_regs_set(vm, VCPU_ID, &regs);
	}

	switch (uc.cmd) {
	case UCALL_DONE:
		break;
	case UCALL_ABORT:
		TEST_FAIL("%s at %s:%ld : argN+1 = 0x%lx, argN+2 = 0x%lx",
			  (const char *)uc.args[0], __FILE__, uc.args[1],
			  uc.args[2], uc.args[3]);
	default:
		TEST_FAIL("Unknown ucall %lu", uc.cmd);
	}

	kvm_vm_free(vm);
	return 0;
}
