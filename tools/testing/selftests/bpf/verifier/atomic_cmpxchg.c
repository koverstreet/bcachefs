{
	"atomic compare-and-exchange smoketest - 64bit",
	.insns = {
		/* val = 3; */
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 3),
		/* old = atomic_cmpxchg(&val, 2, 4); */
		BPF_MOV64_IMM(BPF_REG_1, 4),
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_ATOMIC_OP(BPF_DW, BPF_CMPXCHG, BPF_REG_10, BPF_REG_1, -8),
		/* if (old != 3) exit(2); */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 3, 2),
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_EXIT_INSN(),
		/* if (val != 3) exit(3); */
		BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, -8),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 3, 2),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_EXIT_INSN(),
		/* old = atomic_cmpxchg(&val, 3, 4); */
		BPF_MOV64_IMM(BPF_REG_1, 4),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_ATOMIC_OP(BPF_DW, BPF_CMPXCHG, BPF_REG_10, BPF_REG_1, -8),
		/* if (old != 3) exit(4); */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 3, 2),
		BPF_MOV64_IMM(BPF_REG_0, 4),
		BPF_EXIT_INSN(),
		/* if (val != 4) exit(5); */
		BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, -8),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 4, 2),
		BPF_MOV64_IMM(BPF_REG_0, 5),
		BPF_EXIT_INSN(),
		/* exit(0); */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"atomic compare-and-exchange smoketest - 32bit",
	.insns = {
		/* val = 3; */
		BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 3),
		/* old = atomic_cmpxchg(&val, 2, 4); */
		BPF_MOV32_IMM(BPF_REG_1, 4),
		BPF_MOV32_IMM(BPF_REG_0, 2),
		BPF_ATOMIC_OP(BPF_W, BPF_CMPXCHG, BPF_REG_10, BPF_REG_1, -4),
		/* if (old != 3) exit(2); */
		BPF_JMP32_IMM(BPF_JEQ, BPF_REG_0, 3, 2),
		BPF_MOV32_IMM(BPF_REG_0, 2),
		BPF_EXIT_INSN(),
		/* if (val != 3) exit(3); */
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_10, -4),
		BPF_JMP32_IMM(BPF_JEQ, BPF_REG_0, 3, 2),
		BPF_MOV32_IMM(BPF_REG_0, 3),
		BPF_EXIT_INSN(),
		/* old = atomic_cmpxchg(&val, 3, 4); */
		BPF_MOV32_IMM(BPF_REG_1, 4),
		BPF_MOV32_IMM(BPF_REG_0, 3),
		BPF_ATOMIC_OP(BPF_W, BPF_CMPXCHG, BPF_REG_10, BPF_REG_1, -4),
		/* if (old != 3) exit(4); */
		BPF_JMP32_IMM(BPF_JEQ, BPF_REG_0, 3, 2),
		BPF_MOV32_IMM(BPF_REG_0, 4),
		BPF_EXIT_INSN(),
		/* if (val != 4) exit(5); */
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_10, -4),
		BPF_JMP32_IMM(BPF_JEQ, BPF_REG_0, 4, 2),
		BPF_MOV32_IMM(BPF_REG_0, 5),
		BPF_EXIT_INSN(),
		/* exit(0); */
		BPF_MOV32_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"Can't use cmpxchg on uninit src reg",
	.insns = {
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 3),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_ATOMIC_OP(BPF_DW, BPF_CMPXCHG, BPF_REG_10, BPF_REG_2, -8),
		BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "!read_ok",
},
{
	"Can't use cmpxchg on uninit memory",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_MOV64_IMM(BPF_REG_2, 4),
		BPF_ATOMIC_OP(BPF_DW, BPF_CMPXCHG, BPF_REG_10, BPF_REG_2, -8),
		BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid read from stack",
},
{
	"BPF_W cmpxchg should zero top 32 bits",
	.insns = {
		/* r0 = U64_MAX; */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_ALU64_IMM(BPF_SUB, BPF_REG_0, 1),
		/* u64 val = r0; */
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
		/* r0 = (u32)atomic_cmpxchg((u32 *)&val, r0, 1); */
		BPF_MOV32_IMM(BPF_REG_1, 1),
		BPF_ATOMIC_OP(BPF_W, BPF_CMPXCHG, BPF_REG_10, BPF_REG_1, -8),
		/* r1 = 0x00000000FFFFFFFFull; */
		BPF_MOV64_IMM(BPF_REG_1, 1),
		BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),
		BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, 1),
		/* if (r0 != r1) exit(1); */
		BPF_JMP_REG(BPF_JEQ, BPF_REG_0, BPF_REG_1, 2),
		BPF_MOV32_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
		/* exit(0); */
		BPF_MOV32_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"Dest pointer in r0 - fail",
	.insns = {
		/* val = 0; */
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
		/* r0 = &val */
		BPF_MOV64_REG(BPF_REG_0, BPF_REG_10),
		/* r0 = atomic_cmpxchg(&val, r0, 1); */
		BPF_MOV64_IMM(BPF_REG_1, 1),
		BPF_ATOMIC_OP(BPF_DW, BPF_CMPXCHG, BPF_REG_10, BPF_REG_1, -8),
		/* if (r0 != 0) exit(1); */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
		/* exit(0); */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.result_unpriv = REJECT,
	.errstr_unpriv = "R0 leaks addr into mem",
},
{
	"Dest pointer in r0 - succeed",
	.insns = {
		/* r0 = &val */
		BPF_MOV64_REG(BPF_REG_0, BPF_REG_10),
		/* val = r0; */
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
		/* r0 = atomic_cmpxchg(&val, r0, 0); */
		BPF_MOV64_IMM(BPF_REG_1, 0),
		BPF_ATOMIC_OP(BPF_DW, BPF_CMPXCHG, BPF_REG_10, BPF_REG_1, -8),
		/* r1 = *r0 */
		BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, -8),
		/* exit(0); */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.result_unpriv = REJECT,
	.errstr_unpriv = "R0 leaks addr into mem",
},
{
	"Dest pointer in r0 - succeed, check 2",
	.insns = {
		/* r0 = &val */
		BPF_MOV64_REG(BPF_REG_0, BPF_REG_10),
		/* val = r0; */
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
		/* r5 = &val */
		BPF_MOV64_REG(BPF_REG_5, BPF_REG_10),
		/* r0 = atomic_cmpxchg(&val, r0, r5); */
		BPF_ATOMIC_OP(BPF_DW, BPF_CMPXCHG, BPF_REG_10, BPF_REG_5, -8),
		/* r1 = *r0 */
		BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, -8),
		/* exit(0); */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.result_unpriv = REJECT,
	.errstr_unpriv = "R0 leaks addr into mem",
},
{
	"Dest pointer in r0 - succeed, check 3",
	.insns = {
		/* r0 = &val */
		BPF_MOV64_REG(BPF_REG_0, BPF_REG_10),
		/* val = r0; */
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
		/* r5 = &val */
		BPF_MOV64_REG(BPF_REG_5, BPF_REG_10),
		/* r0 = atomic_cmpxchg(&val, r0, r5); */
		BPF_ATOMIC_OP(BPF_W, BPF_CMPXCHG, BPF_REG_10, BPF_REG_5, -8),
		/* exit(0); */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid size of register fill",
	.errstr_unpriv = "R0 leaks addr into mem",
},
{
	"Dest pointer in r0 - succeed, check 4",
	.insns = {
		/* r0 = &val */
		BPF_MOV32_REG(BPF_REG_0, BPF_REG_10),
		/* val = r0; */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -8),
		/* r5 = &val */
		BPF_MOV32_REG(BPF_REG_5, BPF_REG_10),
		/* r0 = atomic_cmpxchg(&val, r0, r5); */
		BPF_ATOMIC_OP(BPF_W, BPF_CMPXCHG, BPF_REG_10, BPF_REG_5, -8),
		/* r1 = *r10 */
		BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -8),
		/* exit(0); */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.result_unpriv = REJECT,
	.errstr_unpriv = "R10 partial copy of pointer",
},
{
	"Dest pointer in r0 - succeed, check 5",
	.insns = {
		/* r0 = &val */
		BPF_MOV32_REG(BPF_REG_0, BPF_REG_10),
		/* val = r0; */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -8),
		/* r5 = &val */
		BPF_MOV32_REG(BPF_REG_5, BPF_REG_10),
		/* r0 = atomic_cmpxchg(&val, r0, r5); */
		BPF_ATOMIC_OP(BPF_W, BPF_CMPXCHG, BPF_REG_10, BPF_REG_5, -8),
		/* r1 = *r0 */
		BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, -8),
		/* exit(0); */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "R0 invalid mem access",
	.errstr_unpriv = "R10 partial copy of pointer",
},
