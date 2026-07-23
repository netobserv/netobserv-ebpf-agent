/*
 * Helpers to read Go function arguments from pt_regs in uprobe handlers.
 * Follows the Go register ABI (https://go.dev/src/cmd/compile/abi-internal).
 */

#ifndef __GO_ARGUMENT_H__
#define __GO_ARGUMENT_H__

#include <bpf_tracing.h>

#if defined(__TARGET_ARCH_x86)
#define GO_PARAM1(x) ((void *)(long)((x)->ax))
#define GO_PARAM2(x) ((void *)(long)((x)->bx))
#define GO_PARAM3(x) ((void *)(long)((x)->cx))
#define GO_PARAM4(x) ((void *)(long)((x)->di))
#define GO_PARAM5(x) ((void *)(long)((x)->si))
#define GO_PARAM6(x) ((void *)(long)((x)->r8))
#define GO_PARAM7(x) ((void *)(long)((x)->r9))
#define GO_PARAM8(x) ((void *)(long)((x)->r10))
#define GO_SP(x) ((x)->sp)
#elif defined(__TARGET_ARCH_arm64)
#define GO_PARAM1(x) ((void *)(long)PT_REGS_PARM1(x))
#define GO_PARAM2(x) ((void *)(long)PT_REGS_PARM2(x))
#define GO_PARAM3(x) ((void *)(long)PT_REGS_PARM3(x))
#define GO_PARAM4(x) ((void *)(long)PT_REGS_PARM4(x))
#define GO_PARAM5(x) ((void *)(long)PT_REGS_PARM5(x))
#define GO_SP(x) PT_REGS_SP(x)
#elif defined(__TARGET_ARCH_s390)
/* Go s390x ABIInternal: integer args in R2–R9 (gprs[2]–gprs[9]). */
#define GO_PARAM1(x) ((void *)(long)PT_REGS_PARM1(x))
#define GO_PARAM2(x) ((void *)(long)PT_REGS_PARM2(x))
#define GO_PARAM3(x) ((void *)(long)PT_REGS_PARM3(x))
#define GO_PARAM4(x) ((void *)(long)PT_REGS_PARM4(x))
#define GO_PARAM5(x) ((void *)(long)PT_REGS_PARM5(x))
#define GO_SP(x) PT_REGS_SP(x)
#elif defined(__TARGET_ARCH_powerpc)
/* Go ppc64le ABIInternal: integer args in R3–R10 (gpr[3]–gpr[10]). */
#define GO_PARAM1(x) ((void *)(long)PT_REGS_PARM1(x))
#define GO_PARAM2(x) ((void *)(long)PT_REGS_PARM2(x))
#define GO_PARAM3(x) ((void *)(long)PT_REGS_PARM3(x))
#define GO_PARAM4(x) ((void *)(long)PT_REGS_PARM4(x))
#define GO_PARAM5(x) ((void *)(long)PT_REGS_PARM5(x))
#define GO_SP(x) ((x)->gpr[1])
#else
#define GO_PARAM1(x) ((void *)0)
#define GO_PARAM2(x) ((void *)0)
#define GO_PARAM3(x) ((void *)0)
#define GO_PARAM4(x) ((void *)0)
#define GO_PARAM5(x) ((void *)0)
#define GO_SP(x) 0
#endif

static __always_inline void *go_get_argument_by_reg(struct pt_regs *ctx, int index) {
    switch (index) {
    case 1:
        return GO_PARAM1(ctx);
    case 2:
        return GO_PARAM2(ctx);
    case 3:
        return GO_PARAM3(ctx);
    case 4:
        return GO_PARAM4(ctx);
    case 5:
        return GO_PARAM5(ctx);
#if defined(__TARGET_ARCH_x86)
    case 6:
        return GO_PARAM6(ctx);
    case 7:
        return GO_PARAM7(ctx);
    case 8:
        return GO_PARAM8(ctx);
#endif
    default:
        return NULL;
    }
}

static __always_inline void *go_get_argument_by_stack(struct pt_regs *ctx, int index) {
    void *ptr = 0;
    u64 sp = (u64)GO_SP(ctx) + (u64)(index * 8);
    if (bpf_probe_read_user(&ptr, sizeof(ptr), (void *)sp) != 0) {
        return NULL;
    }
    return ptr;
}

static __always_inline void *go_get_argument(struct pt_regs *ctx, bool is_register_abi, int index) {
    if (is_register_abi) {
        return go_get_argument_by_reg(ctx, index);
    }
    return go_get_argument_by_stack(ctx, index);
}

#endif /* __GO_ARGUMENT_H__ */
