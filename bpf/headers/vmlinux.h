#ifndef __VMLINUX_H_PARENT_
#define __VMLINUX_H_PARENT_

#if defined(__TARGET_ARCH_x86)

#include "vmlinux_amd64.h"

#elif defined(__TARGET_ARCH_arm64)

#include "vmlinux_arm64.h"

#elif defined(__TARGET_ARCH_powerpc)

#include "vmlinux_ppc64le.h"

#elif defined(__TARGET_ARCH_s390)

#include "vmlinux_s390.h"

#endif

#endif /*__VMLINUX_H_PARENT_*/
