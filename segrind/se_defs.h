//
// Created by derrick on 3/19/20.
//

#ifndef SE_VALGRIND_SE_DEFS_H
#define SE_VALGRIND_SE_DEFS_H

#if defined(VGA_x86)
#include "../VEX/priv/guest_x86_defs.h"
#define disInstr_X86 DISASM_TO_IR
#elif defined(VGA_amd64)
#include "../VEX/priv/guest_amd64_defs.h"
#define disInstr_AMD64 DISASM_TO_IR
#elif defined(VGA_ppc32)
#include "../VEX/priv/guest_ppc_defs.h"
#define disInstr_PPC DISASM_TO_IR
#elif defined(VGA_ppc64be) || defined(VGA_ppc64le)
#include "../VEX/priv/guest_ppc_defs.h"
#define disInstr_PPC DISASM_TO_IR
#elif defined(VGA_arm)
#include "../VEX/priv/guest_arm_defs.h"
#define disInstr_ARM DISASM_TO_IR
#elif defined(VGA_arm64)
#include "../VEX/priv/guest_arm64_defs.h"
#define disInstr_ARM64 DISASM_TO_IR
#elif defined(VGA_s390x)
#include "../VEX/priv/guest_s390_defs.h"
#define disInstr_S390 DISASM_TO_IR
#elif defined(VGA_mips32) || defined(VGA_mips64)
#include "../VEX/priv/guest_mips_defs.h"
#define disInstr_MIPS DISASM_TO_IR
#elif defined(VGA_nanomips)
#include "../VEX/priv/guest_nanomips_defs.h"
#define disInstr_nanoMIPS DISASM_TO_IR
#else
#error Unknown arch
#endif

#endif // SE_VALGRIND_SE_DEFS_H
