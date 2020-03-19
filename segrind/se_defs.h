//
// Created by derrick on 3/19/20.
//

#ifndef SE_VALGRIND_SE_DEFS_H
#define SE_VALGRIND_SE_DEFS_H

#include "../VEX/priv/guest_generic_bb_to_IR.h"
#include "../coregrind/pub_core_machine.h"

#if defined(VGA_x86)
#include "../VEX/priv/guest_x86_defs.h"
#define DISASM_TO_IR disInstr_X86
#elif defined(VGA_amd64)
#include "../VEX/priv/guest_amd64_defs.h"
#define DISASM_TO_IR disInstr_AMD64
#elif defined(VGA_ppc32)
#include "../VEX/priv/guest_ppc_defs.h"
#define DISASM_TO_IR disInstr_PPC
#elif defined(VGA_ppc64be) || defined(VGA_ppc64le)
#include "../VEX/priv/guest_ppc_defs.h"
#define DISASM_TO_IR disInstr_PPC
#elif defined(VGA_arm)
#include "../VEX/priv/guest_arm_defs.h"
#define DISASM_TO_IR disInstr_ARM
#elif defined(VGA_arm64)
#include "../VEX/priv/guest_arm64_defs.h"
#define DISASM_TO_IR disInstr_ARM64
#elif defined(VGA_s390x)
#include "../VEX/priv/guest_s390_defs.h"
#define DISASM_TO_IR disInstr_S390
#elif defined(VGA_mips32) || defined(VGA_mips64)
#include "../VEX/priv/guest_mips_defs.h"
#define DISASM_TO_IR disInstr_MIPS
#elif defined(VGA_nanomips)
#include "../VEX/priv/guest_nanomips_defs.h"
#define DISASM_TO_IR disInstr_nanoMIPS
#else
#error Unknown arch
#endif

#endif // SE_VALGRIND_SE_DEFS_H
