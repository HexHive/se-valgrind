//
// Created by derrick on 3/24/20.
//

#include "se_taint.h"
#include <libvex_ir.h>

#include "libvex_ir.h"
#include "pub_tool_guest.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_mallocfree.h"

static XArray *program_states_;
static OSet *tainted_locations_;

static Int taint_count;
static SE_(taint_info) taint_info;

/**
 * @brief Adjusts the tainted location address based on the operation
 * @param irExpr
 * @param loc
 */
static void adjust_tainted_location(const IRExpr *irExpr,
                                    SE_(tainted_loc) * loc) {
  tl_assert(loc->type == taint_addr || loc->type == taint_stack);

  IROp op = Iop_INVALID;
  switch (irExpr->tag) {
  case Iex_Unop:
    op = irExpr->Iex.Unop.op;
    break;
  case Iex_Binop:
    op = irExpr->Iex.Binop.op;
    break;
  default:
    ppIRExpr(irExpr);
    tl_assert(0);
  }

  //  VG_(printf)
  //  ("\tAdjusting address %p (= 0x%llx) in response to IRExpr ",
  //   (void *)loc->location.addr, *(ULong *)loc->location.addr);
  //  ppIRExpr(irExpr);
  //  VG_(printf)("\n");

  switch (op) {
  case Iop_Add8:
    tl_assert(irExpr->Iex.Binop.arg2->tag == Iex_Const);
    loc->location.addr += (Int)irExpr->Iex.Binop.arg2->Iex.Const.con->Ico.U8;
    break;
  case Iop_Add16:
    tl_assert(irExpr->Iex.Binop.arg2->tag == Iex_Const);
    loc->location.addr += (Int)irExpr->Iex.Binop.arg2->Iex.Const.con->Ico.U16;
    break;
  case Iop_Add32:
    tl_assert(irExpr->Iex.Binop.arg2->tag == Iex_Const);
    loc->location.addr += (Int)irExpr->Iex.Binop.arg2->Iex.Const.con->Ico.U32;
    break;
  case Iop_Add64:
    tl_assert(irExpr->Iex.Binop.arg2->tag == Iex_Const);
    loc->location.addr += (Int)irExpr->Iex.Binop.arg2->Iex.Const.con->Ico.U64;
    break;
  case Iop_Sub8:
    tl_assert(irExpr->Iex.Binop.arg2->tag == Iex_Const);
    loc->location.addr -= (Int)irExpr->Iex.Binop.arg2->Iex.Const.con->Ico.U8;
    break;
  case Iop_Sub16:
    tl_assert(irExpr->Iex.Binop.arg2->tag == Iex_Const);
    loc->location.addr -= (Int)irExpr->Iex.Binop.arg2->Iex.Const.con->Ico.U16;
    break;
  case Iop_Sub32:
    tl_assert(irExpr->Iex.Binop.arg2->tag == Iex_Const);
    loc->location.addr -= (Int)irExpr->Iex.Binop.arg2->Iex.Const.con->Ico.U32;
    break;
  case Iop_Sub64:
    tl_assert(irExpr->Iex.Binop.arg2->tag == Iex_Const);
    loc->location.addr -= (Int)irExpr->Iex.Binop.arg2->Iex.Const.con->Ico.U64;
    break;
  default:
    break;
  }

  //  VG_(printf)("\taddr is now %p\n", (void *)loc->location.addr);
}

/**
 * @brief Creates a tainted_loc fit for inserting into tainted_locations_,
 * but must be freed using VG_(OSetGen_FreeNode) otherwise
 * @param irExpr
 * @param idx - index into program_states_
 * @param res - Can be null
 * @return
 */
static SE_(tainted_loc) *
    create_loc(IRExpr *irExpr, Word idx, SE_(tainted_loc) * res) {
  SE_(tainted_loc) *result = res;
  IRExpr *baseExpr;
  VexGuestArchState *guest_state;

  switch (irExpr->tag) {
  case Iex_RdTmp:
    if (!result) {
      result =
          VG_(OSetGen_AllocNode)(tainted_locations_, sizeof(SE_(tainted_loc)));
    }
    result->type = taint_temp;
    result->location.temp = irExpr->Iex.RdTmp.tmp;
    break;
  case Iex_Get:
    if (!result) {
      result =
          VG_(OSetGen_AllocNode)(tainted_locations_, sizeof(SE_(tainted_loc)));
    }
    if (irExpr->Iex.Get.offset == VG_O_FRAME_PTR) {
      guest_state = VG_(indexXA)(program_states_, idx);
      result->type = taint_stack;
      result->location.addr = guest_state->VG_FRAME_PTR;
      //      VG_(printf)("\tprogram_states_[%ld]->VG_FRAME_PTR = %p\n", idx,
      //      (void*)guest_state->VG_FRAME_PTR);
    } else if (irExpr->Iex.Get.offset == VG_O_STACK_PTR) {
      guest_state = VG_(indexXA)(program_states_, idx);
      result->type = taint_stack;
      result->location.addr = guest_state->VG_STACK_PTR;
    } else {
      result->type = taint_reg;
      result->location.offset = irExpr->Iex.Get.offset;
    }
    break;
  case Iex_Unop:
  case Iex_Binop:
    baseExpr = SE_(get_IRExpr)(irExpr);
    result = create_loc(baseExpr, idx, res);
    if (result->type == taint_addr || result->type == taint_stack) {
      adjust_tainted_location(irExpr, result);
    }
    break;
  case Iex_Load:
    baseExpr = SE_(get_IRExpr)(irExpr);
    result = create_loc(baseExpr, idx, res);
    break;
  case Iex_Const:
    if (!result) {
      result =
          VG_(OSetGen_AllocNode)(tainted_locations_, sizeof(SE_(tainted_loc)));
    }
    result->type = taint_addr;
    switch (irExpr->Iex.Const.con->tag) {
    case Ico_U32:
      result->location.addr = irExpr->Iex.Const.con->Ico.U32;
      break;
    case Ico_U64:
      result->location.addr = irExpr->Iex.Const.con->Ico.U64;
      break;
    default:
      result->type = taint_invalid;
      result->location.addr = -1;
      break;
    }
    break;
  case Iex_ITE:
  case Iex_CCall:
    if (!result) {
      result =
          VG_(OSetGen_AllocNode)(tainted_locations_, sizeof(SE_(tainted_loc)));
    }
    result->type = taint_invalid;
    result->location.offset = -1;
    break;
  default:
    VG_(printf)("Invalid IRExpr: ");
    ppIRExpr(irExpr);
    tl_assert(0);
  }

  return result;
}

void SE_(ppTaintedLocation)(const SE_(tainted_loc) * loc) {
  tl_assert(loc);

  switch (loc->type) {
  case taint_reg:
    VG_(printf)("{ reg offset: %d }\n", loc->location.offset);
    return;
  case taint_temp:
    VG_(printf)("{ temporary: %u }\n", loc->location.temp);
    return;
  case taint_addr:
    VG_(printf)
    ("{ address: %p }\n", (void *)loc->location.addr);
    return;
  case taint_stack:
    VG_(printf)("{ stack: %p }\n", (void *)loc->location.addr);
    return;
  case taint_invalid:
    VG_(printf)("{ invalid taint }\n");
    return;
  default:
    tl_assert2(0, "Unknown taint type: %d\n", loc->type);
  }
}

Word SE_(taint_cmp)(const void *key, const void *elem) {
  const SE_(tainted_loc) *key_loc = (const SE_(tainted_loc) *)key;
  const SE_(tainted_loc) *elem_loc = (const SE_(tainted_loc) *)elem;

  Word result = 0;
  if (key_loc->type == elem_loc->type) {
    switch (key_loc->type) {
    case taint_stack:
    case taint_addr:
      result = key_loc->location.addr - elem_loc->location.addr;
      break;
    case taint_reg:
      result = key_loc->location.offset - elem_loc->location.offset;
      break;
    case taint_temp:
      result = key_loc->location.temp - elem_loc->location.temp;
      break;
    default:
      tl_assert(0);
    }
  } else {
    result = key_loc->type - elem_loc->type;
  }

  if (result > 0) {
    return 1;
  } else if (result < 0) {
    return -1;
  } else {
    return 0;
  }
}

void SE_(init_taint_analysis)(XArray *program_states, Addr faulting_addr) {
  tl_assert(program_states);
  tl_assert(VG_(sizeXA)(program_states));

  program_states_ = program_states;
  tainted_locations_ = VG_(OSetGen_Create)(0, SE_(taint_cmp), VG_(malloc),
                                           SE_TOOL_ALLOC_STR, VG_(free));

  taint_info.faulting_address = faulting_addr;
  taint_info.taint_source.type = taint_invalid;
  taint_info.taint_source.location.addr = 0;

  taint_count = 0;
  //  VG_(umsg)("Taint analysis beginning!\n");
}

void SE_(end_taint_analysis)(void) {
  if (tainted_locations_) {
    VG_(OSetGen_Destroy)(tainted_locations_);
  }
  //  VG_(umsg)("Taint analysis complete\n");
}

IRExpr *SE_(get_IRExpr)(IRExpr *expr) {
  tl_assert(expr);
  IRExpr *result;

  switch (expr->tag) {
  case Iex_RdTmp:
  case Iex_Get:
  case Iex_Const:
  case Iex_CCall:
    result = expr;
    break;
  case Iex_Load:
    result = SE_(get_IRExpr)(expr->Iex.Load.addr);
    break;
  case Iex_Unop:
    result = SE_(get_IRExpr)(expr->Iex.Unop.arg);
    break;
  case Iex_Binop:
    result = SE_(get_IRExpr)(expr->Iex.Binop.arg1);
    if (result->tag != Iex_Const && result->tag != Iex_RdTmp &&
        result->tag != Iex_Get) {
      result = SE_(get_IRExpr)(expr->Iex.Binop.arg2);
    }
    break;
  case Iex_Triop:
    result = SE_(get_IRExpr)(expr->Iex.Triop.details->arg1);
    if (result->tag != Iex_Const && result->tag != Iex_RdTmp &&
        result->tag != Iex_Get) {
      result = SE_(get_IRExpr)(expr->Iex.Triop.details->arg2);
    }
    if (result->tag != Iex_Const && result->tag != Iex_RdTmp &&
        result->tag != Iex_Get) {
      result = SE_(get_IRExpr)(expr->Iex.Triop.details->arg3);
    }
    break;
  case Iex_Qop:
    result = SE_(get_IRExpr)(expr->Iex.Qop.details->arg1);
    if (result->tag != Iex_Const && result->tag != Iex_RdTmp &&
        result->tag != Iex_Get) {
      result = SE_(get_IRExpr)(expr->Iex.Qop.details->arg2);
    }
    if (result->tag != Iex_Const && result->tag != Iex_RdTmp &&
        result->tag != Iex_Get) {
      result = SE_(get_IRExpr)(expr->Iex.Qop.details->arg3);
    }
    if (result->tag != Iex_Const && result->tag != Iex_RdTmp &&
        result->tag != Iex_Get) {
      result = SE_(get_IRExpr)(expr->Iex.Qop.details->arg4);
    }
    break;
  default:
    VG_(umsg)("Invalid get_IRExpr expression: \n");
    ppIRExpr(expr);
    tl_assert(0);
  }

  return result;
}

void SE_(remove_IRExpr_taint)(IRExpr *irExpr, Word idx) {
  SE_(tainted_loc) loc;
  create_loc(irExpr, idx, &loc);

  void *tmp = VG_(OSetGen_Remove)(tainted_locations_, &loc);
  if (tmp) {
    //    VG_(printf)("\tRemoving taint from ");
    //    SE_(ppTaintedLocation)(&loc);
    VG_(OSetGen_FreeNode)(tainted_locations_, tmp);
  }
}

void SE_(taint_IRExpr)(IRExpr *irExpr, Word idx) {
  SE_(tainted_loc) *loc = create_loc(irExpr, idx, NULL);
  if (loc->type == taint_invalid) {
    //    VG_(printf)("\tInvalid loc created for ");
    //    ppIRExpr(irExpr);
    //    VG_(printf)("\n");
    VG_(OSetGen_FreeNode)(tainted_locations_, loc);
    return;
  }

  if (!VG_(OSetGen_Contains)(tainted_locations_, loc)) {
    if (loc->type == taint_addr || loc->type == taint_reg) {
      taint_count++;
    }
    //    VG_(printf)("\tTainting ");
    //    SE_(ppTaintedLocation)(loc);
    //    if (loc->type == taint_reg) {
    //      UChar *tmp =
    //          VG_(indexXA)(program_states_, VG_(sizeXA)(program_states_) - 1);
    //      UChar *curr = VG_(indexXA)(program_states_, idx);
    //      VG_(printf)
    //      ("\tAt end, Reg %d = 0x%lx\n\tcurrent val = 0x%0lx\n",
    //       loc->location.offset, *(Addr *)(tmp + loc->location.offset),
    //       *(Addr *)(curr + loc->location.offset));
    //      VG_(printf)
    //      ("\tAt end, Reg %d = 0x%lx\n\tcurrent val = 0x%0lx\n", 24,
    //       *(Addr *)(tmp + 24), *(Addr *)(curr + 24));
    //    }

    /* The first tainted location is the faulting instruction,
     * the second tainted location is the load of the invalid address.
     */
    if (taint_count == 2 && taint_info.taint_source.type == taint_invalid &&
        (loc->type == taint_addr || loc->type == taint_reg)) {
      taint_info.taint_source.type = taint_addr;
      switch (loc->type) {
      case taint_addr:
        taint_info.taint_source.location.addr = loc->location.addr;
        break;
      case taint_reg:
        taint_info.taint_source.location.addr =
            *(Addr *)((UChar *)VG_(indexXA)(program_states_, idx) +
                      loc->location.offset);
        break;
      default:
        tl_assert(0);
      }
      if (SE_(get_IRExpr)(irExpr)->tag != Iex_Const) {
        switch (irExpr->tag) {
        case Iex_Unop:
        case Iex_Binop:
          adjust_tainted_location(irExpr, &taint_info.taint_source);
          break;
        default:
          break;
        }
      }
      //      VG_(printf)
      //      ("\ttainted_address.addr = %p\n",
      //       (void *)taint_info.taint_source.location.addr);
    }

    VG_(OSetGen_Insert)(tainted_locations_, loc);
  }

  return;
}

Bool SE_(is_IRExpr_tainted)(IRExpr *irExpr, Word idx) {
  SE_(tainted_loc) loc;

  create_loc(irExpr, idx, &loc);
  return VG_(OSetGen_Contains)(tainted_locations_, &loc);
}

OSet *SE_(get_tainted_locations)() {
  tl_assert(tainted_locations_);

  VG_(OSetGen_ResetIter)(tainted_locations_);
  return tainted_locations_;
}

Bool SE_(taint_found)() {
  tl_assert(tainted_locations_);
  return VG_(OSetGen_Size)(tainted_locations_) > 0;
}

Bool SE_(guest_reg_tainted)(Int offset) {
  SE_(tainted_loc) loc;
  loc.type = taint_reg;
  loc.location.offset = offset;

  return VG_(OSetGen_Contains)(tainted_locations_, &loc);
}

void SE_(remove_tainted_reg)(Int offset) {
  SE_(tainted_loc) loc;
  loc.type = taint_reg;
  loc.location.offset = offset;

  //  VG_(printf)("\tRemoving taint from guest offset %d\n", offset);

  void *tmp = VG_(OSetGen_Remove)(tainted_locations_, &loc);
  if (tmp) {
    VG_(OSetGen_FreeNode)(tainted_locations_, tmp);
  }
}

Bool SE_(temp_tainted)(IRTemp temp) {
  SE_(tainted_loc) loc;
  loc.type = taint_temp;
  loc.location.temp = temp;

  return VG_(OSetGen_Contains)(tainted_locations_, &loc);
}

void SE_(taint_temp)(IRTemp temp) {
  SE_(tainted_loc) *loc =
      VG_(OSetGen_AllocNode)(tainted_locations_, sizeof(SE_(tainted_loc)));
  loc->type = taint_temp;
  loc->location.temp = temp;

  if (!VG_(OSetGen_Contains)(tainted_locations_, loc)) {
    //    VG_(printf)("\tTainting ");
    //    SE_(ppTaintedLocation)(loc);
    VG_(OSetGen_Insert)(tainted_locations_, loc);
  } else {
    VG_(OSetGen_FreeNode)(tainted_locations_, loc);
  }
}

void SE_(remove_tainted_temp)(IRTemp temp) {
  SE_(tainted_loc) loc;
  loc.type = taint_temp;
  loc.location.offset = temp;

  //  VG_(printf)("\tRemoving taint from temporary %u\n", temp);

  void *tmp = VG_(OSetGen_Remove)(tainted_locations_, &loc);
  if (tmp) {
    VG_(OSetGen_FreeNode)(tainted_locations_, tmp);
  }
}

void SE_(clear_temps)(void) {
  OSet *tmp = SE_(get_tainted_locations)();
  SE_(tainted_loc) * loc;
  while ((loc = VG_(OSetGen_Next)(tmp))) {
    if (loc->type == taint_temp) {
      VG_(OSetGen_Remove)(tmp, loc);
      VG_(OSetGen_FreeNode)(tmp, loc);
      VG_(OSetGen_ResetIter)(tmp);
    }
  }
}

Bool SE_(IRExpr_contains_load)(const IRExpr *irExpr) {
  tl_assert(irExpr);
  Bool result;

  switch (irExpr->tag) {
  case Iex_RdTmp:
  case Iex_Get:
  case Iex_Const:
    result = False;
    break;
  case Iex_Load:
    result = True;
    break;
  case Iex_Unop:
    result = SE_(IRExpr_contains_load)(irExpr->Iex.Unop.arg);
    break;
  case Iex_Binop:
    result = SE_(IRExpr_contains_load)(irExpr->Iex.Binop.arg1) ||
             SE_(IRExpr_contains_load)(irExpr->Iex.Binop.arg2);
    break;
  case Iex_Triop:
    result = SE_(IRExpr_contains_load)(irExpr->Iex.Triop.details->arg1) ||
             SE_(IRExpr_contains_load)(irExpr->Iex.Triop.details->arg2) ||
             SE_(IRExpr_contains_load)(irExpr->Iex.Triop.details->arg3);
    break;
  case Iex_Qop:
    result = SE_(IRExpr_contains_load)(irExpr->Iex.Qop.details->arg1) ||
             SE_(IRExpr_contains_load)(irExpr->Iex.Qop.details->arg2) ||
             SE_(IRExpr_contains_load)(irExpr->Iex.Qop.details->arg3) ||
             SE_(IRExpr_contains_load)(irExpr->Iex.Qop.details->arg4);
    break;
  case Iex_ITE:
    result = SE_(IRExpr_contains_load)(irExpr->Iex.ITE.cond) ||
             SE_(IRExpr_contains_load)(irExpr->Iex.ITE.iffalse) ||
             SE_(IRExpr_contains_load)(irExpr->Iex.ITE.iftrue);
    break;
  case Iex_CCall:
    result = False;
    Int i = 0;
    IRExpr *arg = irExpr->Iex.CCall.args[i];
    while (arg && !result) {
      result = SE_(IRExpr_contains_load)(arg);
      arg = irExpr->Iex.CCall.args[++i];
    }
    break;
  default:
    VG_(umsg)("Invalid IRExpr_contains_load expression: \n");
    ppIRExpr(irExpr);
    tl_assert(0);
  }

  return result;
}

const SE_(taint_info) * SE_(get_taint_info)() { return &taint_info; }