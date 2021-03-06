/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * KVM/LS_VZ: Support for LS3A2000/LS3A3000 hardware virtualization extensions
 *
 * Copyright (C) 2017 Loongson Corp.
 * Authors: Huang Pei <huangpei@loongon.cn>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/cacheops.h>
#include <asm/cmpxchg.h>
#include <asm/fpu.h>
#include <asm/hazards.h>
#include <asm/inst.h>
#include <asm/mmu_context.h>
#include <asm/r4kcache.h>
#include <asm/time.h>
#include <asm/tlb.h>
#include <asm/tlbex.h>

#include <linux/kvm_host.h>

#include "interrupt.h"

#include "trace.h"


/* Pointers to last VCPU loaded on each physical CPU */
static struct kvm_vcpu *last_vcpu[NR_CPUS];
/* Pointers to last VCPU executed on each physical CPU */
static struct kvm_vcpu *last_exec_vcpu[NR_CPUS];

/*
 * Number of guest VTLB entries to use, so we can catch inconsistency between
 * CPUs.
 */
/*static unsigned int kvm_vz_guest_vtlb_size;*/

static inline long kvm_vz_read_gc0_ebase(void)
{
	if (sizeof(long) == 8 && cpu_has_ebase_wg)
		return read_gc0_ebase_64();
	else
		return read_gc0_ebase();
}

static inline void kvm_vz_write_gc0_ebase(long v)
{
	/*
	 * First write with WG=1 to write upper bits, then write again in case
	 * WG should be left at 0.
	 * write_gc0_ebase_64() is no longer UNDEFINED since R6.
	 */
        /*
         * loongson VZ on 3a2000/3a3000 is not compatible with MIPS R5/R6
         */
	if (sizeof(long) == 8) {
		write_gc0_ebase_64(MIPS_EBASE_WG);
		write_gc0_ebase_64(v);
	} else {
		write_gc0_ebase(MIPS_EBASE_WG);
		write_gc0_ebase(v);
	}
}

/*
 * These Config bits may be writable by the guest:
 * Config:	[K23, KU] (!TLB), K0
 * Config1:	(none)
 * Config2:	[TU, SU] (impl)
 * Config3:	ISAOnExc
 * Config4:	FTLBPageSize
 * Config5:	K, CV, MSAEn, UFE, FRE, SBRI, UFR
 */

static inline unsigned int kvm_vz_config_guest_wrmask(struct kvm_vcpu *vcpu)
{
	return CONF_CM_CMASK;
}

static inline unsigned int kvm_vz_config1_guest_wrmask(struct kvm_vcpu *vcpu)
{
	return MIPS_CONF1_TLBS;
}

static inline unsigned int kvm_vz_config4_guest_wrmask(struct kvm_vcpu *vcpu)
{
	/* no need to be exact */
	return MIPS_CONF4_VFTLBPAGESIZE;
}

static inline unsigned int kvm_vz_config5_guest_wrmask(struct kvm_vcpu *vcpu)
{
	unsigned int mask = MIPS_CONF5_K | MIPS_CONF5_CV | MIPS_CONF5_SBRI;

	/*
	 * Permit guest FPU mode changes if FPU is enabled and the relevant
	 * feature exists according to FIR register.
	 */
	if (kvm_mips_guest_has_fpu(&vcpu->arch)) {
		if (cpu_has_fre)
			mask |= MIPS_CONF5_FRE | MIPS_CONF5_UFE;
	}

	return mask;
}

/*
 * VZ optionally allows these additional Config bits to be written by root:
 * Config:	M, [MT]
 * Config1:	M, [MMUSize-1, C2, MD, PC, WR, CA], FP
 * Config2:	M
 * Config3:	M, MSAP, [BPG], ULRI, [DSP2P, DSPP], CTXTC, [ITL, LPA, VEIC,
 *		VInt, SP, CDMM, MT, SM, TL]
 * Config4:	M, [VTLBSizeExt, MMUSizeExt]
 * Config5:	MRP
 */

static inline unsigned int kvm_vz_config_user_wrmask(struct kvm_vcpu *vcpu)
{
	return kvm_vz_config_guest_wrmask(vcpu) | MIPS_CONF_M;
}

static inline unsigned int kvm_vz_config1_user_wrmask(struct kvm_vcpu *vcpu)
{
	unsigned int mask = kvm_vz_config1_guest_wrmask(vcpu) | MIPS_CONF_M;

	/* Permit FPU to be present if FPU is supported */
	if (kvm_mips_guest_can_have_fpu(&vcpu->arch))
		mask |= MIPS_CONF1_FP;

	return mask;
}

static inline unsigned int kvm_vz_config2_user_wrmask(struct kvm_vcpu *vcpu)
{
	return 0;
}

static inline unsigned int kvm_vz_config3_user_wrmask(struct kvm_vcpu *vcpu)
{
	return 0;
}

static inline unsigned int kvm_vz_config4_user_wrmask(struct kvm_vcpu *vcpu)
{
	return kvm_vz_config4_guest_wrmask(vcpu) | MIPS_CONF_M;
}

static inline unsigned int kvm_vz_config5_user_wrmask(struct kvm_vcpu *vcpu)
{
	return kvm_vz_config5_guest_wrmask(vcpu) | MIPS_CONF5_MRP;
}


static inline void save_regs_with_field_change_exception(struct kvm_vcpu *vcpu)
{
	vcpu->arch.old_cp0_status = vcpu->arch.cop0->reg[MIPS_CP0_STATUS][0];
	vcpu->arch.old_cp0_intctl = vcpu->arch.cop0->reg[MIPS_CP0_STATUS][1];
	vcpu->arch.old_cp0_cause = vcpu->arch.cop0->reg[MIPS_CP0_CAUSE][0];
	vcpu->arch.old_cp0_entryhi = vcpu->arch.cop0->reg[MIPS_CP0_TLB_HI][0];
}

static int kvm_trap_vz_handle_cop_unusable(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	u32 cause = vcpu->arch.host_cp0_cause;
	enum emulation_result er = EMULATE_FAIL;
	int ret = RESUME_GUEST;

	if (((cause & CAUSEF_CE) >> CAUSEB_CE) == 1) {
		/*
		 * If guest FPU not present, the FPU operation should have been
		 * treated as a reserved instruction!
		 * If FPU already in use, we shouldn't get this at all.
		 */
#if 1
		if (WARN_ON(!kvm_mips_guest_has_fpu(&vcpu->arch) ||
			    vcpu->arch.aux_inuse & KVM_MIPS_AUX_FPU)) {
			preempt_enable();
			return EMULATE_FAIL;
		}

		kvm_own_fpu(vcpu);
#else
		preempt_disable();
		write_c0_status(read_c0_status() | ST0_CU1 | ST0_FR);
		preempt_enable();
#endif
		er = EMULATE_DONE;
	}
	/* other coprocessors not handled */

	switch (er) {
	case EMULATE_DONE:
		ret = RESUME_GUEST;
		break;

	case EMULATE_FAIL:
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
		break;

	default:
		BUG();
	}
	return ret;
}

static int kvm_trap_vz_handle_tlb_ld_miss(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	u32 *opc = (u32 *) vcpu->arch.pc;
	u32 cause = vcpu->arch.host_cp0_cause;
	ulong badvaddr = vcpu->arch.host_cp0_badvaddr;
	union mips_instruction inst;
	enum emulation_result er = EMULATE_DONE;
	int err, ret = RESUME_GUEST;

	if (kvm_mips_handle_vz_root_tlb_fault(badvaddr, vcpu, false)) {
		/* A code fetch fault doesn't count as an MMIO */
		if (kvm_is_ifetch_fault(&vcpu->arch)) {
			run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
			return RESUME_HOST;
		}

		/* Fetch the instruction */
		if (cause & CAUSEF_BD)
			opc += 1;
		err = kvm_get_badinstr(opc, vcpu, &inst.word);
		if (err) {
			run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
			return RESUME_HOST;
		}

		/* Treat as MMIO */
		er = kvm_mips_emulate_load(inst, cause, run, vcpu);
		if (er == EMULATE_FAIL) {
			kvm_err("Guest Emulate Load from MMIO space failed: PC: %p, BadVaddr: %#lx\n",
				opc, badvaddr);
			run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		}
	}

	if (er == EMULATE_DONE) {
		ret = RESUME_GUEST;
	} else if (er == EMULATE_DO_MMIO) {
		run->exit_reason = KVM_EXIT_MMIO;
		ret = RESUME_HOST;
	} else {
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
	}

	return ret;
}

static int kvm_trap_vz_handle_tlb_st_miss(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	u32 *opc = (u32 *) vcpu->arch.pc;
	u32 cause = vcpu->arch.host_cp0_cause;
	ulong badvaddr = vcpu->arch.host_cp0_badvaddr;
	union mips_instruction inst;
	enum emulation_result er = EMULATE_DONE;
	int err, ret = RESUME_GUEST;

	if (kvm_mips_handle_vz_root_tlb_fault(badvaddr, vcpu, true)) {
		/* A code fetch fault doesn't count as an MMIO */
		if (kvm_is_ifetch_fault(&vcpu->arch)) {
			run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
			return RESUME_HOST;
		}

		/* Fetch the instruction */
		if (cause & CAUSEF_BD)
			opc += 1;
		err = kvm_get_badinstr(opc, vcpu, &inst.word);
		if (err) {
			run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
			return RESUME_HOST;
		}

		/* Treat as MMIO */
		er = kvm_mips_emulate_store(inst, cause, run, vcpu);
		if (er == EMULATE_FAIL) {
			kvm_err("Guest Emulate Store from MMIO space failed: PC: %p, BadVaddr: %#lx\n",
				opc, badvaddr);
			run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		}
	}

	if (er == EMULATE_DONE) {
		ret = RESUME_GUEST;
	} else if (er == EMULATE_DO_MMIO) {
		run->exit_reason = KVM_EXIT_MMIO;
		ret = RESUME_HOST;
	} else {
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
	}

	return ret;
}

static int kvm_trap_vz_no_handler(struct kvm_vcpu *vcpu)
{
	return 0;
}

static int kvm_trap_vz_handle_msa_disabled(struct kvm_vcpu *vcpu)

{
	return 0;
}

/* Write Guest TLB Entry @ Index */
#define tlbinvf_op 0x4
enum emulation_result kvm_mips_lsvz_tlbinvf(struct kvm_vcpu *vcpu)
{
	return EMULATE_DONE;
}

static enum emulation_result kvm_vz_gpsi_cop0(union mips_instruction inst,
					      u32 *opc, u32 cause,
					      struct kvm_run *run,
					      struct kvm_vcpu *vcpu)
{
	struct mips_coproc *cop0 = vcpu->arch.cop0;
	enum emulation_result er = EMULATE_DONE;
	u32 rt, rd, sel;
	unsigned long curr_pc;
	unsigned long val;

	/*
	 * Update PC and hold onto current PC in case there is
	 * an error and we want to rollback the PC
	 */
	curr_pc = vcpu->arch.pc;
	er = update_pc(vcpu, cause);
	if (er == EMULATE_FAIL)
		return er;

	if (inst.co_format.co) {
		switch (inst.co_format.func) {
		case wait_op:
			er = kvm_mips_emul_wait(vcpu);
			break;
		case tlbr_op:
			/*NEED TO BE FIXED!!!*/
//			er = kvm_mips_lsvz_tlbr(vcpu);
			break;
		case tlbwi_op:
			/*NEED TO BE FIXED!!!*/
//			er = kvm_mips_lsvz_tlbwi(vcpu);
			break;
		case tlbwr_op:
			/*NEED TO BE FIXED!!!*/
//			er = kvm_mips_lsvz_tlbwr(vcpu);
			break;
		case tlbp_op:
			/*NEED TO BE FIXED!!!*/
//			er = kvm_mips_lsvz_tlbp(vcpu);
			break;
		case tlbinvf_op:
			er = kvm_mips_lsvz_tlbinvf(vcpu);
			break;
		default:
			er = EMULATE_FAIL;
		}
	} else {
		rt = inst.c0r_format.rt;
		rd = inst.c0r_format.rd;
		sel = inst.c0r_format.sel;

//printk("$$$$ inst.word is 0x%x, rt is %d, rd is %d, sel is %d\n", inst.word, rt, rd, sel);
		switch (inst.c0r_format.rs) {
		case dmfc_op:
		case mfc_op:
#ifdef CONFIG_KVM_MIPS_DEBUG_COP0_COUNTERS
			cop0->stat[rd][sel]++;
#endif
			if (rd == MIPS_CP0_TLB_PGGRAIN &&
			    sel == 1) {			/* PageGrain */
				val = cop0->reg[rd][sel];
			} else if ((rd == MIPS_CP0_CONFIG) &&
			    (sel == 6)) {               /* GSConfig*/
				val = cop0->reg[rd][sel];
			} else if ((rd == MIPS_CP0_TLB_CONTEXT) &&
			    (sel == 0)) {               /* Context */
				val = cop0->reg[rd][sel];
			} else if ((rd == MIPS_CP0_TLB_XCONTEXT) &&
			    (sel == 0)) {               /* XContext */
				val = cop0->reg[rd][sel];
			} else if ((rd == MIPS_CP0_DIAG) &&
			    (sel == 0)) {               /* Diag */
				val = cop0->reg[rd][sel];

			} else if ((rd == MIPS_CP0_TLB_HI) &&
			    (sel == 0)) {               /* EntryHI */
				val = cop0->reg[rd][sel];

			} else if ((rd == MIPS_CP0_TLB_PG_MASK) &&
			    ((sel == 0) ||              /* Pagemask */
			     (sel == 5) ||              /* PWBase */
			     (sel == 6) ||              /* PWField */
			     (sel == 7))) {             /* PWSize */
				val = cop0->reg[rd][sel];

			} else if ((rd == MIPS_CP0_TLB_WIRED) &&
			    ((sel == 0) ||              /* Wired */
			     (sel == 6))) {             /* PWCtl */
				val = cop0->reg[rd][sel];

			} else if ((rd == MIPS_CP0_TLB_LO0) &&
			    (sel == 0)) {               /* Entrylo0*/
				val = cop0->reg[rd][sel];

			} else if ((rd == MIPS_CP0_TLB_LO1) &&
			    (sel == 0)) {               /* Entrylo1*/
				val = cop0->reg[rd][sel];

			} else if ((rd == MIPS_CP0_TLB_INDEX) &&
			    (sel == 0)) {               /* Index */
				val = cop0->reg[rd][sel];

			} else if ((rd == MIPS_CP0_DESAVE) &&
			    ((sel == 0) ||              /* Desave */
			    (sel == 2) ||               /* Kscracth1 */
			    (sel == 3) ||               /* Kscracth2 */
			    (sel == 4) ||               /* Kscracth3 */
			    (sel == 5) ||               /* Kscracth4 */
			    (sel == 6) ||               /* Kscracth5 */
			    (sel == 7))) {              /* Kscracth6 */
				val = cop0->reg[rd][sel];

			} else if ((rd == MIPS_CP0_COUNT) &&
			    (sel == 0)) {              /* Count */
				val = kvm_mips_read_count(vcpu);
			} else if ((rd == MIPS_CP0_COUNT) &&
			    (sel == 7)) {               /* PGD */
				val = cop0->reg[rd][sel];
			} else if ((rd == MIPS_CP0_COMPARE) &&
			    (sel == 0)) {               /* Compare */
				val = read_gc0_compare();
			} else if ((rd == MIPS_CP0_PRID &&
				    (sel == 0 ||	/* PRid */
				     sel == 2 ||	/* CDMMBase */
				     sel == 3)) ||	/* CMGCRBase */
				   (rd == MIPS_CP0_STATUS &&
				    (sel == 2 ||	/* SRSCtl */
				     sel == 3)) ||	/* SRSMap */
				   (rd == MIPS_CP0_CONFIG &&
				    (sel == 7)) ||	/* Config7 */
				   (rd == MIPS_CP0_ERRCTL &&
				    (sel == 0))) {	/* ErrCtl */
				val = cop0->reg[rd][sel];
			} else {
				val = 0;
				er = EMULATE_FAIL;
			}

			if (er != EMULATE_FAIL) {
				/* Sign extend */
				if (inst.c0r_format.rs == mfc_op)
					val = (int)val;
				vcpu->arch.gprs[rt] = val;
			}

			trace_kvm_hwr(vcpu, (inst.c0r_format.rs == mfc_op) ?
					KVM_TRACE_MFC0 : KVM_TRACE_DMFC0,
				      KVM_TRACE_COP0(rd, sel), val);
			break;

		case dmtc_op:
		case mtc_op:
#ifdef CONFIG_KVM_MIPS_DEBUG_COP0_COUNTERS
			cop0->stat[rd][sel]++;
#endif
			val = vcpu->arch.gprs[rt];
			trace_kvm_hwr(vcpu, (inst.c0r_format.rs == mtc_op) ?
					KVM_TRACE_MTC0 : KVM_TRACE_DMTC0,
				      KVM_TRACE_COP0(rd, sel), val);
			if (rd == MIPS_CP0_TLB_PGGRAIN &&
			    sel == 1) {			/* PageGrain */
				/* Sign extend */
				if (inst.c0r_format.rs == mtc_op)
					val = (int)val;
				cop0->reg[rd][sel] = val;
			} else if ((rd == MIPS_CP0_CONFIG) &&
			    (sel == 6)) {               /* GSConfig*/
				/* Sign extend */
				if (inst.c0r_format.rs == mtc_op)
					val = (int)val;
				cop0->reg[rd][sel] = val;
			} else if ((rd == MIPS_CP0_TLB_CONTEXT) &&
			    (sel == 0)) {               /* Context */
				cop0->reg[rd][sel] = val;
			} else if ((rd == MIPS_CP0_TLB_XCONTEXT) &&
			    (sel == 0)) {               /* XContext */
				cop0->reg[rd][sel] = val;

			} else if ((rd == MIPS_CP0_DIAG) &&
			    (sel == 0)) {               /* Diag */
				/* Sign extend */
				if (inst.c0r_format.rs == mtc_op)
					val = (int)val;
				cop0->reg[rd][sel] = val;

			} else if ((rd == MIPS_CP0_TLB_HI) &&
			    (sel == 0)) {               /* EntryHI*/
				/* Sign extend */
#define ENTRYHI_WRITE_MASK 0xC000FFFFFFFFFFFF
				if (inst.c0r_format.rs == mtc_op)
					val = (int)val;
				cop0->reg[rd][sel] = val & ENTRYHI_WRITE_MASK;

#define PAGEMASK_WRITE_MASK0 0x00000000FFFFF800
#define PAGEMASK_WRITE_MASK1 0x0000000000003000
#define PWFIELD_WRITE_MASK 0x0000003F3FFFFFFF
#define PWSIZE_WRITE_MASK 0x0000003F7FFFFFFF
			} else if ((rd == MIPS_CP0_TLB_PG_MASK)) {
				if (sel == 0)               /* Pagemask */
					cop0->reg[rd][sel] = (val & PAGEMASK_WRITE_MASK0)
							| PAGEMASK_WRITE_MASK1;
				else if (sel == 5)          /* PWBase */
					cop0->reg[rd][sel] = val;
				else if (sel == 6)          /* PWField */
					cop0->reg[rd][sel] = val & PWFIELD_WRITE_MASK;
				else if (sel == 7)          /* PWSize */
					cop0->reg[rd][sel] = val & PWSIZE_WRITE_MASK;
				else
					er = EMULATE_FAIL;

#define WIRED_WRITE_MASK 0x0000003F
#define PWCTL_WRITE_MASK 0x4000003F
			} else if (rd == MIPS_CP0_TLB_WIRED) {
				if (sel == 0)               /* Wired */
					cop0->reg[rd][sel] = val & WIRED_WRITE_MASK;
				else if (sel == 6)          /* PWCtl */
					cop0->reg[rd][sel] = val & PWCTL_WRITE_MASK;

#define ENTRYLO_WRITE_MASK 0xE00003FFFFFFFFFF
			} else if ((rd == MIPS_CP0_TLB_LO0) &&
			    (sel == 0)) {               /* Entrylo0*/
				cop0->reg[rd][sel] = val & ENTRYLO_WRITE_MASK;

			} else if ((rd == MIPS_CP0_TLB_LO1) &&
			    (sel == 0)) {               /* Entrylo1*/
				cop0->reg[rd][sel] = val & ENTRYLO_WRITE_MASK;

#define INDEX_WRITE_MASK 0x7FF
			} else if ((rd == MIPS_CP0_TLB_INDEX) &&
			    (sel == 0)) {               /* Index */
				cop0->reg[rd][sel] = (int)val & INDEX_WRITE_MASK;

			} else if ((rd == MIPS_CP0_COUNT) &&
			    (sel == 0)) {               /* Count */
#if 1
				kvm_vz_lose_htimer(vcpu);
				kvm_mips_write_count(vcpu, vcpu->arch.gprs[rt]);
#else
				cop0->reg[rd][sel] = val;
				vcpu->arch.write_count_disable = 1;
#endif
			} else if (rd == MIPS_CP0_COMPARE &&
				   sel == 0) {		/* Compare */
				kvm_mips_write_compare(vcpu,
						       vcpu->arch.gprs[rt],
						       true);
			} else if ((rd == MIPS_CP0_COUNT) &&
			    (sel == 7)) {               /* PGD */
				cop0->reg[rd][sel] = val;

			} else if ((rd == MIPS_CP0_DESAVE) &&
			    ((sel == 0) ||              /* Desave */
			    (sel == 2) ||               /* Kscracth1 */
			    (sel == 3) ||               /* Kscracth2 */
			    (sel == 4) ||               /* Kscracth3 */
			    (sel == 5) ||               /* Kscracth4 */
			    (sel == 6) ||               /* Kscracth5 */
			    (sel == 7))) {              /* Kscracth6 */
				if (inst.c0r_format.rs == mtc_op)
					val = (int)val;
				cop0->reg[rd][sel] = val;

			} else {
				er = EMULATE_FAIL;
			}
			break;
		case wrpgpr_op:
			er = EMULATE_FAIL;
			break;
//		case rdpgpr_op:
//			er = EMULATE_FAIL;
//			break;
		default:
			er = EMULATE_FAIL;
			break;
		}
	}
	/* Rollback PC only if emulation was unsuccessful */
	if (er == EMULATE_FAIL) {
		kvm_err("[%#lx]%s: unsupported cop0 instruction 0x%08x\n",
			curr_pc, __func__, inst.word);

		vcpu->arch.pc = curr_pc;
	}

	return er;
}

/*
 *  * Most cache ops are split into a 2 bit field identifying the cache, and a 3
 *   * bit field identifying the cache operation.
 *    */
#define CacheOp_Cache                   0x03
#define CacheOp_Op                      0x1c

#define Cache_I                         0x00
#define Cache_D                         0x01
#define Cache_T                         0x02
#define Cache_V                         0x02 /* Loongson-3 */
#define Cache_S                         0x03

#define Index_Writeback_Inv             0x00
#define Index_Load_Tag                  0x04
#define Index_Store_Tag                 0x08
#define Hit_Invalidate                  0x10
#define Hit_Writeback_Inv               0x14    /* not with Cache_I though */
#define Hit_Writeback                   0x18

static enum emulation_result kvm_vz_gpsi_cache(union mips_instruction inst,
					       u32 *opc, u32 cause,
					       struct kvm_run *run,
					       struct kvm_vcpu *vcpu)
{
	enum emulation_result er = EMULATE_DONE;
	u32 cache, op_inst, op, base;
	s16 offset;
	struct kvm_vcpu_arch *arch = &vcpu->arch;
	unsigned long va, curr_pc;

	/*
	 * Update PC and hold onto current PC in case there is
	 * an error and we want to rollback the PC
	 */

	curr_pc = vcpu->arch.pc;
	er = update_pc(vcpu, cause);
	if (er == EMULATE_FAIL)
		return er;

	base = inst.i_format.rs;
	op_inst = inst.i_format.rt;
	offset = inst.i_format.simmediate;
	cache = op_inst & CacheOp_Cache;
	op = op_inst & CacheOp_Op;

	va = arch->gprs[base] + offset;

	kvm_debug("CACHE (cache: %#x, op: %#x, base[%d]: %#lx, offset: %#x\n",
		  cache, op, base, arch->gprs[base], offset);

	/* Secondary or tirtiary cache ops ignored */
	if (cache != Cache_I && cache != Cache_D)
		return EMULATE_DONE;

	switch (op_inst) {
	case Index_Invalidate_I:
		flush_icache_line_indexed(va);
		return EMULATE_DONE;
	case Index_Writeback_Inv_D:
		flush_dcache_line_indexed(va);
		return EMULATE_DONE;
	case Hit_Invalidate_I:
	case Hit_Invalidate_D:
	case Hit_Writeback_Inv_D:
		if (boot_cpu_type() == CPU_LOONGSON3) {
			/* We can just flush entire icache */
//			local_flush_icache_range(0, 0);
			return EMULATE_DONE;
		}

		/* So far, other platforms support guest hit cache ops */
		break;
	default:
		break;
	};

	kvm_err("@ %#lx/%#lx CACHE (cache: %#x, op: %#x, base[%d]: %#lx, offset: %#x\n",
		curr_pc, vcpu->arch.gprs[31], cache, op, base, arch->gprs[base],
		offset);
	/* Rollback PC */
	vcpu->arch.pc = curr_pc;

	return EMULATE_FAIL;
}

static enum emulation_result kvm_trap_vz_handle_gpsi(u32 cause, u32 *opc,
						     struct kvm_vcpu *vcpu)
{
	enum emulation_result er = EMULATE_DONE;
	struct kvm_vcpu_arch *arch = &vcpu->arch;
	struct kvm_run *run = vcpu->run;
	union mips_instruction inst;
	int rd, rt, sel;
	int err;

	/*
	 *  Fetch the instruction.
	 */
	if (cause & CAUSEF_BD)
		opc += 1;

	err = kvm_get_badinstr(opc, vcpu, &inst.word);
//	printk("#### badinst is 0x%x\n", inst.word);
	if (err)
		return EMULATE_FAIL;

	switch (inst.r_format.opcode) {
	case cop0_op:
		er = kvm_vz_gpsi_cop0(inst, opc, cause, run, vcpu);
		break;
	case cache_op:
		trace_kvm_exit(vcpu, KVM_TRACE_EXIT_CACHE);
		er = kvm_vz_gpsi_cache(inst, opc, cause, run, vcpu);
		break;
	case spec3_op:
		switch (inst.spec3_format.func) {
		case rdhwr_op:
			if (inst.r_format.rs || (inst.r_format.re >> 3))
				goto unknown;

			rd = inst.r_format.rd;
			rt = inst.r_format.rt;
			sel = inst.r_format.re & 0x7;

			switch (rd) {
			case MIPS_HWR_CC:	/* Read count register */
				arch->gprs[rt] =
					(long)(int)kvm_mips_read_count(vcpu);
				break;
			default:
				trace_kvm_hwr(vcpu, KVM_TRACE_RDHWR,
					      KVM_TRACE_HWR(rd, sel), 0);
				goto unknown;
			};

			trace_kvm_hwr(vcpu, KVM_TRACE_RDHWR,
				      KVM_TRACE_HWR(rd, sel), arch->gprs[rt]);

			er = update_pc(vcpu, cause);
			break;
		default:
			goto unknown;
		};
		break;
unknown:
	default:
		kvm_err("GPSI exception not supported (%p/%#x)\n",
				opc, inst.word);
		kvm_arch_vcpu_dump_regs(vcpu);
		er = EMULATE_FAIL;
		break;
	}

	return er;
}

static enum emulation_result kvm_trap_vz_handle_gsfc(u32 cause, u32 *opc,
						     struct kvm_vcpu *vcpu)
{
	enum emulation_result er = EMULATE_DONE;
	struct kvm_vcpu_arch *arch = &vcpu->arch;
	union mips_instruction inst;
	int err;

	/*
	 *  Fetch the instruction.
	 */
	if (cause & CAUSEF_BD)
		opc += 1;
	err = kvm_get_badinstr(opc, vcpu, &inst.word);
	if (err)
		return EMULATE_FAIL;

	/* complete MTC0 on behalf of guest and advance EPC */
	if (inst.c0r_format.opcode == cop0_op &&
	    ((inst.c0r_format.rs == mtc_op) ||
	    (inst.c0r_format.rs == dmtc_op)) &&
	    inst.c0r_format.z == 0) {
		int rt = inst.c0r_format.rt;
		int rd = inst.c0r_format.rd;
		int sel = inst.c0r_format.sel;
		unsigned int val = arch->gprs[rt];
		unsigned int old_val, change;

		trace_kvm_hwr(vcpu, KVM_TRACE_MTC0, KVM_TRACE_COP0(rd, sel),
			      val);

		if ((rd == MIPS_CP0_STATUS) && (sel == 0)) {
			/* FR bit should read as zero if no FPU */
			if (!kvm_mips_guest_has_fpu(&vcpu->arch))
				val &= ~(ST0_CU1 | ST0_FR);

			/*
			 * Also don't allow FR to be set if host doesn't support
			 * it.
			 */
			if (!(boot_cpu_data.fpu_id & MIPS_FPIR_F64))
				val &= ~ST0_FR;

			old_val = arch->old_cp0_status;
			change = val ^ old_val;

			if (change & ST0_KX) {
				/*
				 * indicate access 64 bit kernel seg
				 * and use XTLB REFILL exception
				 */
					old_val ^= ST0_KX;
			}

			if (change & ST0_FR) {
				/*
				 * FPU and Vector register state is made
				 * UNPREDICTABLE by a change of FR, so don't
				 * even bother saving it.
				 */
				kvm_drop_fpu(vcpu);
			}

			//Update old value
			arch->old_cp0_status = old_val;
		} else if ((rd == MIPS_CP0_CAUSE) && (sel == 0)) {
			u32 old_cause = arch->old_cp0_cause;
			u32 change = old_cause ^ val;

			/* DC bit enabling/disabling timer? */
			if (change & CAUSEF_DC) {
				if (val & CAUSEF_DC) {
					kvm_vz_lose_htimer(vcpu);
					kvm_mips_count_disable_cause(vcpu);
				} else {
					kvm_mips_count_enable_cause(vcpu);
				}
			}

			/* Only certain bits are RW to the guest */
			change &= (CAUSEF_DC | CAUSEF_IV | CAUSEF_WP |
				   CAUSEF_IP0 | CAUSEF_IP1);

			/* WP can only be cleared */
			change &= ~CAUSEF_WP | old_cause;

			arch->old_cp0_cause = old_cause ^ change;
			write_gc0_cause(old_cause ^ change);
		} else if ((rd == MIPS_CP0_STATUS) && (sel == 1)) { /* IntCtl */
			arch->old_cp0_intctl = val;
		} else if ((rd == MIPS_CP0_TLB_HI) && (sel == 0)) {
			unsigned long old_val = arch->old_cp0_entryhi;
			unsigned long val = arch->gprs[rt];
			change = val ^ old_val;
			/* If change R VPN2 EHINV area
			   Still set ZERO to these area
			*/

		} else {
			kvm_err("Handle GSFC, unsupported field change @ %p: %#x\n",
			    opc, inst.word);
			er = EMULATE_FAIL;
		}

		if (er != EMULATE_FAIL)
			er = update_pc(vcpu, cause);
	} else {
		kvm_err("Handle GSFC, unrecognized instruction @ %p: %#x\n",
			opc, inst.word);
		er = EMULATE_FAIL;
	}

	return er;
}

static enum emulation_result kvm_trap_vz_handle_hc(u32 cause, u32 *opc,
						   struct kvm_vcpu *vcpu)
{
	enum emulation_result er;
	union mips_instruction inst;
	unsigned long curr_pc;
	int err;

	if (cause & CAUSEF_BD)
		opc += 1;
	err = kvm_get_badinstr(opc, vcpu, &inst.word);
	if (err)
		return EMULATE_FAIL;

	/*
	 * Update PC and hold onto current PC in case there is
	 * an error and we want to rollback the PC
	 */
	curr_pc = vcpu->arch.pc;
	er = update_pc(vcpu, cause);
	if (er == EMULATE_FAIL)
		return er;

	er = kvm_mips_emul_hypcall(vcpu, inst);
	if (er == EMULATE_FAIL)
		vcpu->arch.pc = curr_pc;

	return er;
}

static enum emulation_result kvm_trap_vz_no_handler_guest_exit(u32 gexccode,
							u32 cause,
							u32 *opc,
							struct kvm_vcpu *vcpu)
{
	u32 inst;

	/*
	 *  Fetch the instruction.
	 */
	if (cause & CAUSEF_BD)
		opc += 1;
	kvm_get_badinstr(opc, vcpu, &inst);

	kvm_err("Guest Exception Code: %d not yet handled @ PC: %p, inst: 0x%08x  Status: %#x\n",
		gexccode, opc, inst, read_gc0_status());

	return EMULATE_FAIL;
}

static int kvm_trap_vz_handle_guest_exit(struct kvm_vcpu *vcpu)
{
	u32 cause = vcpu->arch.host_cp0_cause;
	enum emulation_result er = EMULATE_DONE;
	u32 __user *opc = (u32 __user *) vcpu->arch.pc;
	u32 gexccode = (vcpu->arch.host_cp0_guestctl0 &
			MIPS_GCTL0_GEXC) >> MIPS_GCTL0_GEXC_SHIFT;
	int ret = RESUME_GUEST;
	vcpu->arch.is_hypcall = 0;
//	vcpu->arch.write_count_disable = 0;

#if 0
	u32 exccode = (cause >> CAUSEB_EXCCODE) & 0x1f;
	unsigned long badvaddr = vcpu->arch.host_cp0_badvaddr;

	printk("$$$$ %s:%s:%d\n", __FILE__,__func__,__LINE__);
	printk("$$$$ VZ Guest Exception: cause %#x, PC: %p, BadVaddr: %#lx\n",
			  cause, opc, badvaddr);
	printk("$$$$ excode %#x, gsexccode: %#x\n",
			  exccode, gexccode);
#endif

	trace_kvm_exit(vcpu, KVM_TRACE_EXIT_GEXCCODE_BASE + gexccode);
	switch (gexccode) {
	case MIPS_GCTL0_GEXC_GPSI:
		++vcpu->stat.vz_gpsi_exits;
		er = kvm_trap_vz_handle_gpsi(cause, opc, vcpu);
		break;
	case MIPS_GCTL0_GEXC_GSFC:
	/*only GFC in loongson, the same code as GSFC*/
		++vcpu->stat.vz_gsfc_exits;
		er = kvm_trap_vz_handle_gsfc(cause, opc, vcpu);
		break;
	case MIPS_GCTL0_GEXC_HC:
		vcpu->arch.is_hypcall = 1;
		++vcpu->stat.vz_hc_exits;
		er = kvm_trap_vz_handle_hc(cause, opc, vcpu);
		break;
	case MIPS_GCTL0_GEXC_GRR:
		++vcpu->stat.vz_grr_exits;
		er = kvm_trap_vz_no_handler_guest_exit(gexccode, cause, opc,
						       vcpu);
		break;
	default:
		++vcpu->stat.vz_resvd_exits;
		er = kvm_trap_vz_no_handler_guest_exit(gexccode, cause, opc,
						       vcpu);
		break;

	}

	if (er == EMULATE_DONE) {
		ret = RESUME_GUEST;
	} else if (er == EMULATE_HYPERCALL) {
		ret = kvm_mips_handle_hypcall(vcpu);
	} else {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
	}

	return ret;
}

static void kvm_vz_hardware_disable(void)
{
	switch (current_cpu_type()) {
	case CPU_LOONGSON3:
		/* Flush moved entries in new (root) context */
		local_flush_tlb_all();
		break;
	default:
		break;
	}
}

/*enable 每个cpu成虚拟模式 ~jeff */
static int kvm_vz_hardware_enable(void)
{
	/*
	 * Enable virtualization features granting guest direct control of
	 * certain features:
	 * CP0=1:	Guest coprocessor 0 context.
	 * AT=Guest:	Guest MMU.
	 * CG=1:	Hit (virtual address) CACHE operations (optional).
	 * CF=1:	Guest Config registers.
	 */
	 /*设置12,6寄存器(客户guest控制寄存器0)
	   *MIPS_GCTL0_CF如果设置为1，guest访问config-0-1是允许的
	   * MIPS_GCTL0_CP0如果设置为0，说明guest访问的所有敏感指令
	   * 都将触发异常 ~jeff
	   */
	write_c0_guestctl0(MIPS_GCTL0_CP0 | MIPS_GCTL0_CF);

	/* clear any pending injected virtual guest interrupts */
	if (cpu_has_guestctl2)
		clear_c0_guestctl2(0x3f << 10);
	//Set vpid.vpmask to fixed 0xff,so we can have 256 guest
	write_c0_diag(read_c0_diag() | (1<<16));
	write_c0_vpid(0xff<<8);

	return 0;
}

static int kvm_vz_check_extension(struct kvm *kvm, long ext)
{

	return 0;
}
/*对应 vcpu_init 只初始化架构对应的vpid为0 ~jeff */
static int kvm_vz_vcpu_init(struct kvm_vcpu *vcpu)
{
	int i;

	for_each_possible_cpu(i)
		vcpu->arch.vpid[i] = 0;

	return 0;
}

static void kvm_vz_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	int cpu;

	/*
	 * If the VCPU is freed and reused as another VCPU, we don't want the
	 * matching pointer wrongly hanging around in last_vcpu[] or
	 * last_exec_vcpu[].
	 */
	for_each_possible_cpu(cpu) {
		if (last_vcpu[cpu] == vcpu)
			last_vcpu[cpu] = NULL;
		if (last_exec_vcpu[cpu] == vcpu)
			last_exec_vcpu[cpu] = NULL;
	}
}

static int kvm_vz_vcpu_setup(struct kvm_vcpu *vcpu)
{
	struct mips_coproc *cop0 = vcpu->arch.cop0;

	unsigned long count_hz = 100*1000*1000; /* default to 100 MHz */

	cop0->reg[MIPS_CP0_TLB_PG_MASK][0] = 0xF000ULL;

	/*
	 * Start off the timer at the same frequency as the host timer, but the
	 * soft timer doesn't handle frequencies greater than 1GHz yet.
	 */
	if (mips_hpt_frequency && mips_hpt_frequency <= NSEC_PER_SEC)
		count_hz = mips_hpt_frequency;
	kvm_mips_init_count(vcpu, count_hz);

	/* architecturally writable (e.g. from guest) */
	kvm_change_sw_gc0_config(cop0, CONF_CM_CMASK,
				 _page_cachable_default >> _CACHE_SHIFT);

	/* EBase */
	kvm_write_sw_gc0_ebase(cop0, (s32)0x80100000 | vcpu->vcpu_id);

	/* start with no pending virtual guest interrupts */
	if (cpu_has_guestctl2)
		cop0->reg[MIPS_CP0_GUESTCTL2][MIPS_CP0_GUESTCTL2_SEL] = 0;

	return 0;
}

static void kvm_vz_flush_shadow_all(struct kvm *kvm)
{
        flush_tlb_all();
}

static void kvm_vz_flush_shadow_memslot(struct kvm *kvm,
					const struct kvm_memory_slot *slot)
{
	kvm_vz_flush_shadow_all(kvm);
}

static gpa_t kvm_vz_gva_to_gpa_cb(gva_t gva)
{
	/* VZ guest has already converted gva to gpa */
	if((gva & CKSEG3) == CKSEG1)
		return CPHYSADDR(gva);
	else {
		if((gva & 0xfffffffff0000000) == 0x9000000040000000 )
			gva &= 0x4fffffff;
		if((gva & XKSEG) == XKPHYS)
			gva = XPHYSADDR(gva);
		return gva;
	}
}

static void kvm_vz_queue_irq(struct kvm_vcpu *vcpu, unsigned int priority)
{
	set_bit(priority, &vcpu->arch.pending_exceptions);
	clear_bit(priority, &vcpu->arch.pending_exceptions_clr);
}

static void kvm_vz_dequeue_irq(struct kvm_vcpu *vcpu, unsigned int priority)
{
	clear_bit(priority, &vcpu->arch.pending_exceptions);
	set_bit(priority, &vcpu->arch.pending_exceptions_clr);
}

static void kvm_vz_queue_timer_int_cb(struct kvm_vcpu *vcpu)
{
	/*
	 * timer expiry is asynchronous to vcpu execution therefore defer guest
	 * cp0 accesses
	 */
	kvm_vz_queue_irq(vcpu, MIPS_EXC_INT_TIMER);
}

static void kvm_vz_dequeue_timer_int_cb(struct kvm_vcpu *vcpu)
{
	/*
	 * timer expiry is asynchronous to vcpu execution therefore defer guest
	 * cp0 accesses
	 */
	kvm_vz_dequeue_irq(vcpu, MIPS_EXC_INT_TIMER);
}

#define MIPS_EXC_INT_HT          11
#define MIPS_EXC_INT_IPI         14

static void kvm_vz_queue_io_int_cb(struct kvm_vcpu *vcpu,
				   struct kvm_mips_interrupt *irq)
{
	int intr = (int)irq->irq;

	/*
	 * interrupts are asynchronous to vcpu execution therefore defer guest
	 * cp0 accesses
	 */
	switch (intr) {
	case 2:
		kvm_vz_queue_irq(vcpu, MIPS_EXC_INT_IO);
		break;

	case 3:
		kvm_vz_queue_irq(vcpu, MIPS_EXC_INT_HT);
		break;

	case 6:
		kvm_vz_queue_irq(vcpu, MIPS_EXC_INT_IPI);
		break;

	default:
		break;
	}
}

static void kvm_vz_dequeue_io_int_cb(struct kvm_vcpu *vcpu,
				     struct kvm_mips_interrupt *irq)
{
	int intr = (int)irq->irq;

	/*
	 * interrupts are asynchronous to vcpu execution therefore defer guest
	 * cp0 accesses
	 */
	switch (intr) {
	case -2:
		kvm_vz_dequeue_irq(vcpu, MIPS_EXC_INT_IO);
		break;

	case -3:
		kvm_vz_dequeue_irq(vcpu, MIPS_EXC_INT_HT);
		break;

	case -6:
		kvm_vz_dequeue_irq(vcpu, MIPS_EXC_INT_IPI);
		break;

	default:
		break;
	}
}

static u32 kvm_vz_priority_to_irq[MIPS_EXC_MAX] = {
	[MIPS_EXC_INT_TIMER] = C_IRQ5,
	[MIPS_EXC_INT_IO]    = C_IRQ0,
	[MIPS_EXC_INT_HT]    = C_IRQ1,
	[MIPS_EXC_INT_IPI]   = C_IRQ4,
};

static int kvm_vz_irq_clear_cb(struct kvm_vcpu *vcpu, unsigned int priority,
			       u32 cause)
{
	u32 irq = (priority < MIPS_EXC_MAX) ?
		kvm_vz_priority_to_irq[priority] : 0;

	switch (priority) {
	case MIPS_EXC_INT_TIMER:
		/*
		 * Call to kvm_write_c0_guest_compare() clears Cause.TI in
		 * kvm_mips_emulate_CP0(). Explicitly clear irq associated with
		 * Cause.IP[IPTI] if GuestCtl2 virtual interrupt register not
		 * supported or if not using GuestCtl2 Hardware Clear.
		 */
		if (cpu_has_guestctl2) {
			if (!(read_c0_guestctl2() & (irq << 14)))
				;
		} else {
			kvm_err("No any other way to clear guest interrupt\n");
		}
		break;

	case MIPS_EXC_INT_IO:
	case MIPS_EXC_INT_HT:
	case MIPS_EXC_INT_IPI:
		/* Clear GuestCtl2.VIP irq if not using Hardware Clear */
		if (cpu_has_guestctl2) {
			if(vcpu->arch.pending_exceptions_clr & (1<< priority)) {
				/*To insure the other IP not affect by the clear operation for
				* not once to clear all the pending_exception_clr
				*/
				vcpu->arch.cop0->reg[MIPS_CP0_CAUSE][0] = read_gc0_cause();
				vcpu->arch.cop0->reg[MIPS_CP0_CAUSE][0] &= (~irq);
				write_c0_guestctl2(vcpu->arch.cop0->reg[MIPS_CP0_CAUSE][0] & 0x4c00);
			}
		} else {
			kvm_err("No any other way to clear guest interrupt\n");
		}
		break;

	default:
		break;
	}

	clear_bit(priority, &vcpu->arch.pending_exceptions_clr);

	return 1;
}

static int kvm_vz_irq_deliver_cb(struct kvm_vcpu *vcpu, unsigned int priority,
				 u32 cause)
{
	u32 irq = (priority < MIPS_EXC_MAX) ?
		kvm_vz_priority_to_irq[priority] : 0;

	switch (priority) {
	case MIPS_EXC_INT_TIMER:
//		printk("--set guest cause TI\n");
		set_gc0_cause(C_TI);
		break;

	case MIPS_EXC_INT_IO:
	case MIPS_EXC_INT_HT:
	case MIPS_EXC_INT_IPI:
		if (cpu_has_guestctl2) {
			/*To insure the other IP not miss by the set guestctl2 for
			* not once to set all the pending_exception
			*/
			vcpu->arch.cop0->reg[MIPS_CP0_CAUSE][0] = read_gc0_cause();
			vcpu->arch.cop0->reg[MIPS_CP0_CAUSE][0] |= irq;
			write_c0_guestctl2(vcpu->arch.cop0->reg[MIPS_CP0_CAUSE][0] & 0x4c00);
		} else
			set_gc0_cause(irq);
		break;

	default:
		break;
	}

	clear_bit(priority, &vcpu->arch.pending_exceptions);

	return 1;
}

/*
 * VZ guest timer handling.
 */

/**
 * kvm_vz_should_use_htimer() - Find whether to use the VZ hard guest timer.
 * @vcpu:	Virtual CPU.
 *
 * Returns:	true if the VZ GTOffset & real guest CP0_Count should be used
 *		instead of software emulation of guest timer.
 *		false otherwise.
 */
static bool kvm_vz_should_use_htimer(struct kvm_vcpu *vcpu)
{
	if (kvm_mips_count_disabled(vcpu))
		return false;

	/* Chosen frequency must match real frequency */
	if (mips_hpt_frequency != vcpu->arch.count_hz)
		return false;

	/* We don't support a CP0_GTOffset with fewer bits than CP0_Count,
	 * because we don't test gtoffset in cpu-probe.c, so ignore this
	 */
//	if (current_cpu_data.gtoffset_mask != 0xffffffff)
//		return false;

//	printk("---user htimer\n");
	return true;
}

/**
 * _kvm_vz_restore_stimer() - Restore soft timer state.
 * @vcpu:	Virtual CPU.
 * @compare:	CP0_Compare register value, restored by caller.
 * @cause:	CP0_Cause register to restore.
 *
 * Restore VZ state relating to the soft timer. The hard timer can be enabled
 * later.
 */
static void _kvm_vz_restore_stimer(struct kvm_vcpu *vcpu, u32 compare,
				   u32 cause)
{
	/*
	 * Avoid spurious counter interrupts by setting Guest CP0_Count to just
	 * after Guest CP0_Compare.
	 */
	write_c0_gtoffset(compare - read_c0_count());

	back_to_back_c0_hazard();
	write_gc0_cause(cause);
	write_c0_guestctl2(cause & 0x4c00);
}

/**
 * _kvm_vz_restore_htimer() - Restore hard timer state.
 * @vcpu:	Virtual CPU.
 * @compare:	CP0_Compare register value, restored by caller.
 * @cause:	CP0_Cause register to restore.
 *
 * Restore hard timer Guest.Count & Guest.Cause taking care to preserve the
 * value of Guest.CP0_Cause.TI while restoring Guest.CP0_Cause.
 */
static void _kvm_vz_restore_htimer(struct kvm_vcpu *vcpu,
				   u32 compare, u32 cause)
{
	u32 start_count, after_count;
	ktime_t freeze_time;
	unsigned long flags;

	/*
	 * Freeze the soft-timer and sync the guest CP0_Count with it. We do
	 * this with interrupts disabled to avoid latency.
	 */
	local_irq_save(flags);
	freeze_time = kvm_mips_freeze_hrtimer(vcpu, &start_count);
	write_c0_gtoffset(start_count - read_c0_count());
	local_irq_restore(flags);

	/* restore guest CP0_Cause, as TI may already be set */
	back_to_back_c0_hazard();
	write_gc0_cause(cause);
	write_c0_guestctl2(cause & 0x4c00);

	/*
	 * The above sequence isn't atomic and would result in lost timer
	 * interrupts if we're not careful. Detect if a timer interrupt is due
	 * and assert it.
	 */
	back_to_back_c0_hazard();
	after_count = read_gc0_count();
	if (after_count - start_count > compare - start_count - 1)
		kvm_vz_queue_irq(vcpu, MIPS_EXC_INT_TIMER);
}

/**
 * kvm_vz_restore_timer() - Restore timer state.
 * @vcpu:	Virtual CPU.
 *
 * Restore soft timer state from saved context.
 */
static void kvm_vz_restore_timer(struct kvm_vcpu *vcpu)
{
	struct mips_coproc *cop0 = vcpu->arch.cop0;
	u32 cause, compare;

	compare = kvm_read_sw_gc0_compare(cop0);
	cause = kvm_read_sw_gc0_cause(cop0);

	write_gc0_compare(compare);
	_kvm_vz_restore_stimer(vcpu, compare, cause);
}

/**
 * kvm_vz_acquire_htimer() - Switch to hard timer state.
 * @vcpu:	Virtual CPU.
 *
 * Restore hard timer state on top of existing soft timer state if possible.
 *
 * Since hard timer won't remain active over preemption, preemption should be
 * disabled by the caller.
 */
void kvm_vz_acquire_htimer(struct kvm_vcpu *vcpu)
{
	u32 gctl0;

	gctl0 = read_c0_guestctl0();
	if (!(gctl0 & MIPS_GCTL0_GT) && kvm_vz_should_use_htimer(vcpu)) {
		/* enable guest access to hard timer */
		write_c0_guestctl0(gctl0 | MIPS_GCTL0_GT);

		_kvm_vz_restore_htimer(vcpu, read_gc0_compare(),
				       read_gc0_cause());
	}
}

/**
 * _kvm_vz_save_htimer() - Switch to software emulation of guest timer.
 * @vcpu:	Virtual CPU.
 * @compare:	Pointer to write compare value to.
 * @cause:	Pointer to write cause value to.
 *
 * Save VZ guest timer state and switch to software emulation of guest CP0
 * timer. The hard timer must already be in use, so preemption should be
 * disabled.
 */
static void _kvm_vz_save_htimer(struct kvm_vcpu *vcpu,
				u32 *out_compare, u32 *out_cause)
{
	u32 cause, compare, before_count, end_count;
	ktime_t before_time;

	compare = read_gc0_compare();
	*out_compare = compare;

	before_time = ktime_get();

	/*
	 * Record the CP0_Count *prior* to saving CP0_Cause, so we have a time
	 * at which no pending timer interrupt is missing.
	 */
	before_count = read_gc0_count();
	back_to_back_c0_hazard();
	cause = read_gc0_cause();
	*out_cause = cause;

	/*
	 * Record a final CP0_Count which we will transfer to the soft-timer.
	 * This is recorded *after* saving CP0_Cause, so we don't get any timer
	 * interrupts from just after the final CP0_Count point.
	 */
	back_to_back_c0_hazard();
	end_count = read_gc0_count();

	/*
	 * The above sequence isn't atomic, so we could miss a timer interrupt
	 * between reading CP0_Cause and end_count. Detect and record any timer
	 * interrupt due between before_count and end_count.
	 */
	if (end_count - before_count > compare - before_count - 1)
		kvm_vz_queue_irq(vcpu, MIPS_EXC_INT_TIMER);

	/*
	 * Restore soft-timer, ignoring a small amount of negative drift due to
	 * delay between freeze_hrtimer and setting CP0_GTOffset.
	 */
	kvm_mips_restore_hrtimer(vcpu, before_time, end_count, -0x10000);
}

/**
 * kvm_vz_save_timer() - Save guest timer state.
 * @vcpu:	Virtual CPU.
 *
 * Save VZ guest timer state and switch to soft guest timer if hard timer was in
 * use.
 */
static void kvm_vz_save_timer(struct kvm_vcpu *vcpu)
{
	struct mips_coproc *cop0 = vcpu->arch.cop0;
	u32 gctl0, compare, cause;

	gctl0 = read_c0_guestctl0();
	if (gctl0 & MIPS_GCTL0_GT) {
		/* disable guest use of hard timer */
		write_c0_guestctl0(gctl0 & ~MIPS_GCTL0_GT);

		/* save hard timer state */
		_kvm_vz_save_htimer(vcpu, &compare, &cause);
	} else {
		compare = read_gc0_compare();
		cause = read_gc0_cause();
	}

	/* save timer-related state to VCPU context */
	kvm_write_sw_gc0_cause(cop0, cause);
	kvm_write_sw_gc0_compare(cop0, compare);
}

/**
 * kvm_vz_lose_htimer() - Ensure hard guest timer is not in use.
 * @vcpu:	Virtual CPU.
 *
 * Transfers the state of the hard guest timer to the soft guest timer, leaving
 * guest state intact so it can continue to be used with the soft timer.
 */
void kvm_vz_lose_htimer(struct kvm_vcpu *vcpu)
{
	u32 gctl0, compare, cause;

	preempt_disable();
	gctl0 = read_c0_guestctl0();
	if (gctl0 & MIPS_GCTL0_GT) {
		/* disable guest use of timer */
		write_c0_guestctl0(gctl0 & ~MIPS_GCTL0_GT);

		/* switch to soft timer */
		_kvm_vz_save_htimer(vcpu, &compare, &cause);

		/* leave soft timer in usable state */
		_kvm_vz_restore_stimer(vcpu, compare, cause);
	}
	preempt_enable();
}

static unsigned long kvm_vz_num_regs(struct kvm_vcpu *vcpu)
{
	return 0;
}

static int kvm_vz_copy_reg_indices(struct kvm_vcpu *vcpu, u64 __user *indices)
{
	return 0;
}
#if 0
static inline s64 entrylo_kvm_to_user(unsigned long v)
{
	s64 mask, ret = v;

	if (BITS_PER_LONG == 32) {
		/*
		 * KVM API exposes 64-bit version of the register, so move the
		 * RI/XI bits up into place.
		 */
		mask = MIPS_ENTRYLO_RI | MIPS_ENTRYLO_XI;
		ret &= ~mask;
		ret |= ((s64)v & mask) << 32;
	}
	return ret;
}

static inline unsigned long entrylo_user_to_kvm(s64 v)
{
	unsigned long mask, ret = v;

	if (BITS_PER_LONG == 32) {
		/*
		 * KVM API exposes 64-bit versiono of the register, so move the
		 * RI/XI bits down into place.
		 */
		mask = MIPS_ENTRYLO_RI | MIPS_ENTRYLO_XI;
		ret &= ~mask;
		ret |= (v >> 32) & mask;
	}
	return ret;
}
#endif

static int kvm_vz_get_one_reg(struct kvm_vcpu *vcpu,
			      const struct kvm_one_reg *reg,
			      s64 *v)
{
	struct mips_coproc *cop0 = vcpu->arch.cop0;
	unsigned int idx;
	int ret = 0;

	switch (reg->id) {
	case KVM_REG_MIPS_CP0_INDEX:
		*v = (long)kvm_read_sw_gc0_index(cop0);
		break;
	case KVM_REG_MIPS_CP0_ENTRYLO0:
		*v = (long)kvm_read_sw_gc0_entrylo0(cop0);
		break;
	case KVM_REG_MIPS_CP0_ENTRYLO1:
		*v = (long)kvm_read_sw_gc0_entrylo1(cop0);
		break;
	case KVM_REG_MIPS_CP0_CONTEXT:
		*v = kvm_read_sw_gc0_context(cop0);
		break;
	case KVM_REG_MIPS_CP0_CONTEXTCONFIG:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_USERLOCAL:
		*v = read_gc0_userlocal();
		break;
#ifdef CONFIG_64BIT
	case KVM_REG_MIPS_CP0_XCONTEXTCONFIG:
		ret = -EINVAL;
		break;
#endif
	case KVM_REG_MIPS_CP0_PAGEMASK:
		*v = kvm_read_sw_gc0_pagemask(cop0);
		break;
	case KVM_REG_MIPS_CP0_PAGEGRAIN:
		*v = (long)kvm_read_sw_gc0_pagegrain(cop0);
		break;
	case KVM_REG_MIPS_CP0_SEGCTL0:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_SEGCTL1:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_SEGCTL2:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_PWBASE:
		*v = kvm_read_sw_gc0_pwbase(cop0);
		break;
	case KVM_REG_MIPS_CP0_PWFIELD:
		*v = kvm_read_sw_gc0_pwfield(cop0);
		break;
	case KVM_REG_MIPS_CP0_PWSIZE:
		*v = kvm_read_sw_gc0_pwsize(cop0);
		break;
	case KVM_REG_MIPS_CP0_WIRED:
		*v = (long)kvm_read_sw_gc0_wired(cop0);
		break;
	case KVM_REG_MIPS_CP0_PWCTL:
		*v = (long)kvm_read_sw_gc0_pwctl(cop0);
		break;
	case KVM_REG_MIPS_CP0_HWRENA:
		*v = (long)read_gc0_hwrena();
		break;
	case KVM_REG_MIPS_CP0_BADVADDR:
		*v = (long)read_gc0_badvaddr();
		break;
	case KVM_REG_MIPS_CP0_BADINSTR:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_BADINSTRP:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_COUNT:
		*v = kvm_mips_read_count(vcpu);
		break;
	case KVM_REG_MIPS_CP0_ENTRYHI:
		*v = (long)read_gc0_entryhi();
		break;
	case KVM_REG_MIPS_CP0_COMPARE:
		*v = (long)read_gc0_compare();
		break;
	case KVM_REG_MIPS_CP0_STATUS:
		*v = (long)read_gc0_status();
		break;
	case KVM_REG_MIPS_CP0_INTCTL:
		*v = read_gc0_intctl();
		break;
	case KVM_REG_MIPS_CP0_CAUSE:
		*v = (long)read_gc0_cause();
		break;
	case KVM_REG_MIPS_CP0_EPC:
		*v = (long)read_gc0_epc();
		break;
	case KVM_REG_MIPS_CP0_PRID:
		*v = (long)kvm_read_sw_gc0_prid(cop0);
		break;
	case KVM_REG_MIPS_CP0_EBASE:
		*v = kvm_vz_read_gc0_ebase();
		break;
	case KVM_REG_MIPS_CP0_CONFIG:
		*v = read_gc0_config();
		break;
	case KVM_REG_MIPS_CP0_CONFIG1:
		*v = read_gc0_config1();
		break;
	case KVM_REG_MIPS_CP0_CONFIG2:
		*v = read_gc0_config2();
		break;
	case KVM_REG_MIPS_CP0_CONFIG3:
		*v = read_gc0_config3();
		break;
	case KVM_REG_MIPS_CP0_CONFIG4:
		*v = read_gc0_config4();
		break;
	case KVM_REG_MIPS_CP0_CONFIG5:
		*v = read_gc0_config5();
		break;
#if 0
	case KVM_REG_MIPS_CP0_MAAR(0) ... KVM_REG_MIPS_CP0_MAAR(0x3f):
		if (!cpu_guest_has_maar || cpu_guest_has_dyn_maar)
			return -EINVAL;
		idx = reg->id - KVM_REG_MIPS_CP0_MAAR(0);
		if (idx >= ARRAY_SIZE(vcpu->arch.maar))
			return -EINVAL;
		*v = vcpu->arch.maar[idx];
		break;
	case KVM_REG_MIPS_CP0_MAARI:
		if (!cpu_guest_has_maar || cpu_guest_has_dyn_maar)
			return -EINVAL;
		*v = kvm_read_sw_gc0_maari(vcpu->arch.cop0);
		break;
#endif
#ifdef CONFIG_64BIT
	case KVM_REG_MIPS_CP0_XCONTEXT:
		*v = (long)kvm_read_sw_gc0_xcontext(cop0);
		break;
#endif
	case KVM_REG_MIPS_CP0_ERROREPC:
		*v = (long)read_gc0_errorepc();
		break;
	case KVM_REG_MIPS_CP0_KSCRATCH1 ... KVM_REG_MIPS_CP0_KSCRATCH6:
		idx = reg->id - KVM_REG_MIPS_CP0_KSCRATCH1 + 2;
		switch (idx) {
		case 2:
			*v = (long)kvm_read_sw_gc0_kscratch1(cop0);
			break;
		case 3:
			*v = (long)kvm_read_sw_gc0_kscratch2(cop0);
			break;
		case 4:
			*v = (long)kvm_read_sw_gc0_kscratch3(cop0);
			break;
		case 5:
			*v = (long)kvm_read_sw_gc0_kscratch4(cop0);
			break;
		case 6:
			*v = (long)kvm_read_sw_gc0_kscratch5(cop0);
			break;
		case 7:
			*v = (long)kvm_read_sw_gc0_kscratch6(cop0);
			break;
		}
		break;
	case KVM_REG_MIPS_COUNT_CTL:
		*v = vcpu->arch.count_ctl;
		break;
	case KVM_REG_MIPS_COUNT_RESUME:
		*v = ktime_to_ns(vcpu->arch.count_resume);
		break;
	case KVM_REG_MIPS_COUNT_HZ:
		*v = vcpu->arch.count_hz;
		break;
	default:
		return -EINVAL;
	}
	return ret;
}

static int kvm_vz_set_one_reg(struct kvm_vcpu *vcpu,
			      const struct kvm_one_reg *reg,
			      s64 v)
{
	struct mips_coproc *cop0 = vcpu->arch.cop0;
	unsigned int idx;
	int ret = 0;
	unsigned int cur, change;

	switch (reg->id) {
	case KVM_REG_MIPS_CP0_INDEX:
		kvm_write_sw_gc0_index(cop0,v);
		break;
	case KVM_REG_MIPS_CP0_ENTRYLO0:
		kvm_write_sw_gc0_entrylo0(cop0,v);
		break;
	case KVM_REG_MIPS_CP0_ENTRYLO1:
		kvm_write_sw_gc0_entrylo1(cop0,v);
		break;
	case KVM_REG_MIPS_CP0_CONTEXT:
		kvm_write_sw_gc0_context(cop0,v);
		break;
	case KVM_REG_MIPS_CP0_CONTEXTCONFIG:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_USERLOCAL:
		write_gc0_userlocal(v);
		break;
#ifdef CONFIG_64BIT
	case KVM_REG_MIPS_CP0_XCONTEXTCONFIG:
		ret = -EINVAL;
		break;
#endif
	case KVM_REG_MIPS_CP0_PAGEMASK:
		kvm_write_sw_gc0_pagemask(cop0,v);
		break;
	case KVM_REG_MIPS_CP0_PAGEGRAIN:
		kvm_write_sw_gc0_pagegrain(cop0,v);
		break;
	case KVM_REG_MIPS_CP0_SEGCTL0:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_SEGCTL1:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_SEGCTL2:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_PWBASE:
		kvm_write_sw_gc0_pwbase(cop0,v);
		break;
	case KVM_REG_MIPS_CP0_PWFIELD:
		kvm_write_sw_gc0_pwfield(cop0,v);
		break;
	case KVM_REG_MIPS_CP0_PWSIZE:
		kvm_write_sw_gc0_pwsize(cop0,v);
		break;
	case KVM_REG_MIPS_CP0_WIRED:
		kvm_write_sw_gc0_wired(cop0,v);
		break;
	case KVM_REG_MIPS_CP0_PWCTL:
		kvm_write_sw_gc0_pwctl(cop0,v);
		break;
	case KVM_REG_MIPS_CP0_HWRENA:
		write_gc0_hwrena(v);
		break;
	case KVM_REG_MIPS_CP0_BADVADDR:
		write_gc0_badvaddr(v);
		break;
	case KVM_REG_MIPS_CP0_BADINSTR:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_BADINSTRP:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_COUNT:
		kvm_mips_write_count(vcpu, v);
		break;
	case KVM_REG_MIPS_CP0_ENTRYHI:
		write_gc0_entryhi(v);
		break;
	case KVM_REG_MIPS_CP0_COMPARE:
		kvm_mips_write_compare(vcpu, v, false);
		break;
	case KVM_REG_MIPS_CP0_STATUS:
		write_gc0_status(v);
		break;
	case KVM_REG_MIPS_CP0_INTCTL:
		write_gc0_intctl(v);
		break;
	case KVM_REG_MIPS_CP0_CAUSE:
		/*
		 * If the timer is stopped or started (DC bit) it must look
		 * atomic with changes to the timer interrupt pending bit (TI).
		 * A timer interrupt should not happen in between.
		 */
		if ((read_gc0_cause() ^ v) & CAUSEF_DC) {
			if (v & CAUSEF_DC) {
				/* disable timer first */
				kvm_mips_count_disable_cause(vcpu);
				change_gc0_cause((u32)~CAUSEF_DC, v);
			} else {
				/* enable timer last */
				change_gc0_cause((u32)~CAUSEF_DC, v);
				kvm_mips_count_enable_cause(vcpu);
			}
		} else {
			write_gc0_cause(v);
		}
		break;
	case KVM_REG_MIPS_CP0_EPC:
		write_gc0_epc(v);
		break;
	case KVM_REG_MIPS_CP0_PRID:
		kvm_write_sw_gc0_prid(cop0,v);
		break;
	case KVM_REG_MIPS_CP0_EBASE:
		kvm_vz_write_gc0_ebase(v);
		break;
	case KVM_REG_MIPS_CP0_CONFIG:
		cur = read_gc0_config();
		change = (cur ^ v) & kvm_vz_config_user_wrmask(vcpu);
		if (change) {
			v = cur ^ change;
			write_gc0_config(v);
		}
		break;
	case KVM_REG_MIPS_CP0_CONFIG1:
		cur = read_gc0_config1();
		change = (cur ^ v) & kvm_vz_config1_user_wrmask(vcpu);
		if (change) {
			v = cur ^ change;
			write_gc0_config1(v);
		}
		break;
	case KVM_REG_MIPS_CP0_CONFIG2:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_CONFIG3:
		ret = -EINVAL;
		break;
	case KVM_REG_MIPS_CP0_CONFIG4:
		cur = read_gc0_config4();
		change = (cur ^ v) & kvm_vz_config4_user_wrmask(vcpu);
		if (change) {
			v = cur ^ change;
			write_gc0_config4(v);
		}
		break;
	case KVM_REG_MIPS_CP0_CONFIG5:
		cur = read_gc0_config5();
		change = (cur ^ v) & kvm_vz_config5_user_wrmask(vcpu);
		if (change) {
			v = cur ^ change;
			write_gc0_config5(v);
		}
		break;
#if 0
	case KVM_REG_MIPS_CP0_MAAR(0) ... KVM_REG_MIPS_CP0_MAAR(0x3f):
		if (!cpu_guest_has_maar || cpu_guest_has_dyn_maar)
			return -EINVAL;
		idx = reg->id - KVM_REG_MIPS_CP0_MAAR(0);
		if (idx >= ARRAY_SIZE(vcpu->arch.maar))
			return -EINVAL;
		vcpu->arch.maar[idx] = mips_process_maar(dmtc_op, v);
		break;
	case KVM_REG_MIPS_CP0_MAARI:
		if (!cpu_guest_has_maar || cpu_guest_has_dyn_maar)
			return -EINVAL;
		kvm_write_maari(vcpu, v);
		break;
#endif
#ifdef CONFIG_64BIT
	case KVM_REG_MIPS_CP0_XCONTEXT:
		kvm_write_sw_gc0_xcontext(cop0,v);
		break;
#endif
	case KVM_REG_MIPS_CP0_ERROREPC:
		write_gc0_errorepc(v);
		break;
	case KVM_REG_MIPS_CP0_KSCRATCH1 ... KVM_REG_MIPS_CP0_KSCRATCH6:
		idx = reg->id - KVM_REG_MIPS_CP0_KSCRATCH1 + 2;
		switch (idx) {
		case 2:
			kvm_write_sw_gc0_kscratch1(cop0,v);
			break;
		case 3:
			kvm_write_sw_gc0_kscratch2(cop0,v);
			break;
		case 4:
			kvm_write_sw_gc0_kscratch3(cop0,v);
			break;
		case 5:
			kvm_write_sw_gc0_kscratch4(cop0,v);
			break;
		case 6:
			kvm_write_sw_gc0_kscratch5(cop0,v);
			break;
		case 7:
			kvm_write_sw_gc0_kscratch6(cop0,v);
			break;
		}
		break;
	case KVM_REG_MIPS_COUNT_CTL:
		ret = kvm_mips_set_count_ctl(vcpu, v);
		break;
	case KVM_REG_MIPS_COUNT_RESUME:
		ret = kvm_mips_set_count_resume(vcpu, v);
		break;
	case KVM_REG_MIPS_COUNT_HZ:
		ret = kvm_mips_set_count_hz(vcpu, v);
		break;
	default:
		return -EINVAL;
	}
	return ret;
}

/* Returns 1 if the guest TLB may be clobbered */
static int kvm_vz_check_requests(struct kvm_vcpu *vcpu, int cpu)
{
	int ret = 0;
	int i;

	if (!vcpu->requests)
		return 0;

	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
		if (cpu_has_guestid) {
			/* Drop all GuestIDs for this VCPU */
			for_each_possible_cpu(i)
				vcpu->arch.vzguestid[i] = 0;
			/* This will clobber guest TLB contents too */
			ret = 1;
		}
		/*
		 * For Root ASID Dealias (RAD) we don't do anything here, but we
		 * still need the request to ensure we recheck asid_flush_mask.
		 * We can still return 0 as only the root TLB will be affected
		 * by a root ASID flush.
		 */
	}

	return ret;
}

#define vpid_cache(cpu)	(cpu_data[cpu].vpid_cache)
#define VPID_MASK	0xff
#define VPID_VERSION_MASK  ((unsigned long)~(VPID_MASK|(VPID_MASK-1)))
#define VPID_FIRST_VERSION ((unsigned long)(~VPID_VERSION_MASK) + 1)

static void kvm_vz_get_new_vpid(unsigned long cpu, struct kvm_vcpu *vcpu)
{
	unsigned long guestid = vpid_cache(cpu);

	if (!(++guestid & VPID_MASK)) {
		if (!guestid)		/* fix version if needed */
			guestid = VPID_FIRST_VERSION;

		++guestid;		/* guestid 0 reserved for root */

		/* start new guestid cycle */
		local_flush_tlb_all();
	}

	vpid_cache(cpu) = guestid;
}


static void kvm_vz_vcpu_change_vpid(struct kvm_vcpu *vcpu, int cpu)
{
	bool migrated, all;

	/*
	 * Are we entering guest context on a different CPU to last time?
	 * If so, the VCPU's guest TLB state on this CPU may be stale.
	 */
	migrated = (vcpu->arch.last_exec_cpu != cpu);
	vcpu->arch.last_exec_cpu = cpu;
	all = migrated || (last_exec_vcpu[cpu] != vcpu);
	last_exec_vcpu[cpu] = vcpu;

	/*
	 *
	 */
#if 1
	if (
	    (vcpu->arch.vpid[cpu] ^ vpid_cache(cpu)) &
				VPID_VERSION_MASK) {
		kvm_vz_get_new_vpid(cpu, vcpu);
		vcpu->arch.vpid[cpu] = vpid_cache(cpu);
//		trace_kvm_guestid_change(vcpu,
//					 vcpu->arch.vpid[cpu]);
	}
	write_c0_vpid((read_c0_vpid() &0xff00) | (vcpu->arch.vpid[cpu] & 0xff));
#endif
}


static int kvm_vz_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct mips_coproc *cop0 = vcpu->arch.cop0;
	bool migrated, all;

	/*
	 * Have we migrated to a different CPU?
	 * If so, any old guest TLB state may be stale.
	 */
	migrated = (vcpu->arch.last_sched_cpu != cpu);

	/*
	 * Was this the last VCPU to run on this CPU?
	 * If not, any old guest state from this VCPU will have been clobbered.
	 */
	all = migrated || (last_vcpu[cpu] != vcpu);
	last_vcpu[cpu] = vcpu;

	/*Should we load the guest cp0s here??? FIX ME */

	/*
	 * Restore timer state regardless, as e.g. Cause.TI can change over time
	 * if left unmaintained.
	 */
	kvm_vz_restore_timer(vcpu);

	if (current->flags & PF_VCPU) {
		kvm_vz_vcpu_change_vpid(vcpu, cpu);
	}
	/* Don't bother restoring registers multiple times unless necessary */
	if (!all)
		return 0;

	write_c0_gsebase(0x800);
	write_c0_gsebase(kvm_read_sw_gc0_gsebase(cop0));

	/*
	 * Restore config registers first, as some implementations restrict
	 * writes to other registers when the corresponding feature bits aren't
	 * set.Only conf/conf1/conf4 are writable.
	 * For example Status.CU1 cannot be set unless Config1.FP is set.
	 */
	kvm_restore_gc0_config(cop0);
	kvm_restore_gc0_config1(cop0);
	kvm_restore_gc0_config4(cop0);

	kvm_restore_gc0_hwrena(cop0);
	kvm_restore_gc0_badvaddr(cop0);
	/*Restore entryhi will cause trouble temporarily,if set guestctl0.asid=1 FIX ME!!!!!*/
	kvm_restore_gc0_entryhi(cop0);
	kvm_restore_gc0_status(cop0);
	kvm_restore_gc0_intctl(cop0);
	kvm_restore_gc0_epc(cop0);
	kvm_vz_write_gc0_ebase(kvm_read_sw_gc0_ebase(cop0) | vcpu->vcpu_id);
	kvm_restore_gc0_userlocal(cop0);
	kvm_restore_gc0_errorepc(cop0);

	/* restore Root.GuestCtl2 from unused Guest guestctl2 register */
	if (cpu_has_guestctl2) {
		write_c0_guestctl2(
			cop0->reg[MIPS_CP0_CAUSE][0] & 0x4c00);
	}

	return 0;
}

static int kvm_vz_vcpu_put(struct kvm_vcpu *vcpu, int cpu)
{
	struct mips_coproc *cop0 = vcpu->arch.cop0;

	if (current->flags & PF_VCPU)
		;
	/*Should we save the guest cp0s here??? FIX ME */

	kvm_lose_fpu(vcpu);

	kvm_save_gc0_hwrena(cop0);
	kvm_save_gc0_badvaddr(cop0);
	/*Not save entryhi for temporarily,FIX ME!!!!!!*/
	kvm_save_gc0_entryhi(cop0);
	kvm_save_gc0_status(cop0);
	kvm_save_gc0_intctl(cop0);
	kvm_save_gc0_epc(cop0);
	kvm_write_sw_gc0_ebase(cop0, kvm_vz_read_gc0_ebase() |vcpu->vcpu_id);
	kvm_save_gc0_userlocal(cop0);

	/* only save implemented and writable config registers */
	kvm_save_gc0_config(cop0);
	kvm_save_gc0_config1(cop0);
	kvm_save_gc0_config4(cop0);

	kvm_save_gc0_errorepc(cop0);

	kvm_vz_save_timer(vcpu);

	/* save Root.GuestCtl2 in unused Guest guestctl2 register */
	if (cpu_has_guestctl2)
		cop0->reg[MIPS_CP0_GUESTCTL2][MIPS_CP0_GUESTCTL2_SEL] =
			read_gc0_cause() & 0x4c00;

	return 0;
}

static void kvm_vz_vcpu_reenter(struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	int cpu = smp_processor_id();
	kvm_vz_check_requests(vcpu, cpu);
	save_regs_with_field_change_exception(vcpu);
	kvm_vz_vcpu_change_vpid(vcpu, cpu);
}

static int kvm_vz_vcpu_run(struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	int cpu = smp_processor_id();
	int r;

	kvm_vz_acquire_htimer(vcpu);
	/* Check if we have any exceptions/interrupts pending */
	kvm_mips_deliver_interrupts(vcpu, read_gc0_cause());

	kvm_vz_check_requests(vcpu, cpu);
	kvm_vz_vcpu_change_vpid(vcpu, cpu);
	save_regs_with_field_change_exception(vcpu);

	r = vcpu->arch.vcpu_run(run, vcpu);

	return r;
}

static struct kvm_mips_callbacks kvm_vz_callbacks = {
	.handle_cop_unusable = kvm_trap_vz_handle_cop_unusable,
	.handle_tlb_mod = kvm_trap_vz_handle_tlb_st_miss,
	.handle_tlb_ld_miss = kvm_trap_vz_handle_tlb_ld_miss,
	.handle_tlb_st_miss = kvm_trap_vz_handle_tlb_st_miss,
	.handle_addr_err_st = kvm_trap_vz_no_handler,
	.handle_addr_err_ld = kvm_trap_vz_no_handler,
	.handle_syscall = kvm_trap_vz_no_handler,
	.handle_res_inst = kvm_trap_vz_no_handler,
	.handle_break = kvm_trap_vz_no_handler,
	.handle_msa_disabled = kvm_trap_vz_handle_msa_disabled,
	.handle_guest_exit = kvm_trap_vz_handle_guest_exit,

	.hardware_enable = kvm_vz_hardware_enable,
	.hardware_disable = kvm_vz_hardware_disable,
	.check_extension = kvm_vz_check_extension,
	.vcpu_init = kvm_vz_vcpu_init,
	.vcpu_uninit = kvm_vz_vcpu_uninit,
	.vcpu_setup = kvm_vz_vcpu_setup,
	.flush_shadow_all = kvm_vz_flush_shadow_all,
	.flush_shadow_memslot = kvm_vz_flush_shadow_memslot,
	.gva_to_gpa = kvm_vz_gva_to_gpa_cb,
	.queue_timer_int = kvm_vz_queue_timer_int_cb,
	.dequeue_timer_int = kvm_vz_dequeue_timer_int_cb,
	.queue_io_int = kvm_vz_queue_io_int_cb,
	.dequeue_io_int = kvm_vz_dequeue_io_int_cb,
	.irq_deliver = kvm_vz_irq_deliver_cb,
	.irq_clear = kvm_vz_irq_clear_cb,
	.num_regs = kvm_vz_num_regs,
	.copy_reg_indices = kvm_vz_copy_reg_indices,
	.get_one_reg = kvm_vz_get_one_reg,
	.set_one_reg = kvm_vz_set_one_reg,
	.vcpu_load = kvm_vz_vcpu_load,
	.vcpu_put = kvm_vz_vcpu_put,
	.vcpu_run = kvm_vz_vcpu_run,
	.vcpu_reenter = kvm_vz_vcpu_reenter,
};

/*初始化的有点太简单，直接赋予了一个ops ~jeff */
int kvm_mips_emulation_init(struct kvm_mips_callbacks **install_callbacks)
{
	if (!cpu_has_vz)
		return -ENODEV;

	/*
	 * VZ requires at least 2 KScratch registers, so it should have been
	 * possible to allocate pgd_reg.
	 */
	if (WARN(pgd_reg == -1,
		 "pgd_reg not allocated even though cpu_has_vz\n"))
		return -ENODEV;

	pr_info("Starting KVM with MIPS VZ extensions\n");

	*install_callbacks = &kvm_vz_callbacks;
	return 0;
}
