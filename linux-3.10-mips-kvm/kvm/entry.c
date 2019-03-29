/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Generation of main entry point for the guest, exception handling.
 *
 * Copyright (C) 2012  MIPS Technologies, Inc.
 * Authors: Sanjay Lal <sanjayl@kymasys.com>
 *
 * Copyright (C) 2016 Imagination Technologies Ltd.
 */

#include <linux/kvm_host.h>
#include <linux/log2.h>
#include <asm/mmu_context.h>
#include <asm/setup.h>
#include <asm/tlbex.h>
#include <asm/uasm.h>

//#define LSVZ_TLB_ISOLATE_DEBUG
#ifdef LSVZ_TLB_ISOLATE_DEBUG
int guest_vtlb_index = 0;
#endif
// used by ls vz
#define C0_COUNT	9, 0
#define C0_GUESTCTL2	10, 5
#define C0_COMPARE	11, 0
#define C0_GTOFFSET	12, 7
#define C0_DIAG		22, 0
#define C0_GSCAUSE	22, 1
#define C0_GSEBASE	9, 6
#define LS_ITLB_SHIFT	2
#define LS_MODE_SHIFT	16
#define LS_MID_SHIFT	18
#define MIPS_GCTL0_ASID_SHIFT	20
#define MIPS_GCTL0_ASID		(_ULCAST_(1) << MIPS_GCTL0_ASID_SHIFT)

/* Register names */
#define ZERO		0
#define AT		1
#define V0		2
#define V1		3
#define A0		4
#define A1		5
#define A2		6
#define A3		7

#if _MIPS_SIM == _MIPS_SIM_ABI32
#define T0		8
#define T1		9
#define T2		10
#define T3		11
#endif /* _MIPS_SIM == _MIPS_SIM_ABI32 */

#if _MIPS_SIM == _MIPS_SIM_ABI64 || _MIPS_SIM == _MIPS_SIM_NABI32
#define A4		8
#define T0		12
#define T1		13
#define T2		14
#define T3		15
#endif /* _MIPS_SIM == _MIPS_SIM_ABI64 || _MIPS_SIM == _MIPS_SIM_NABI32 */

#define S0		16
#define S1		17
#define T9		25
#define K0		26
#define K1		27
#define GP		28
#define SP		29
#define RA		31

/* Some CP0 registers */
#define C0_INDEX	0, 0
#define C0_ENTRYLO0	2, 0
#define C0_ENTRYLO1	3, 0
#define C0_PAGEMASK	5, 0
#define C0_PWBASE	5, 5
#define C0_HWRENA	7, 0
#define C0_BADVADDR	8, 0
#define C0_BADINSTR	8, 1
#define C0_BADINSTRP	8, 2
#define C0_ENTRYHI	10, 0
#define C0_GUESTCTL1	10, 4
#define C0_STATUS	12, 0
#define C0_GUESTCTL0	12, 6
#define C0_CAUSE	13, 0
#define C0_EPC		14, 0
#define C0_EBASE	15, 1
#define C0_CONFIG5	16, 5
#define C0_DDATA_LO	28, 3
#define C0_ERROREPC	30, 0

#define CALLFRAME_SIZ   32

#ifdef CONFIG_64BIT
#define ST0_KX_IF_64	ST0_KX
#else
#define ST0_KX_IF_64	0
#endif

static unsigned int scratch_vcpu[2] = { C0_DDATA_LO };
static unsigned int scratch_tmp[2] = { C0_ERROREPC };

enum label_id {
	label_fpu_1 = 1,
	label_msa_1,
	label_return_to_host,
	label_kernel_asid,
	label_exit_common,
	label_no_tlb_line,
	label_finish_tlb_fill,
	label_ignore_tlb_general,
	label_mapped,
	label_not_mapped,
	label_refill_exit,
	label_tlb_normal,
	label_tlb_flush,
	label_get_gpa,
	label_get_hpa,
	label_fpu_0,
	label_not_write_count,
	label_finish_write_count,
	label_no_ti,
	label_nodecounter,
};

UASM_L_LA(_fpu_1)
UASM_L_LA(_msa_1)
UASM_L_LA(_return_to_host)
UASM_L_LA(_kernel_asid)
UASM_L_LA(_exit_common)
UASM_L_LA(_no_tlb_line)
UASM_L_LA(_finish_tlb_fill)
UASM_L_LA(_ignore_tlb_general)
UASM_L_LA(_not_mapped)
UASM_L_LA(_mapped)
UASM_L_LA(_refill_exit)
UASM_L_LA(_tlb_normal)
UASM_L_LA(_tlb_flush)
UASM_L_LA(_get_gpa)
UASM_L_LA(_get_hpa)
UASM_L_LA(_fpu_0)
UASM_L_LA(_not_write_count)
UASM_L_LA(_finish_write_count)
UASM_L_LA(_no_ti)
UASM_L_LA(_nodecounter)

static void *kvm_mips_build_enter_guest(void *addr);
static void *kvm_mips_build_ret_from_exit(void *addr, int update_tlb);
static void *kvm_mips_build_ret_to_guest(void *addr);
static void *kvm_mips_build_ret_to_host(void *addr);
extern void __kvm_save_fpu(struct kvm_vcpu_arch *arch);
extern void __kvm_restore_fpu(struct kvm_vcpu_arch *arch);
extern void __kvm_restore_fcsr(struct kvm_vcpu_arch *arch);

/*
 * The version of this function in tlbex.c uses current_cpu_type(), but for KVM
 * we assume symmetry.
 */
static int c0_kscratch(void)
{
	switch (boot_cpu_type()) {
	case CPU_XLP:
	case CPU_XLR:
		return 22;
	default:
		return 31;
	}
}

/**
 * kvm_mips_entry_setup() - Perform global setup for entry code.
 *
 * Perform global setup for entry code, such as choosing a scratch register.
 *
 * Returns:	0 on success.
 *		-errno on failure.
 */
int kvm_mips_entry_setup(void)
{
	/*
	 * We prefer to use KScratchN registers if they are available over the
	 * defaults above, which may not work on all cores.
	 */
	unsigned int kscratch_mask = cpu_data[0].kscratch_mask;

	if (pgd_reg != -1)
		kscratch_mask &= ~BIT(pgd_reg);

	/* Pick a scratch register for storing VCPU */
	if (kscratch_mask) {
		scratch_vcpu[0] = c0_kscratch();
		scratch_vcpu[1] = 4;
		kscratch_mask &= ~BIT(scratch_vcpu[1]);
	}

	/* Pick a scratch register to use as a temp for saving state */
	if (kscratch_mask) {
		scratch_tmp[0] = c0_kscratch();
		scratch_tmp[1] = 5;
		kscratch_mask &= ~BIT(scratch_tmp[1]);
	}

	return 0;
}

static void kvm_mips_build_save_scratch(u32 **p, unsigned int tmp,
					unsigned int frame)
{
	/* Save the VCPU scratch register value in cp0_epc of the stack frame */
	UASM_i_MFC0(p, tmp, scratch_vcpu[0], scratch_vcpu[1]);
	UASM_i_SW(p, tmp, offsetof(struct pt_regs, cp0_epc), frame);

	/* Save the temp scratch register value in cp0_cause of stack frame */
	if (scratch_tmp[0] == c0_kscratch()) {
		UASM_i_MFC0(p, tmp, scratch_tmp[0], scratch_tmp[1]);
		UASM_i_SW(p, tmp, offsetof(struct pt_regs, cp0_cause), frame);
	}
}

static void kvm_mips_build_restore_scratch(u32 **p, unsigned int tmp,
					   unsigned int frame)
{
	/*
	 * Restore host scratch register values saved by
	 * kvm_mips_build_save_scratch().
	 */
	UASM_i_LW(p, tmp, offsetof(struct pt_regs, cp0_epc), frame);
	UASM_i_MTC0(p, tmp, scratch_vcpu[0], scratch_vcpu[1]);

	if (scratch_tmp[0] == c0_kscratch()) {
		UASM_i_LW(p, tmp, offsetof(struct pt_regs, cp0_cause), frame);
		UASM_i_MTC0(p, tmp, scratch_tmp[0], scratch_tmp[1]);
	}
}

/**
 * build_set_exc_base() - Assemble code to write exception base address.
 * @p:		Code buffer pointer.
 * @reg:	Source register (generated code may set WG bit in @reg).
 *
 * Assemble code to modify the exception base address in the EBase register,
 * using the appropriately sized access and setting the WG bit if necessary.
 */
static inline void build_set_exc_base(u32 **p, unsigned int reg)
{
	if (cpu_has_ebase_wg) {
		/* Set WG so that all the bits get written */
		uasm_i_ori(p, reg, reg, MIPS_EBASE_WG);
		UASM_i_MTC0(p, reg, C0_EBASE);
		UASM_i_MTC0(p, reg, C0_EBASE);
	} else {
		UASM_i_MTC0(p, reg, C0_EBASE);
	}
}

/**
 * kvm_mips_build_vcpu_run() - Assemble function to start running a guest VCPU.
 * @addr:	Address to start writing code.
 *
 * Assemble the start of the vcpu_run function to run a guest VCPU. The function
 * conforms to the following prototype:
 *
 * int vcpu_run(struct kvm_run *run, struct kvm_vcpu *vcpu);
 *
 * The exit from the guest and return to the caller is handled by the code
 * generated by kvm_mips_build_ret_to_host().
 *
 * Returns:	Next address after end of written function.
 */
void *kvm_mips_build_vcpu_run(void *addr)
{
	u32 *p = addr;
	unsigned int i;

	/*
	 * A0: run
	 * A1: vcpu
	 */

	/* k0/k1 not being used in host kernel context */
	UASM_i_ADDIU(&p, K1, SP, -(int)sizeof(struct pt_regs));
	for (i = 16; i < 32; ++i) {
		if (i == K0 || i == K1)
			continue;
		UASM_i_SW(&p, i, offsetof(struct pt_regs, regs[i]), K1);
	}

	/* Save host status */
	uasm_i_mfc0(&p, V0, C0_STATUS);
	UASM_i_SW(&p, V0, offsetof(struct pt_regs, cp0_status), K1);

	/* Save scratch registers, will be used to store pointer to vcpu etc */
	kvm_mips_build_save_scratch(&p, V1, K1);

	/* VCPU scratch register has pointer to vcpu */
	UASM_i_MTC0(&p, A1, scratch_vcpu[0], scratch_vcpu[1]);

	/* Offset into vcpu->arch */
	UASM_i_ADDIU(&p, K1, A1, offsetof(struct kvm_vcpu, arch));

	/*
	 * Save the host stack to VCPU, used for exception processing
	 * when we exit from the Guest
	 */
	UASM_i_SW(&p, SP, offsetof(struct kvm_vcpu_arch, host_stack), K1);

	/* Save the kernel gp as well */
	UASM_i_SW(&p, GP, offsetof(struct kvm_vcpu_arch, host_gp), K1);

	/*
	 * Setup status register for running the guest in UM, interrupts
	 * are disabled
	 */
	UASM_i_LA(&p, K0, ST0_EXL | KSU_USER | ST0_UX | ST0_KX_IF_64 | ST0_MX);
	uasm_i_mtc0(&p, K0, C0_STATUS);
	uasm_i_ehb(&p);

	/* load up the new EBASE */
	UASM_i_LW(&p, K0, offsetof(struct kvm_vcpu_arch, guest_ebase), K1);
	build_set_exc_base(&p, K0);

	/*
	 * Now that the new EBASE has been loaded, unset BEV, set
	 * interrupt mask as it was but make sure that timer interrupts
	 * are enabled
	 */
#ifdef CONFIG_CPU_LOONGSON3
	UASM_i_LA(&p, K0, ST0_EXL | KSU_USER | ST0_IE | ST0_UX | ST0_KX_IF_64 | ST0_MX);
#else
	uasm_i_addiu(&p, K0, ZERO, ST0_EXL | KSU_USER | ST0_IE | ST0_KX_IF_64);
#endif
	uasm_i_andi(&p, V0, V0, ST0_IM);
	uasm_i_or(&p, K0, K0, V0);
	uasm_i_mtc0(&p, K0, C0_STATUS);
	uasm_i_ehb(&p);

	p = kvm_mips_build_enter_guest(p);

	return p;
}

/**
 * kvm_mips_build_enter_guest() - Assemble code to resume guest execution.
 * @addr:	Address to start writing code.
 *
 * Assemble the code to resume guest execution. This code is common between the
 * initial entry into the guest from the host, and returning from the exit
 * handler back to the guest.
 *
 * Returns:	Next address after end of written function.
 */
static void *kvm_mips_build_enter_guest(void *addr)
{
	u32 *p = addr;
	unsigned int i;
	struct uasm_label labels[8];
	struct uasm_reloc relocs[8];
	struct uasm_label __maybe_unused *l = labels;
	struct uasm_reloc __maybe_unused *r = relocs;

	memset(labels, 0, sizeof(labels));
	memset(relocs, 0, sizeof(relocs));

	/* Set Guest EPC */
	UASM_i_LW(&p, T0, offsetof(struct kvm_vcpu_arch, pc), K1);
	UASM_i_MTC0(&p, T0, C0_EPC);

#ifdef CONFIG_KVM_MIPS_VZ
#ifdef CONFIG_CPU_LOONGSON3
	/* Clear DIAG.MID */
	uasm_i_mfc0(&p, T0, C0_DIAG);
	uasm_i_ins(&p, T0, ZERO, LS_MID_SHIFT, 2);
	uasm_i_mtc0(&p, T0, C0_DIAG);
#endif

	/* Save normal linux process pgd (VZ guarantees pgd_reg is set) */
	/* Loongson use kscratch PWBASE instead of kscratch for save pgd, CAUTION!!!!!!!!!!!!! */
	if(cpu_has_ldpte)
		UASM_i_MFC0(&p, K0, C0_PWBASE);
	else
		UASM_i_MFC0(&p, K0, c0_kscratch(), pgd_reg);
	UASM_i_SW(&p, K0, offsetof(struct kvm_vcpu_arch, host_pgd), K1);

#ifndef CONFIG_CPU_LOONGSON3
	/*
	 * Set up KVM GPA pgd.
	 * This does roughly the same as TLBMISS_HANDLER_SETUP_PGD():
	 * - call tlbmiss_handler_setup_pgd(mm->pgd)
	 * - write mm->pgd into CP0_PWBase
	 *
	 * We keep S0 pointing at struct kvm so we can load the ASID below.
	 */
	UASM_i_LW(&p, S0, (int)offsetof(struct kvm_vcpu, kvm) -
			  (int)offsetof(struct kvm_vcpu, arch), K1);
	UASM_i_LW(&p, A0, offsetof(struct kvm, arch.gpa_mm.pgd), S0);
	UASM_i_LA(&p, T9, (unsigned long)tlbmiss_handler_setup_pgd);
	uasm_i_jalr(&p, RA, T9);
	/* delay slot */
	if (cpu_has_htw)
		UASM_i_MTC0(&p, A0, C0_PWBASE);
	else
		uasm_i_nop(&p);
#endif
	/* Set GM bit to setup eret to VZ guest context */
	uasm_i_addiu(&p, V1, ZERO, 1);
	uasm_i_mfc0(&p, K0, C0_GUESTCTL0);
	uasm_i_ins(&p, K0, V1, MIPS_GCTL0_GM_SHIFT, 1);
	uasm_i_ins(&p, K0, V1, MIPS_GCTL0_CP0_SHIFT, 1);
	uasm_i_ins(&p, K0, V1, MIPS_GCTL0_CF_SHIFT, 1);
	uasm_i_ins(&p, K0, V1, MIPS_GCTL0_ASID_SHIFT, 1);
	uasm_i_mtc0(&p, K0, C0_GUESTCTL0);
	/* LSVZ set diag bit[16] = 1 */
	uasm_i_mfc0(&p, K0, C0_DIAG);
	uasm_i_ins(&p, K0, V1, LS_MODE_SHIFT, 1);
	uasm_i_mtc0(&p, K0, C0_DIAG);

	uasm_i_mfgc0(&p, K0, C0_STATUS);
	uasm_i_ins(&p, K0, ZERO, 2, 1);
	uasm_i_ins(&p, K0, ZERO, 22, 1);
	uasm_i_mtgc0(&p, K0, C0_STATUS);

#ifdef CONFIG_CPU_LOONGSON3
	/* Get gsebase and set GSEBASE (9,6)*/
	UASM_i_LW(&p, K0, offsetof(struct kvm_vcpu_arch, cop0), K1);
	UASM_i_LW(&p, K0, offsetof(struct mips_coproc,
			reg[MIPS_CP0_COUNT][6]), K0);
	UASM_i_ADDIU(&p, V1, ZERO, 0x800);
	UASM_i_MTC0(&p, V1, C0_GSEBASE);
	UASM_i_MTC0(&p, K0, C0_GSEBASE);

#endif

//	uasm_i_lui(&p, K0, 0x8010);
//	uasm_i_mtc0(&p, K0, C0_GSEBASE);
#if 0
	if (cpu_has_guestid) {
		/*
		 * Set root mode GuestID, so that root TLB refill handler can
		 * use the correct GuestID in the root TLB.
		 */

		/*[> Get current GuestID <]*/
		uasm_i_mfc0(&p, T0, C0_GUESTCTL1);
		/*[> Set GuestCtl1.RID = GuestCtl1.ID <]*/
		uasm_i_ext(&p, T1, T0, MIPS_GCTL1_ID_SHIFT,
			   MIPS_GCTL1_ID_WIDTH);
		uasm_i_ins(&p, T0, T1, MIPS_GCTL1_RID_SHIFT,
			   MIPS_GCTL1_RID_WIDTH);
		uasm_i_mtc0(&p, T0, C0_GUESTCTL1);

		/*[> GuestID handles dealiasing so we don't need to touch ASID <]*/
		/*goto skip_asid_restore;*/
	}
#endif

	/* Root ASID Dealias (RAD) */

	/* Save host ASID */
	UASM_i_MFC0(&p, K0, C0_ENTRYHI);
	UASM_i_SW(&p, K0, offsetof(struct kvm_vcpu_arch, host_entryhi),
		  K1);
	goto skip_asid_restore;
#ifndef CONFIG_CPU_LOONGSON3
	/* Set the root ASID for the Guest */
	UASM_i_ADDIU(&p, T1, S0,
		     offsetof(struct kvm, arch.gpa_mm.context.asid));
#endif
#else
	/* Set the ASID for the Guest Kernel or User */
	UASM_i_LW(&p, T0, offsetof(struct kvm_vcpu_arch, cop0), K1);
	UASM_i_LW(&p, T0, offsetof(struct mips_coproc, reg[MIPS_CP0_STATUS][0]),
		  T0);
	uasm_i_andi(&p, T0, T0, KSU_USER | ST0_ERL | ST0_EXL);
	uasm_i_xori(&p, T0, T0, KSU_USER);
	uasm_il_bnez(&p, &r, T0, label_kernel_asid);
	UASM_i_ADDIU(&p, T1, K1, offsetof(struct kvm_vcpu_arch,
					   guest_kernel_mm.context.asid));
	/* else user */
	UASM_i_ADDIU(&p, T1, K1, offsetof(struct kvm_vcpu_arch,
					  guest_user_mm.context.asid));
	uasm_l_kernel_asid(&l, p);
#endif

#ifndef CONFIG_CPU_LOONGSON3
	/* t1: contains the base of the ASID array, need to get the cpu id  */
	/* smp_processor_id */
	uasm_i_lw(&p, T2, offsetof(struct thread_info, cpu), GP);
	/* index the ASID array */
	uasm_i_sll(&p, T2, T2, ilog2(sizeof(long)));
	UASM_i_ADDU(&p, T3, T1, T2);
	UASM_i_LW(&p, K0, 0, T3);
#endif
#ifdef CONFIG_MIPS_ASID_BITS_VARIABLE
	/*
	 * reuse ASID array offset
	 * cpuinfo_mips is a multiple of sizeof(long)
	 */
	uasm_i_addiu(&p, T3, ZERO, sizeof(struct cpuinfo_mips)/sizeof(long));
	uasm_i_mul(&p, T2, T2, T3);

	UASM_i_LA_mostly(&p, AT, (long)&cpu_data[0].asid_mask);
	UASM_i_ADDU(&p, AT, AT, T2);
	UASM_i_LW(&p, T2, uasm_rel_lo((long)&cpu_data[0].asid_mask), AT);
	uasm_i_and(&p, K0, K0, T2);
#else
#ifndef CONFIG_CPU_LOONGSON3
	uasm_i_andi(&p, K0, K0, MIPS_ENTRYHI_ASID);
#endif
#endif

#ifndef CONFIG_KVM_MIPS_VZ
	/*
	 * Set up KVM T&E GVA pgd.
	 * This does roughly the same as TLBMISS_HANDLER_SETUP_PGD():
	 * - call tlbmiss_handler_setup_pgd(mm->pgd)
	 * - but skips write into CP0_PWBase for now
	 */
	UASM_i_LW(&p, A0, (int)offsetof(struct mm_struct, pgd) -
			  (int)offsetof(struct mm_struct, context.asid), T1);

	UASM_i_LA(&p, T9, (unsigned long)tlbmiss_handler_setup_pgd);
	uasm_i_jalr(&p, RA, T9);
	UASM_i_MTC0(&p, K0, C0_ENTRYHI);
#else
#ifndef CONFIG_CPU_LOONGSON3
	/* Set up KVM VZ root ASID (!guestid) */
//	uasm_i_mtc0(&p, K0, C0_ENTRYHI);
	UASM_i_MTC0(&p, K0, C0_ENTRYHI);
#endif
skip_asid_restore:
#endif
	uasm_i_ehb(&p);

#ifndef CONFIG_CPU_LOONGSON3
	/* Disable RDHWR access */
	uasm_i_mtc0(&p, ZERO, C0_HWRENA);
#endif
#ifdef CONFIG_CPU_LOONGSON3
	/* Restore guest fpu */
	UASM_i_ADDIU(&p, AT, ZERO, 1);
	uasm_i_mfc0(&p, T0, C0_STATUS);
	uasm_i_ins(&p, T0, AT, 29, 1);
	uasm_i_ins(&p, T0, AT, 26, 1);
	uasm_i_mtc0(&p, T0, C0_STATUS);
	uasm_i_move(&p, A0, K1);

	UASM_i_LA(&p, T9, (unsigned long)__kvm_restore_fpu);
	uasm_i_jalr(&p, RA, T9);
	uasm_i_nop(&p);

	//Flush ITLB to workaround read wrong root.entryhi.asid bug
	uasm_i_ori(&p, A1, ZERO, 1);
	uasm_i_mfc0(&p, A0, C0_DIAG);
	uasm_i_ins(&p, A0, A1, LS_ITLB_SHIFT, 1);
	uasm_i_mtc0(&p, A0, C0_DIAG);
#endif

	/* load the guest context from VCPU and return */
	for (i = 1; i < 32; ++i) {
		/* Guest k0/k1 loaded later */
		if (i == K0 || i == K1)
			continue;
		UASM_i_LW(&p, i, offsetof(struct kvm_vcpu_arch, gprs[i]), K1);
	}

#ifndef CONFIG_CPU_MIPSR6
	/* Restore hi/lo */
	UASM_i_LW(&p, K0, offsetof(struct kvm_vcpu_arch, hi), K1);
	uasm_i_mthi(&p, K0);

	UASM_i_LW(&p, K0, offsetof(struct kvm_vcpu_arch, lo), K1);
	uasm_i_mtlo(&p, K0);
#endif
/*******************************************************/
//make sure kernel entry addr 0x80aec1c0 entryHI OK
#if 0
	uasm_i_lui(&p, K0, 0x5);
	uasm_i_mtc0(&p, K0, C0_DIAG);

	uasm_i_lui(&p, K0, 0xc000);
	uasm_i_ori(&p, K0, K0, 0xffff);
	uasm_i_dsll(&p, K0, K0, 16);
	uasm_i_ori(&p, K0, K0, 0x80ae);
	uasm_i_dsll(&p, K0, K0, 16);
	uasm_i_ori(&p, K0, K0, 0xc000);
	UASM_i_MTC0(&p, ZERO, C0_ENTRYLO0);
	UASM_i_MTC0(&p, ZERO, C0_ENTRYLO1);
	UASM_i_MTC0(&p, K0, C0_ENTRYHI);
	uasm_i_tlbwr(&p);

	uasm_i_lui(&p, K0, 0x1);
	uasm_i_mtc0(&p, K0, C0_DIAG);
#endif
/*******************************************************/

	/* Restore the guest's k0/k1 registers */
	UASM_i_LW(&p, K0, offsetof(struct kvm_vcpu_arch, gprs[K0]), K1);
	UASM_i_LW(&p, K1, offsetof(struct kvm_vcpu_arch, gprs[K1]), K1);

	/* Jump to guest */
	uasm_i_eret(&p);

	uasm_resolve_relocs(relocs, labels);

	return p;
}

#if 0
void loongson_vz_exception(void)
{
	/*the real process is:
	check the GVA->GPA trans is exist in table which stored in root
	if no exist, if the GVA is KSEG0/1/XPHY,do the trans directly in root,
	update the table,update tlb with null entrylo0/1,eret
	(??? the following maybe should be processed in tlb invalid 
	get the GPA->HPA trans; if GVA not in KSEG0/1/XPHY,
	return to guest tlbmiss process and tlb invalid process to allocate GPA,
	then update tlb)
	*/
	//the following is a test code
	__asm__ volatile(
	".set	push\n"
	".set	noreorder\n"
	"dmfc0	$26,$14,0\n"
	"dsrl	$26,15\n"
	"dsll	$26,15\n"
	"dmtc0	$26,$14,0\n"

	"mfc0	$26,$12,6\n"
	"lui	$27,0x7010\n"
	"or	$26,$27\n"
	"mtc0	$26,$12,6\n"
	
	"dmfc0	$26,$10,0\n"
	"dsrl	$4,$26,13\n"
	"andi	$5,$26,0xff\n"
	"li	$6,0x6000\n"
	"li	$13,5\n"
	"li	$27,0\n"
	"1:\n"
	"li	$26,0\n"
	"bne	$27,$26,2f\n"
	"nop\n"
	"daddiu	$26,$4,0\n"
	"dli	$12,0x441b\n"
	"dli	$14,0x451b\n"
	"b	6f\n"
	"li	$15,0\n"
	"2:\n"
	"li	$26,1\n"
	"bne	$27,$26,3f\n"
	"nop\n"
	"daddiu	$26,$4,4\n"
	"dli	$12,0x800000000000461b\n"
	"dli	$14,0x800000000000471b\n"
	"b	6f\n"
	"li	$15,1\n"
	"3:\n"
	"li	$26,2\n"
	"bne	$27,$26,4f\n"
	"nop\n"
	"daddiu	$26,$4,8\n"
	"dli	$12,0x400000000000481b\n"
	"dli	$14,0x400000000000491b\n"
	"b	6f\n"
	"li	$15,2\n"
	"4:\n"
	"li	$26,3\n"
	"bne	$27,$26,5f\n"
	"nop\n"
	"daddiu	$26,$4,0xc\n"
	"dli	$12,0x4a1b\n"
	"dli	$14,0x4b1b\n"
	"b	6f\n"
	"li	$15,3\n"
	"5:\n"
	"li	$26,4\n"
	"bne	$27,$26,6f\n"
	"nop\n"
	"daddiu	$26,$4,0x10\n"
	"dli	$12,0x4c19\n"
	"dli	$14,0x4d19\n"
	"b	6f\n"
	"li	$15,4\n"
	"6:\n"
	"dsll	$26,$26,13\n"
	"or	$26,$5\n"
	"dmtc0	$26,$10,0\n"
	"dmtc0	$12,$2,0\n"
	"dmtc0	$14,$3,0\n"
	"mtc0	$5,$5,0\n"
	"mtc0	$15,$0,0\n"
	"tlbwi\n"
	"addiu	$27,1\n"
	"bne	$27,$13,1b\n"
	"nop\n"
	".set	pop\n"
	:::
	);
}

/*write for test exception trigger*/
void loongson_vz_general_exc(void)
{
	/*this handler process the guest TLB relate exception
	 in root context,including IS/VMMMU/VMTLBL/VMTLBS/VMTLBM/VMTLBRI/VMTLBXI
	after the guest tlb miss handled in root, maybe the tlb entrylo0/1 is 0,
	if lo0/1 is 0,will trigger this handler;so if GVA in KSEG0/1, process the
	GPA->HPA trans,fill the table and update tlb then we got the total GVA->HPA trans
	*/
	__asm__ volatile (
	".set	push\n"
	".set	noreorder\n"
	"mfc0	$26, $22, 1\n"
	"srl	$26, 2\n"
	"andi	$26, 0x1f\n"
	//VMTLBXI
	"li	$27, 0x6\n"
	"bne	$26, $27, 1f\n"
	"nop\n"
	"dli	$27, 0xbfffffffffffffff\n"
	"b	7f\n"
	"li	$12, 2\n"

	//VMTLBRI
	"1:\n"
	"li	$27, 0x5\n"
	"bne	$26, $27, 2f\n"
	"nop\n"
	"dli	$27, 0x7fffffffffffffff\n"
	"b	7f\n"
	"li	$12, 1\n"

	//VMTLBM
	"2:\n"
	"li	$27, 0x4\n"
	"bne	$26, $27, 3f\n"
	"nop\n"
	"dli	$27, 0x4\n"
	"b	8f\n"
	"li	$12, 3\n"

	//VMTLBS
	"3:\n"
	"li	$27, 0x3\n"
	"bne	$26, $27, 4f\n"
	"nop\n"
	"dli	$27, 0x4\n"
	"b	8f\n"
	"li	$12, 4\n"
	
	//VMTLBL
	"4:\n"
	"li	$27, 0x2\n"
	"bne	$26, $27, 5f\n"
	"nop\n"
	"li	$27, 0x2\n"
	"b	8f\n"
	"li	$12, 4\n"	
	
	//VMMMU
	"5:\n"
	"li	$27, 0x1\n"
	"bne	$26, $27, 6f\n"
	"nop\n"

	"7:\n"
	"mtc0	$12, $0, 0\n"
	"tlbr\n"
	"dmfc0	$26, $2, 0\n"
	"and	$26, $27\n"
	"dmtc0	$26, $2, 0\n"
	"dmfc0	$26, $3, 0\n"
	"and	$26, $27\n"
	"dmtc0	$26, $3, 0\n"
	"tlbwi\n"
	"b	6f\n"
	"nop\n"

	"8:\n"
	"mtc0	$12, $0, 0\n"
	"tlbr\n"
	"dmfc0	$26, $2, 0\n"
	"or	$26, $27\n"
	"dmtc0	$26, $2, 0\n"
	"dmfc0	$26, $3, 0\n"
	"or	$26, $27\n"
	"dmtc0	$26, $3, 0\n"
	"tlbwi\n"
	
	"6:\n"
	"eret\n"
	".set	pop\n"
	:::
	);
}
#endif

/**
 * kvm_mips_build_tlb_refill_exception() - Assemble TLB refill handler.
 * @addr:	Address to start writing code.
 * @handler:	Address of common handler (within range of @addr).
 *
 * Assemble TLB refill exception fast path handler for guest execution.
 *
 * Returns:	Next address after end of written function.
 */
void *kvm_mips_build_tlb_refill_exception(void *addr, void *handler)
{
	u32 *p = addr;
	struct uasm_label labels[2];
	struct uasm_reloc relocs[2];
//	struct uasm_label *l = labels;
//	struct uasm_reloc *r = relocs;
	unsigned long refill_target = (unsigned long)addr + 0x3b80;
	unsigned int high = refill_target >> 32;
	unsigned int low = (unsigned int)refill_target;
	unsigned int lui_inst = 0x3c1a0000;

	memset(labels, 0, sizeof(labels));
	memset(relocs, 0, sizeof(relocs));

	/* Save guest k1 into scratch register */
	UASM_i_MTC0(&p, K1, scratch_tmp[0], scratch_tmp[1]);
	UASM_i_MFC0(&p, K1, scratch_vcpu[0], scratch_vcpu[1]);
	UASM_i_SW(&p, K0, offsetof(struct kvm_vcpu, arch.gprs[K0]), K1);

	*p = lui_inst | (high >> 16);
	p++;
	uasm_i_ori(&p, K0, K0, high & 0xffff);
	uasm_i_dsll(&p, K0, K0, 16);
	uasm_i_ori(&p, K0, K0, low >> 16);
	uasm_i_dsll(&p, K0, K0, 16);
	uasm_i_ori(&p, K0, K0, low & 0xffff);
	uasm_i_jr(&p, K0);
	uasm_i_nop(&p);

	return p;
}

/**
 * kvm_mips_build_tlb_refill_target() - Assemble TLB refill handler.
 * @addr:	Address to start writing code.
 * @handler:	Address of common handler (within range of @addr).
 *
 * Assemble TLB refill exception fast path handler for guest execution.
 *
 * Returns:	Next address after end of written function.
 */
void *kvm_mips_build_tlb_refill_target(void *addr, void *handler)
{
	u32 *p = addr;
	struct uasm_label labels[10];
	struct uasm_reloc relocs[10];
	struct uasm_label *l = labels;
	struct uasm_reloc *r = relocs;

	memset(labels, 0, sizeof(labels));
	memset(relocs, 0, sizeof(relocs));

#if 1
	/*
	 * Some of the common tlbex code uses current_cpu_type(). For KVM we
	 * assume symmetry and just disable preemption to silence the warning.
	 */
	preempt_disable();

#if 1 //Debug for ASID
	/* Save guest A0,root.entryhi into VCPU structure */
	UASM_i_SW(&p, A0, offsetof(struct kvm_vcpu, arch.gprs[A0]), K1);
	UASM_i_SW(&p, A1, offsetof(struct kvm_vcpu, arch.gprs[A1]), K1);
	UASM_i_SW(&p, A2, offsetof(struct kvm_vcpu, arch.gprs[A2]), K1);
	UASM_i_SW(&p, A3, offsetof(struct kvm_vcpu, arch.gprs[A3]), K1);

	/* Is badvaddr userspace or kernel mapped */
	UASM_i_MFC0(&p, K0, C0_BADVADDR);

	uasm_i_lui(&p, A0, 0xc000);
	uasm_i_sltu(&p, A0, K0, A0);
	/* A0 == 0 means (badvaddr >= 0xffffffffc0000000) */
	uasm_il_beqz(&p, &r, A0, label_mapped);
	uasm_i_nop(&p);

	uasm_i_lui(&p, A0, 0x8000);
	uasm_i_sltu(&p, A0, K0, A0);
	/* A0 == 0 means (badvaddr >= 0xffffffff80000000) */
	uasm_il_beqz(&p, &r, A0, label_not_mapped);
	uasm_i_nop(&p);

	UASM_i_ADDIU(&p, A1, ZERO, 0xc000);
	uasm_i_dsll32(&p, A1, A1, 16);
	uasm_i_sltu(&p, A1, K0, A1);
	uasm_i_xori(&p, A1, A1, 1);
	/* A1 == 1 means (badvaddr >= 0xc000000000000000) */
	uasm_il_bnez(&p, &r, A1, label_mapped);
	uasm_i_nop(&p);

	/* Is badvaddr userspace */
	UASM_i_ADDIU(&p, A1, ZERO, 0x4000);
	uasm_i_dsll32(&p, A1, A1, 16);
	uasm_i_sltu(&p, A1, K0, A1);
	/* A1 == 1 means (badvaddr < 0x4000000000000000) */
	uasm_il_bnez(&p, &r, A1, label_mapped);
	uasm_i_nop(&p);

	uasm_l_not_mapped(&l, p);

#if 0

	/* Get guest ASID */
	UASM_i_MFGC0(&p, A0, MIPS_CP0_TLB_HI, 0);
	uasm_i_dsrl(&p, K0, K0, 8);
	uasm_i_dsll(&p, K0, K0, 8);
	uasm_i_or(&p, K0, K0, A0);
	UASM_i_MTC0(&p, K0, C0_ENTRYHI);
#endif
#endif

#ifndef CONFIG_CPU_LOONGSON3
	/*Store the guest pgd into PWBASE*/
	UASM_i_LW(&p, K0, (int)offsetof(struct kvm_vcpu, kvm), K1);
	UASM_i_LW(&p, K0, offsetof(struct kvm, arch.gpa_mm.pgd), K0);
	if (cpu_has_ldpte)
		UASM_i_MTC0(&p, K0, C0_PWBASE);

	/*
	 * Now for the actual refill bit. A lot of this can be common with the
	 * Linux TLB refill handler, however we don't need to handle so many
	 * cases. We only need to handle user mode refills, and user mode runs
	 * with 32-bit addressing.
	 *
	 * Therefore the branch to label_vmalloc generated by build_get_pmde64()
	 * that isn't resolved should never actually get taken and is harmless
	 * to leave in place for now.
	 */

#ifdef CONFIG_64BIT
	build_get_pmde64(&p, &l, &r, K0, K1); /* get pmd in K1 */
#else
	build_get_pgde32(&p, K0, K1); /* get pgd in K1 */
#endif

	/* we don't support huge pages yet */

	build_get_ptep(&p, K0, K1);
	build_update_entries(&p, K0, K1);
	build_tlb_write_entry(&p, &l, &r, tlb_random);
#else
	UASM_i_MFC0(&p, K0, C0_BADVADDR);

	uasm_i_lui(&p, A0, 0x8000);
	uasm_i_sltu(&p, A0, K0, A0);
	/* A0 == 0 means (badvaddr >= 0xffffffff80000000) */
	uasm_il_beqz(&p, &r, A0, label_get_gpa);
	uasm_i_nop(&p);
	/* The address is 0x9xxxxxxxxxxxxxxx, we only do rough
	 * distinction, maybe there is mmio address, caution!!!!
	*/
	UASM_i_LA(&p, A0, (unsigned long)0x0000ffffffffffff);
	uasm_i_and(&p, K0, K0, A0);

	uasm_il_b(&p, &r, label_get_hpa);
	uasm_i_nop(&p);

	// The address is 0xffffffff8xxxxxxx

	uasm_l_get_gpa(&l, p);

	UASM_i_LA(&p, A0, 0x1fffffff);
	uasm_i_and(&p, K0, K0, A0);

	uasm_l_get_hpa(&l, p);
	//start the find process in gpa_mm.pgd

	uasm_i_move(&p, A0, K0);
	/* Use gpa_mm.pgd directly for pagetable lookup */
	UASM_i_LW(&p, K1, (int)offsetof(struct kvm_vcpu, kvm), K1);
	UASM_i_LW(&p, K1, offsetof(struct kvm, arch.gpa_mm.pgd), K1);
	uasm_i_dsrl32(&p, A0, A0, 1);
	uasm_i_andi(&p, A0, A0, 0x7ff8); //if set PGD_ORDER=1
	UASM_i_ADDU(&p, K1, K1, A0);
	UASM_i_LW(&p, K1, 0, K1);
	UASM_i_SRL(&p, A0, K0, 0x16);
	uasm_i_andi(&p, A0, A0, 0x3ff8);
	UASM_i_ADDU(&p, K1, K1, A0);
	UASM_i_LW(&p, K1, 0, K1); //get pmd offset
	UASM_i_SRL(&p, A0, K0, 0xb);
	uasm_i_andi(&p, A0, A0, 0x3ff0);
	UASM_i_ADDU(&p, K1, K1, A0);
	UASM_i_LW(&p, K0, 0, K1); //get pmd offset
	UASM_i_LW(&p, K1, 8, K1); //get pmd offset
	uasm_i_drotr(&p, K0, K0, 0xa);
	uasm_i_ori(&p, K0, K0, 1); //make G=1
	UASM_i_MTC0(&p, K0, C0_ENTRYLO0);
	uasm_i_drotr(&p, K1, K1, 0xa);
	uasm_i_ori(&p, K1, K1, 1); //make G=1
	UASM_i_MTC0(&p, K1, C0_ENTRYLO1);
#ifdef LSVZ_TLB_ISOLATE_DEBUG
	uasm_i_mfc0(&p, A0, C0_INDEX);
	UASM_i_LA(&p, A1, (unsigned long)&guest_vtlb_index);
	uasm_i_lw(&p, A2, 0, A1);
	uasm_i_mtc0(&p, A2, C0_INDEX);
	uasm_i_ehb(&p);
	uasm_i_tlbwi(&p);
	uasm_i_mtc0(&p, A0, C0_INDEX);
	uasm_i_addiu(&p, A2, A2, 1);
	uasm_i_andi(&p, A2, A2, 0x3f);
	uasm_i_sw(&p, A2, 0, A1);
#else
	uasm_i_ehb(&p);
	uasm_i_tlbwr(&p);
#endif
#endif
	uasm_il_b(&p, &r, label_refill_exit);
	uasm_i_nop(&p);

	uasm_l_mapped(&l, p);

	UASM_i_MFC0(&p, A0, C0_EPC);
	UASM_i_MTGC0(&p, A0, C0_EPC);
	UASM_i_MFC0(&p, A0, C0_BADVADDR);
	UASM_i_MTGC0(&p, A0, C0_BADVADDR);

	UASM_i_MFGC0(&p, A0, C0_EBASE);
	UASM_i_ADDIU(&p, A2, ZERO, 0x200);
	uasm_i_ins(&p, A0, A2, 0, 12);

	/* Set Guest EPC */
	UASM_i_MTC0(&p, A0, C0_EPC);

	uasm_i_mfgc0(&p, A0, C0_STATUS);
	uasm_i_ori(&p, A0, A0, ST0_EXL);
	uasm_i_mtgc0(&p, A0, C0_STATUS);

	uasm_i_mfc0(&p, A0, C0_GSCAUSE);
	uasm_i_ext(&p, A1, A0, 2, 5);
	uasm_i_mfgc0(&p, A2, C0_COUNT);
	uasm_i_mfgc0(&p, A0, C0_CAUSE);
	uasm_i_ins(&p, A0, A1, 2, 5);
	uasm_i_mtgc0(&p, A0, C0_CAUSE);
	uasm_i_mfgc0(&p, A3, C0_COUNT);
	uasm_i_mfgc0(&p, K0, C0_COMPARE);

	uasm_i_addiu(&p, K0, K0, -1);
	uasm_i_subu(&p, A3, A3, A2);
	uasm_i_subu(&p, A1, K0, A2);
	uasm_i_sltu(&p, A1, A1, A3);
	uasm_il_beqz(&p, &r, A1, label_no_ti);
	uasm_i_nop(&p);

	uasm_i_lui(&p, A1, CAUSEF_TI>>16);
	uasm_i_or(&p, A0, A0, A1);
	uasm_i_mtgc0(&p, A0, C0_CAUSE);

	uasm_l_no_ti(&l, p);

	uasm_l_refill_exit(&l, p);

	//Flush ITLB/DTLB
	uasm_i_ori(&p, A1, ZERO, 3);
	uasm_i_mfc0(&p, A0, C0_DIAG);
	uasm_i_ins(&p, A0, A1, LS_ITLB_SHIFT, 2);
	uasm_i_mtc0(&p, A0, C0_DIAG);

#if 1 //Debug for ASID
	/* Restore Root.entryhi, Guest A0 from VCPU structure */
	UASM_i_MFC0(&p, K1, scratch_vcpu[0], scratch_vcpu[1]);
	UASM_i_LW(&p, A0, offsetof(struct kvm_vcpu, arch.gprs[A0]), K1);
	UASM_i_LW(&p, A1, offsetof(struct kvm_vcpu, arch.gprs[A1]), K1);
	UASM_i_LW(&p, A2, offsetof(struct kvm_vcpu, arch.gprs[A2]), K1);
	UASM_i_LW(&p, A3, offsetof(struct kvm_vcpu, arch.gprs[A3]), K1);
#endif

	preempt_enable();

	/* Get the VCPU pointer from the VCPU scratch register again */
	UASM_i_MFC0(&p, K1, scratch_vcpu[0], scratch_vcpu[1]);

	/* Restore the guest's k0/k1 registers */
	UASM_i_LW(&p, K0, offsetof(struct kvm_vcpu, arch.gprs[K0]), K1);
	uasm_i_ehb(&p);
	UASM_i_MFC0(&p, K1, scratch_tmp[0], scratch_tmp[1]);
#endif
	/* Jump to guest */
	uasm_i_eret(&p);

	uasm_resolve_relocs(relocs, labels);
	return p;
}

/**
 * kvm_mips_build_tlb_general_exception() - Assemble TLB general handler.
 * @addr:	Address to start writing code.
 * @handler:	Address of common handler (within range of @addr).
 *
 * Assemble TLB general exception fast path handler for guest execution.
 *
 * Returns:	Next address after end of written function.
 */
void *kvm_mips_build_tlb_general_exception(void *addr, void *handler)
{
	u32 *p = addr;
	struct uasm_label labels[6];
	struct uasm_reloc relocs[6];
	struct uasm_label *l = labels;
	struct uasm_reloc *r = relocs;
	int i;

	memset(labels, 0, sizeof(labels));
	memset(relocs, 0, sizeof(relocs));

	/* Save guest k1 into scratch register */
	UASM_i_MTC0(&p, K1, scratch_tmp[0], scratch_tmp[1]);

	/* Get the VCPU pointer from the VCPU scratch register */
	UASM_i_MFC0(&p, K1, scratch_vcpu[0], scratch_vcpu[1]);
	UASM_i_ADDIU(&p, K1, K1, offsetof(struct kvm_vcpu, arch));

	/* Save guest k0 into VCPU structure */
	UASM_i_SW(&p, K0, offsetof(struct kvm_vcpu_arch, gprs[K0]), K1);

	/* Start saving Guest context to VCPU */
	for (i = 0; i < 32; ++i) {
		/* Guest k0/k1 saved later */
		if (i == K0 || i == K1)
			continue;
		UASM_i_SW(&p, i, offsetof(struct kvm_vcpu_arch, gprs[i]), K1);
	}


#ifndef CONFIG_CPU_MIPSR6
	/* We need to save hi/lo and restore them on the way out */
	uasm_i_mfhi(&p, T0);
	UASM_i_SW(&p, T0, offsetof(struct kvm_vcpu_arch, hi), K1);

	uasm_i_mflo(&p, T0);
	UASM_i_SW(&p, T0, offsetof(struct kvm_vcpu_arch, lo), K1);
#endif

	/* Finally save guest k1 to VCPU */
	uasm_i_ehb(&p);
	UASM_i_MFC0(&p, T0, scratch_tmp[0], scratch_tmp[1]);
	UASM_i_SW(&p, T0, offsetof(struct kvm_vcpu_arch, gprs[K1]), K1);

	/* Now that context has been saved, we can use other registers */

	/* Restore vcpu */
	UASM_i_MFC0(&p, S1, scratch_vcpu[0], scratch_vcpu[1]);

	/* Restore run (vcpu->run) */
	UASM_i_LW(&p, S0, offsetof(struct kvm_vcpu, run), S1);

	/*
	 * Save Host level EPC, BadVaddr and Cause to VCPU, useful to process
	 * the exception
	 */
	UASM_i_MFC0(&p, K0, C0_EPC);
	UASM_i_SW(&p, K0, offsetof(struct kvm_vcpu_arch, pc), K1);

	UASM_i_MFC0(&p, K0, C0_BADVADDR);
	UASM_i_SW(&p, K0, offsetof(struct kvm_vcpu_arch, host_cp0_badvaddr),
		  K1);

	uasm_i_mfc0(&p, K0, C0_GSCAUSE);
	uasm_i_sw(&p, K0, offsetof(struct kvm_vcpu_arch, host_cp0_gscause), K1);

	uasm_i_mfc0(&p, K0, C0_CAUSE);
	uasm_i_sw(&p, K0, offsetof(struct kvm_vcpu_arch, host_cp0_cause), K1);
#if 1
	uasm_i_mfgc0(&p, K0, C0_CAUSE);
	UASM_i_LW(&p, V0, offsetof(struct kvm_vcpu_arch, cop0), K1);
	uasm_i_sw(&p, K0, offsetof(struct mips_coproc,
			reg[MIPS_CP0_CAUSE][0]), V0);
	UASM_i_MFGC0(&p, K0, C0_ENTRYHI);
	UASM_i_SW(&p, K0, offsetof(struct mips_coproc,
			reg[MIPS_CP0_TLB_HI][0]), V0);
#endif
#if 0
	if (cpu_has_badinstr) {
		uasm_i_mfc0(&p, K0, C0_BADINSTR);
		uasm_i_sw(&p, K0, offsetof(struct kvm_vcpu_arch,
					   host_cp0_badinstr), K1);
	}

	if (cpu_has_badinstrp) {
		uasm_i_mfc0(&p, K0, C0_BADINSTRP);
		uasm_i_sw(&p, K0, offsetof(struct kvm_vcpu_arch,
					   host_cp0_badinstrp), K1);
	}
#endif
	/* Now restore the host state just enough to run the handlers */

	/* Switch EBASE to the one used by Linux */
	/* load up the host EBASE */
	uasm_i_mfc0(&p, V0, C0_STATUS);

#if 0
	uasm_i_lui(&p, AT, ST0_BEV >> 16);
	uasm_i_or(&p, K0, V0, AT);

	uasm_i_mtc0(&p, K0, C0_STATUS);
	uasm_i_ehb(&p);
#endif

	UASM_i_LA_mostly(&p, K0, (long)&ebase);
	UASM_i_LW(&p, K0, uasm_rel_lo((long)&ebase), K0);
	build_set_exc_base(&p, K0);

	if (raw_cpu_has_fpu) {
		/*
		 * If FPU is enabled, save FCR31 and clear it so that later
		 * ctc1's don't trigger FPE for pending exceptions.
		 */
		uasm_i_lui(&p, AT, ST0_CU1 >> 16);
		uasm_i_and(&p, V1, V0, AT);
		uasm_il_beqz(&p, &r, V1, label_fpu_1);
		 uasm_i_nop(&p);
		uasm_i_cfc1(&p, T0, 31);
		uasm_i_sw(&p, T0, offsetof(struct kvm_vcpu_arch, fpu.fcr31),
			  K1);
		uasm_i_ctc1(&p, ZERO, 31);
		uasm_l_fpu_1(&l, p);
#ifdef CONFIG_CPU_LOONGSON3
	/* Save guest fpu */
	UASM_i_ADDIU(&p, AT, ZERO, 1);
	uasm_i_mfc0(&p, T0, C0_STATUS);
	uasm_i_ins(&p, T0, AT, 29, 1); //SET ST0_CU1
	uasm_i_ins(&p, T0, AT, 26, 1); //SET ST0_FR
	uasm_i_mtc0(&p, T0, C0_STATUS);

	uasm_i_move(&p, A0, K1);
	UASM_i_LA(&p, T9, (unsigned long)__kvm_save_fpu);
	uasm_i_jalr(&p, RA, T9);
	uasm_i_nop(&p);
#endif

	}

#if 0
	if (cpu_has_msa) {
		/*
		 * If MSA is enabled, save MSACSR and clear it so that later
		 * instructions don't trigger MSAFPE for pending exceptions.
		 */
		uasm_i_mfc0(&p, T0, C0_CONFIG5);
		uasm_i_ext(&p, T0, T0, 27, 1); /*[> MIPS_CONF5_MSAEN <]*/
		uasm_il_beqz(&p, &r, T0, label_msa_1);
		uasm_i_nop(&p);
		uasm_i_cfcmsa(&p, T0, MSA_CSR);
		uasm_i_sw(&p, T0, offsetof(struct kvm_vcpu_arch, fpu.msacsr),
			  K1);
		uasm_i_ctcmsa(&p, MSA_CSR, ZERO);
		uasm_l_msa_1(&l, p);
	}
#endif

#ifdef CONFIG_KVM_MIPS_VZ
#if 0
	/* Restore host ASID */
	if (!cpu_has_guestid) {
		UASM_i_LW(&p, K0, offsetof(struct kvm_vcpu_arch, host_entryhi),
			  K1);
		UASM_i_MTC0(&p, K0, C0_ENTRYHI);
	}
#endif
	UASM_i_MFC0(&p, K0, C0_PAGEMASK);
	UASM_i_SW(&p, K0, offsetof(struct kvm_vcpu_arch, guest_pagemask),
		  K1);
	UASM_i_LW(&p, K0, offsetof(struct kvm_vcpu_arch, host_entryhi),
		  K1);
	UASM_i_MTC0(&p, K0, C0_ENTRYHI);
	uasm_i_ehb(&p);

#ifdef CONFIG_CPU_LOONGSON3
	/* Clear DIAG.MID t0 get root.PWBASE*/
	uasm_i_mfc0(&p, A0, C0_DIAG);
	uasm_i_ins(&p, A0, ZERO, LS_MID_SHIFT, 2);
	uasm_i_mtc0(&p, A0, C0_DIAG);
#endif

	/*
	 * Set up normal Linux process pgd.
	 * This does roughly the same as TLBMISS_HANDLER_SETUP_PGD():
	 * - call tlbmiss_handler_setup_pgd(mm->pgd)
	 * - write mm->pgd into CP0_PWBase
	 */
	UASM_i_LW(&p, A0,
		  offsetof(struct kvm_vcpu_arch, host_pgd), K1);
#if 0
	UASM_i_LA(&p, T9, (unsigned long)tlbmiss_handler_setup_pgd);
	uasm_i_jalr(&p, RA, T9);
	/* delay slot */
	if (cpu_has_htw)
		UASM_i_MTC0(&p, A0, C0_PWBASE);
	else
		uasm_i_nop(&p);
#else
	UASM_i_MTC0(&p, A0, C0_PWBASE);
	uasm_i_ehb(&p);
#endif

	/* Clear GM bit so we don't enter guest mode when EXL is cleared */
	uasm_i_mfc0(&p, K0, C0_GUESTCTL0);
	uasm_i_ins(&p, K0, ZERO, MIPS_GCTL0_GM_SHIFT, 1);
	uasm_i_mtc0(&p, K0, C0_GUESTCTL0);

	/* Save GuestCtl0 so we can access GExcCode after CPU migration */
	uasm_i_sw(&p, K0,
		  offsetof(struct kvm_vcpu_arch, host_cp0_guestctl0), K1);

#if 0
	if (cpu_has_guestid) {
		/*
		 * Clear root mode GuestID, so that root TLB operations use the
		 * root GuestID in the root TLB.
		 */
		uasm_i_mfc0(&p, T0, C0_GUESTCTL1);
		/*[> Set GuestCtl1.RID = MIPS_GCTL1_ROOT_GUESTID (i.e. 0) <]*/
		uasm_i_ins(&p, T0, ZERO, MIPS_GCTL1_RID_SHIFT,
			   MIPS_GCTL1_RID_WIDTH);
		uasm_i_mtc0(&p, T0, C0_GUESTCTL1);
	}
#endif
#endif

	/* Now that the new EBASE has been loaded, unset BEV and KSU_USER */
	UASM_i_ADDIU(&p, AT, ZERO, ~(ST0_EXL | KSU_USER | ST0_IE));
	uasm_i_and(&p, V0, V0, AT);
	uasm_i_lui(&p, AT, ST0_CU0 >> 16);
	uasm_i_or(&p, V0, V0, AT);
#ifdef CONFIG_64BIT
	uasm_i_ori(&p, V0, V0, ST0_SX | ST0_UX);
#endif
	uasm_i_mtc0(&p, V0, C0_STATUS);
	uasm_i_ehb(&p);

	/* Load up host GP */
	UASM_i_LW(&p, GP, offsetof(struct kvm_vcpu_arch, host_gp), K1);

	/* Need a stack before we can jump to "C" */
	UASM_i_LW(&p, SP, offsetof(struct kvm_vcpu_arch, host_stack), K1);

	/* Saved host state */
	UASM_i_ADDIU(&p, SP, SP, -(int)sizeof(struct pt_regs));

	/*
	 * XXXKYMA do we need to load the host ASID, maybe not because the
	 * kernel entries are marked GLOBAL, need to verify
	 */

	/* Restore host scratch registers, as we'll have clobbered them */
	kvm_mips_build_restore_scratch(&p, K0, SP);

#ifndef CONFIG_CPU_LOONGSON3
	/* Restore RDHWR access */
	UASM_i_LA_mostly(&p, K0, (long)&hwrena);
	uasm_i_lw(&p, K0, uasm_rel_lo((long)&hwrena), K0);
	uasm_i_mtc0(&p, K0, C0_HWRENA);
#endif

	/*If we meet XKSEG/XUSEG address,we ignore the invalid exception
	 * process and jump back to guest_ebase+0x180
	*/
#if 1
//	UASM_i_MFC0(&p, T1, C0_BADVADDR);
	UASM_i_LW(&p, T1, offsetof(struct kvm_vcpu_arch, host_cp0_badvaddr), K1);

	uasm_i_lui(&p, T0, 0xc000);
	uasm_i_sltu(&p, T0, T1, T0);
	/* T0 == 0 means (badvaddr >= 0xffffffffc0000000) */
	uasm_il_beqz(&p, &r, T0, label_ignore_tlb_general);
	uasm_i_nop(&p);

	UASM_i_ADDIU(&p, T0, ZERO, 0xf000);
	uasm_i_dsll32(&p, T0, T0, 16);
	uasm_i_and(&p, T2, T1, T0);

	//Check for XKSEG address
	UASM_i_ADDIU(&p, T0, ZERO, 0xc000);
	uasm_i_dsll32(&p, T0, T0, 16);

	uasm_il_beq(&p, &r, T2, T0, label_ignore_tlb_general);
	uasm_i_nop(&p);

	//Check for XUSEG address
	UASM_i_ADDIU(&p, T0, ZERO, 0x4000);
	uasm_i_dsll32(&p, T0, T0, 16);

	uasm_i_sltu(&p, AT, T1, T0);
	uasm_il_bnez(&p, &r, AT, label_ignore_tlb_general);
	uasm_i_nop(&p);
#endif

	/* Jump to handler */
	/*
	 * XXXKYMA: not sure if this is safe, how large is the stack??
	 * Now jump to the kvm_mips_handle_exit() to see if we can deal
	 * with this in the kernel
	 */
	uasm_i_move(&p, A0, S0);
	uasm_i_move(&p, A1, S1);
/*****************************************************/

#if 0
	/* LSVZ set diag bit[16] [18][19]= 0 */
	uasm_i_mfc0(&p, K0, C0_DIAG);
	uasm_i_ins(&p, K0, ZERO, LS_MODE_SHIFT, 1);
	uasm_i_ins(&p, K0, ZERO, LS_MID_SHIFT, 2);
	uasm_i_mtc0(&p, K0, C0_DIAG);

//	uasm_i_mfc0(&p, V0, C0_STATUS);
//	uasm_i_ori(&p, V0, V0, 0x1f);
//	uasm_i_xori(&p, V0, V0, 0x1e);
//	uasm_i_sync(&p, 0);
//	uasm_i_mtc0(&p, V0, C0_STATUS);
//	uasm_i_sync(&p, 0);

//	uasm_i_b(&p, -4);
//	uasm_i_nop(&p);
#endif
/*****************************************************/
	UASM_i_LA(&p, T9, (unsigned long)handle_tlb_general_exception);
	uasm_i_jalr(&p, RA, T9);
	UASM_i_ADDIU(&p, SP, SP, -CALLFRAME_SIZ);

	p = kvm_mips_build_ret_from_exit(p, 1);

#if 1
	uasm_l_ignore_tlb_general(&l, p);

	uasm_i_move(&p, A0, S0);
	uasm_i_move(&p, A1, S1);

	UASM_i_LA(&p, T9, (unsigned long)handle_ignore_tlb_general_exception);
	uasm_i_jalr(&p, RA, T9);
	UASM_i_ADDIU(&p, SP, SP, -CALLFRAME_SIZ);

	uasm_i_di(&p, ZERO);
	uasm_i_ehb(&p);
	uasm_i_move(&p, K1, S1);
	UASM_i_ADDIU(&p, K1, K1, offsetof(struct kvm_vcpu, arch));

	p = kvm_mips_build_ret_to_guest(p);
#endif

	uasm_resolve_relocs(relocs, labels);

	return p;
}


/**
 * kvm_mips_build_exception() - Assemble first level guest exception handler.
 * @addr:	Address to start writing code.
 * @handler:	Address of common handler (within range of @addr).
 *
 * Assemble exception vector code for guest execution. The generated vector will
 * branch to the common exception handler generated by kvm_mips_build_exit().
 *
 * Returns:	Next address after end of written function.
 */
void *kvm_mips_build_exception(void *addr, void *handler)
{
	u32 *p = addr;
	struct uasm_label labels[2];
	struct uasm_reloc relocs[2];
	struct uasm_label *l = labels;
	struct uasm_reloc *r = relocs;

	memset(labels, 0, sizeof(labels));
	memset(relocs, 0, sizeof(relocs));

	/* Save guest k1 into scratch register */
	UASM_i_MTC0(&p, K1, scratch_tmp[0], scratch_tmp[1]);

	/* Get the VCPU pointer from the VCPU scratch register */
	UASM_i_MFC0(&p, K1, scratch_vcpu[0], scratch_vcpu[1]);
	UASM_i_ADDIU(&p, K1, K1, offsetof(struct kvm_vcpu, arch));

	/* Save guest k0 into VCPU structure */
	UASM_i_SW(&p, K0, offsetof(struct kvm_vcpu_arch, gprs[K0]), K1);

	/* Branch to the common handler */
	uasm_il_b(&p, &r, label_exit_common);
	uasm_i_nop(&p);

	uasm_l_exit_common(&l, handler);
	uasm_resolve_relocs(relocs, labels);

	return p;
}

/**
 * kvm_mips_build_exit() - Assemble common guest exit handler.
 * @addr:	Address to start writing code.
 *
 * Assemble the generic guest exit handling code. This is called by the
 * exception vectors (generated by kvm_mips_build_exception()), and calls
 * kvm_mips_handle_exit(), then either resumes the guest or returns to the host
 * depending on the return value.
 *
 * Returns:	Next address after end of written function.
 */
void *kvm_mips_build_exit(void *addr)
{
	u32 *p = addr;
	unsigned int i;
	struct uasm_label labels[5];
	struct uasm_reloc relocs[5];
	struct uasm_label *l = labels;
	struct uasm_reloc *r = relocs;

	memset(labels, 0, sizeof(labels));
	memset(relocs, 0, sizeof(relocs));

	/*
	 * Generic Guest exception handler. We end up here when the guest
	 * does something that causes a trap to kernel mode.
	 *
	 * Both k0/k1 registers will have already been saved (k0 into the vcpu
	 * structure, and k1 into the scratch_tmp register).
	 *
	 * The k1 register will already contain the kvm_vcpu_arch pointer.
	 */

	/* Start saving Guest context to VCPU */
	for (i = 0; i < 32; ++i) {
		/* Guest k0/k1 saved later */
		if (i == K0 || i == K1)
			continue;
		UASM_i_SW(&p, i, offsetof(struct kvm_vcpu_arch, gprs[i]), K1);
	}


#ifndef CONFIG_CPU_MIPSR6
	/* We need to save hi/lo and restore them on the way out */
	uasm_i_mfhi(&p, T0);
	UASM_i_SW(&p, T0, offsetof(struct kvm_vcpu_arch, hi), K1);

	uasm_i_mflo(&p, T0);
	UASM_i_SW(&p, T0, offsetof(struct kvm_vcpu_arch, lo), K1);
#endif

	/* Finally save guest k1 to VCPU */
	uasm_i_ehb(&p);
	UASM_i_MFC0(&p, T0, scratch_tmp[0], scratch_tmp[1]);
	UASM_i_SW(&p, T0, offsetof(struct kvm_vcpu_arch, gprs[K1]), K1);

	/* Now that context has been saved, we can use other registers */

	/* Restore vcpu */
	UASM_i_MFC0(&p, S1, scratch_vcpu[0], scratch_vcpu[1]);

	/* Restore run (vcpu->run) */
	UASM_i_LW(&p, S0, offsetof(struct kvm_vcpu, run), S1);

	/*
	 * Save Host level EPC, BadVaddr and Cause to VCPU, useful to process
	 * the exception
	 */
	UASM_i_MFC0(&p, K0, C0_EPC);
	UASM_i_SW(&p, K0, offsetof(struct kvm_vcpu_arch, pc), K1);

	UASM_i_MFC0(&p, K0, C0_BADVADDR);
	UASM_i_SW(&p, K0, offsetof(struct kvm_vcpu_arch, host_cp0_badvaddr),
		  K1);

	uasm_i_mfc0(&p, K0, C0_GSCAUSE);
	uasm_i_sw(&p, K0, offsetof(struct kvm_vcpu_arch, host_cp0_gscause), K1);

	uasm_i_mfc0(&p, K0, C0_CAUSE);
	uasm_i_sw(&p, K0, offsetof(struct kvm_vcpu_arch, host_cp0_cause), K1);
#if 1
	uasm_i_mfgc0(&p, K0, C0_CAUSE);
	UASM_i_LW(&p, V0, offsetof(struct kvm_vcpu_arch, cop0), K1);
	uasm_i_sw(&p, K0, offsetof(struct mips_coproc,
			reg[MIPS_CP0_CAUSE][0]), V0);
	UASM_i_MFGC0(&p, K0, C0_ENTRYHI);
	UASM_i_SW(&p, K0, offsetof(struct mips_coproc,
			reg[MIPS_CP0_TLB_HI][0]), V0);
#endif
#if 0
	if (cpu_has_badinstr) {
		uasm_i_mfc0(&p, K0, C0_BADINSTR);
		uasm_i_sw(&p, K0, offsetof(struct kvm_vcpu_arch,
					   host_cp0_badinstr), K1);
	}

	if (cpu_has_badinstrp) {
		uasm_i_mfc0(&p, K0, C0_BADINSTRP);
		uasm_i_sw(&p, K0, offsetof(struct kvm_vcpu_arch,
					   host_cp0_badinstrp), K1);
	}
#endif
	/* Now restore the host state just enough to run the handlers */

	/* Switch EBASE to the one used by Linux */
	/* load up the host EBASE */
	uasm_i_mfc0(&p, V0, C0_STATUS);

#ifndef CONFIG_CPU_LOONGSON3
	uasm_i_lui(&p, AT, ST0_BEV >> 16);
	uasm_i_or(&p, K0, V0, AT);

	uasm_i_mtc0(&p, K0, C0_STATUS);
	uasm_i_ehb(&p);
#endif

	UASM_i_LA_mostly(&p, K0, (long)&ebase);
	UASM_i_LW(&p, K0, uasm_rel_lo((long)&ebase), K0);
	build_set_exc_base(&p, K0);

	if (raw_cpu_has_fpu) {
		/*
		 * If FPU is enabled, save FCR31 and clear it so that later
		 * ctc1's don't trigger FPE for pending exceptions.
		 */
		uasm_i_lui(&p, AT, ST0_CU1 >> 16);
		uasm_i_and(&p, V1, V0, AT);
		uasm_il_beqz(&p, &r, V1, label_fpu_1);
		 uasm_i_nop(&p);
		uasm_i_cfc1(&p, T0, 31);
		uasm_i_sw(&p, T0, offsetof(struct kvm_vcpu_arch, fpu.fcr31),
			  K1);
		uasm_i_ctc1(&p, ZERO, 31);
		uasm_l_fpu_1(&l, p);
#ifdef CONFIG_CPU_LOONGSON3
	/* Save guest fpu */
	UASM_i_ADDIU(&p, AT, ZERO, 1);
	uasm_i_mfc0(&p, T0, C0_STATUS);
	uasm_i_ins(&p, T0, AT, 29, 1); //SET ST0_CU1
	uasm_i_ins(&p, T0, AT, 26, 1); //SET ST0_FR
	uasm_i_mtc0(&p, T0, C0_STATUS);

	uasm_i_move(&p, A0, K1);
	UASM_i_LA(&p, T9, (unsigned long)__kvm_save_fpu);
	uasm_i_jalr(&p, RA, T9);
	uasm_i_nop(&p);
#endif
	}

#if 0
	if (cpu_has_msa) {
		/*
		 * If MSA is enabled, save MSACSR and clear it so that later
		 * instructions don't trigger MSAFPE for pending exceptions.
		 */
		uasm_i_mfc0(&p, T0, C0_CONFIG5);
		uasm_i_ext(&p, T0, T0, 27, 1); /*[> MIPS_CONF5_MSAEN <]*/
		uasm_il_beqz(&p, &r, T0, label_msa_1);
		uasm_i_nop(&p);
		uasm_i_cfcmsa(&p, T0, MSA_CSR);
		uasm_i_sw(&p, T0, offsetof(struct kvm_vcpu_arch, fpu.msacsr),
			  K1);
		uasm_i_ctcmsa(&p, MSA_CSR, ZERO);
		uasm_l_msa_1(&l, p);
	}
#endif

#ifdef CONFIG_KVM_MIPS_VZ
#if 0
	/* Restore host ASID */
	if (!cpu_has_guestid) {
		UASM_i_LW(&p, K0, offsetof(struct kvm_vcpu_arch, host_entryhi),
			  K1);
		UASM_i_MTC0(&p, K0, C0_ENTRYHI);
	}
#endif
	UASM_i_MFC0(&p, K0, C0_PAGEMASK);
	UASM_i_SW(&p, K0, offsetof(struct kvm_vcpu_arch, guest_pagemask),
		  K1);
	UASM_i_LW(&p, K0, offsetof(struct kvm_vcpu_arch, host_entryhi),
		  K1);
	UASM_i_MTC0(&p, K0, C0_ENTRYHI);

#ifdef CONFIG_CPU_LOONGSON3
	/* Clear DIAG.MID t0 get root.PWBASE*/
	uasm_i_mfc0(&p, A0, C0_DIAG);
	uasm_i_ins(&p, A0, ZERO, LS_MID_SHIFT, 2);
	uasm_i_mtc0(&p, A0, C0_DIAG);
#endif

	/*
	 * Set up normal Linux process pgd.
	 * This does roughly the same as TLBMISS_HANDLER_SETUP_PGD():
	 * - call tlbmiss_handler_setup_pgd(mm->pgd)
	 * - write mm->pgd into CP0_PWBase
	 */
	UASM_i_LW(&p, A0,
		  offsetof(struct kvm_vcpu_arch, host_pgd), K1);
#if 0
	UASM_i_LA(&p, T9, (unsigned long)tlbmiss_handler_setup_pgd);
	uasm_i_jalr(&p, RA, T9);
	/* delay slot */
	if (cpu_has_htw)
		UASM_i_MTC0(&p, A0, C0_PWBASE);
	else
		uasm_i_nop(&p);
#else
	UASM_i_MTC0(&p, A0, C0_PWBASE);
	uasm_i_ehb(&p);
#endif

	/* Clear GM bit so we don't enter guest mode when EXL is cleared */
	uasm_i_mfc0(&p, K0, C0_GUESTCTL0);
	uasm_i_ins(&p, K0, ZERO, MIPS_GCTL0_GM_SHIFT, 1);
	uasm_i_mtc0(&p, K0, C0_GUESTCTL0);

	/* Save GuestCtl0 so we can access GExcCode after CPU migration */
	uasm_i_sw(&p, K0,
		  offsetof(struct kvm_vcpu_arch, host_cp0_guestctl0), K1);

#if 0
	if (cpu_has_guestid) {
		/*
		 * Clear root mode GuestID, so that root TLB operations use the
		 * root GuestID in the root TLB.
		 */
		uasm_i_mfc0(&p, T0, C0_GUESTCTL1);
		/*[> Set GuestCtl1.RID = MIPS_GCTL1_ROOT_GUESTID (i.e. 0) <]*/
		uasm_i_ins(&p, T0, ZERO, MIPS_GCTL1_RID_SHIFT,
			   MIPS_GCTL1_RID_WIDTH);
		uasm_i_mtc0(&p, T0, C0_GUESTCTL1);
	}
#endif
#endif

	/* Now that the new EBASE has been loaded, unset BEV and KSU_USER */
	UASM_i_ADDIU(&p, AT, ZERO, ~(ST0_EXL | KSU_USER | ST0_IE));
	uasm_i_and(&p, V0, V0, AT);
	uasm_i_lui(&p, AT, ST0_CU0 >> 16);
	uasm_i_or(&p, V0, V0, AT);
#ifdef CONFIG_64BIT
	uasm_i_ori(&p, V0, V0, ST0_SX | ST0_UX);
#endif
	uasm_i_mtc0(&p, V0, C0_STATUS);
	uasm_i_ehb(&p);

	/* Load up host GP */
	UASM_i_LW(&p, GP, offsetof(struct kvm_vcpu_arch, host_gp), K1);

	/* Need a stack before we can jump to "C" */
	UASM_i_LW(&p, SP, offsetof(struct kvm_vcpu_arch, host_stack), K1);

	/* Saved host state */
	UASM_i_ADDIU(&p, SP, SP, -(int)sizeof(struct pt_regs));

	/*
	 * XXXKYMA do we need to load the host ASID, maybe not because the
	 * kernel entries are marked GLOBAL, need to verify
	 */

	/* Restore host scratch registers, as we'll have clobbered them */
	kvm_mips_build_restore_scratch(&p, K0, SP);

#ifndef CONFIG_CPU_LOONGSON3
	/* Restore RDHWR access */
	UASM_i_LA_mostly(&p, K0, (long)&hwrena);
	uasm_i_lw(&p, K0, uasm_rel_lo((long)&hwrena), K0);
	uasm_i_mtc0(&p, K0, C0_HWRENA);
#endif

	/* Jump to handler */
	/*
	 * XXXKYMA: not sure if this is safe, how large is the stack??
	 * Now jump to the kvm_mips_handle_exit() to see if we can deal
	 * with this in the kernel
	 */
	uasm_i_move(&p, A0, S0);
	uasm_i_move(&p, A1, S1);
	UASM_i_LA(&p, T9, (unsigned long)kvm_mips_handle_exit);
	uasm_i_jalr(&p, RA, T9);
	UASM_i_ADDIU(&p, SP, SP, -CALLFRAME_SIZ);

	uasm_resolve_relocs(relocs, labels);

	p = kvm_mips_build_ret_from_exit(p, 0);

	return p;
}

/**
 * kvm_mips_build_ret_from_exit() - Assemble guest exit return handler.
 * @addr:	Address to start writing code.
 *
 * Assemble the code to handle the return from kvm_mips_handle_exit(), either
 * resuming the guest or returning to the host depending on the return value.
 *
 * Returns:	Next address after end of written function.
 */
static void *kvm_mips_build_ret_from_exit(void *addr, int update_tlb)
{
	u32 *p = addr;
	struct uasm_label labels[9];
	struct uasm_reloc relocs[9];
	struct uasm_label *l = labels;
	struct uasm_reloc *r = relocs;

	memset(labels, 0, sizeof(labels));
	memset(relocs, 0, sizeof(relocs));

	/* Return from handler Make sure interrupts are disabled */
	uasm_i_di(&p, ZERO);
	uasm_i_ehb(&p);

	/*
	 * XXXKYMA: k0/k1 could have been blown away if we processed
	 * an exception while we were handling the exception from the
	 * guest, reload k1
	 */

	uasm_i_move(&p, K1, S1);
	UASM_i_ADDIU(&p, K1, K1, offsetof(struct kvm_vcpu, arch));
	/*
	 * Check return value, should tell us if we are returning to the
	 * host (handle I/O etc)or resuming the guest
	 */
	uasm_i_andi(&p, T0, V0, RESUME_HOST);
	uasm_il_bnez(&p, &r, T0, label_return_to_host);
	uasm_i_nop(&p);

	if(update_tlb) {
		//process nodecounter read passthrough
		uasm_i_lw(&p, A3, offsetof(struct kvm_vcpu_arch, is_nodecounter), K1);
		uasm_il_bnez(&p, &r, A3, label_nodecounter);
		uasm_i_nop(&p);

		uasm_i_mfc0(&p, A0, C0_INDEX); //save index
		UASM_i_MFC0(&p, A1, C0_ENTRYHI);
		UASM_i_MFC0(&p, T0, C0_PAGEMASK);
		UASM_i_MFC0(&p, T1, C0_ENTRYLO0);
		UASM_i_MFC0(&p, T2, C0_ENTRYLO1);

		/* Set Diag.MID to make sure all TLB instructions works only
		   on guest TLB entrys */
		uasm_i_addiu(&p, A4, ZERO, 1);
		uasm_i_mfc0(&p, A2, C0_DIAG);
		uasm_i_ins(&p, A2, A4, LS_MID_SHIFT, 2);
		uasm_i_mtc0(&p, A2, C0_DIAG);

		/* Get guest TLB entry to be written into hardware */
		UASM_i_LW(&p, V1, offsetof(struct kvm_vcpu_arch, guest_tlb[0].tlb_mask), K1);
		UASM_i_MTC0(&p, V1, C0_PAGEMASK);
		UASM_i_LW(&p, V1, offsetof(struct kvm_vcpu_arch, guest_tlb[0].tlb_lo[0]), K1);
		uasm_i_ori(&p, V1, V1, 1); //ensure G=1
		UASM_i_MTC0(&p, V1, C0_ENTRYLO0);
		UASM_i_LW(&p, V1, offsetof(struct kvm_vcpu_arch, guest_tlb[0].tlb_lo[1]), K1);
		uasm_i_ori(&p, V1, V1, 1); //ensure G=1
		UASM_i_MTC0(&p, V1, C0_ENTRYLO1);

		/* Probe the TLB entry to be written into hardware */
		UASM_i_LW(&p, V1, offsetof(struct kvm_vcpu_arch, guest_tlb[0].tlb_hi), K1);
		UASM_i_MTC0(&p, V1, C0_ENTRYHI);

		uasm_i_tlbp(&p);
		uasm_i_ehb(&p);

		uasm_i_mfc0(&p, T3, C0_INDEX);

		/* If TLB entry to be written not in TLB hardware, write it randomly.
		   Otherwise write it with index */
		uasm_il_bltz(&p, &r, T3, label_no_tlb_line);
		uasm_i_nop(&p);

		uasm_i_tlbwi(&p);
		uasm_i_ehb(&p);
		uasm_il_b(&p, &r, label_finish_tlb_fill);
		uasm_i_nop(&p);

		uasm_l_no_tlb_line(&l, p);
		uasm_i_tlbwr(&p);
		uasm_i_ehb(&p);

		uasm_l_finish_tlb_fill(&l, p);

		/* Clear Diag.MID to make sure Root.TLB refill & general
		   exception works right */
		uasm_i_mfc0(&p, A2, C0_DIAG);
		uasm_i_ins(&p, A2, ZERO, LS_MID_SHIFT, 2);
		uasm_i_mtc0(&p, A2, C0_DIAG);

		uasm_i_mtc0(&p, A0, C0_INDEX); //restore index
		UASM_i_MTC0(&p, A1, C0_ENTRYHI);
		UASM_i_MTC0(&p, T0, C0_PAGEMASK);
		UASM_i_MTC0(&p, T1, C0_ENTRYLO0);
		UASM_i_MTC0(&p, T2, C0_ENTRYLO1);

		//Flush ITLB/DTLB
		uasm_i_ori(&p, A1, ZERO, 3);
		uasm_i_mfc0(&p, A0, C0_DIAG);
		uasm_i_ins(&p, A0, A1, LS_ITLB_SHIFT, 2);
		uasm_i_mtc0(&p, A0, C0_DIAG);

		uasm_l_nodecounter(&l, p);
		uasm_i_sw(&p, ZERO, offsetof(struct kvm_vcpu_arch, is_nodecounter), K1);
		uasm_i_nop(&p);
	} else
		uasm_i_sw(&p, ZERO, offsetof(struct kvm_vcpu_arch, is_hypcall), K1);

	p = kvm_mips_build_ret_to_guest(p);

	uasm_l_return_to_host(&l, p);
	p = kvm_mips_build_ret_to_host(p);

	uasm_resolve_relocs(relocs, labels);

	return p;
}

/**
 * kvm_mips_build_ret_to_guest() - Assemble code to return to the guest.
 * @addr:	Address to start writing code.
 *
 * Assemble the code to handle return from the guest exit handler
 * (kvm_mips_handle_exit()) back to the guest.
 *
 * Returns:	Next address after end of written function.
 */
static void *kvm_mips_build_ret_to_guest(void *addr)
{
	u32 *p = addr;

	/* Put the saved pointer to vcpu (s1) back into the scratch register */
	UASM_i_MTC0(&p, S1, scratch_vcpu[0], scratch_vcpu[1]);

	/* Load up the Guest EBASE to minimize the window where BEV is set */
	UASM_i_LW(&p, T0, offsetof(struct kvm_vcpu_arch, guest_ebase), K1);

	/* Switch EBASE back to the one used by KVM */
	uasm_i_mfc0(&p, V1, C0_STATUS);
#ifndef CONFIG_CPU_LOONGSON3
	uasm_i_lui(&p, AT, ST0_BEV >> 16);
	uasm_i_or(&p, K0, V1, AT);
	uasm_i_mtc0(&p, K0, C0_STATUS);
	uasm_i_ehb(&p);
#endif
	build_set_exc_base(&p, T0);

	/* Setup status register for running guest in UM */
	uasm_i_lui(&p, AT, 0x100); //set ST0_MX
	uasm_i_or(&p, V1, V1, AT);
	uasm_i_ori(&p, V1, V1, ST0_EXL | KSU_USER | ST0_IE);
	//UASM_i_LA(&p, AT, ~(ST0_CU0 | ST0_MX | ST0_SX | ST0_UX));
	UASM_i_LA(&p, AT, ~(ST0_CU0 | ST0_SX));
	uasm_i_and(&p, V1, V1, AT);
	uasm_i_mtc0(&p, V1, C0_STATUS);
	uasm_i_ehb(&p);

	p = kvm_mips_build_enter_guest(p);

	return p;
}

/**
 * kvm_mips_build_ret_to_host() - Assemble code to return to the host.
 * @addr:	Address to start writing code.
 *
 * Assemble the code to handle return from the guest exit handler
 * (kvm_mips_handle_exit()) back to the host, i.e. to the caller of the vcpu_run
 * function generated by kvm_mips_build_vcpu_run().
 *
 * Returns:	Next address after end of written function.
 */
static void *kvm_mips_build_ret_to_host(void *addr)
{
	u32 *p = addr;
	unsigned int i;

	/* EBASE is already pointing to Linux */
	UASM_i_LW(&p, K1, offsetof(struct kvm_vcpu_arch, host_stack), K1);
	UASM_i_ADDIU(&p, K1, K1, -(int)sizeof(struct pt_regs));

	/*
	 * r2/v0 is the return code, shift it down by 2 (arithmetic)
	 * to recover the err code
	 */
	uasm_i_sra(&p, K0, V0, 2);
	uasm_i_move(&p, V0, K0);

	/* Load context saved on the host stack */
	for (i = 16; i < 31; ++i) {
		if (i == K0 || i == K1)
			continue;
		UASM_i_LW(&p, i, offsetof(struct pt_regs, regs[i]), K1);
	}

#ifndef CONFIG_CPU_LOONGSON3
	/* Restore RDHWR access */
	UASM_i_LA_mostly(&p, K0, (long)&hwrena);
	uasm_i_lw(&p, K0, uasm_rel_lo((long)&hwrena), K0);
	uasm_i_mtc0(&p, K0, C0_HWRENA);
#endif

	/* Restore RA, which is the address we will return to */
	UASM_i_LW(&p, RA, offsetof(struct pt_regs, regs[RA]), K1);
	uasm_i_jr(&p, RA);
	uasm_i_nop(&p);

	return p;
}
