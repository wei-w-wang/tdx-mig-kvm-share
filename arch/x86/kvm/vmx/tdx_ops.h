/* SPDX-License-Identifier: GPL-2.0 */
/* constants/data definitions for TDX SEAMCALLs */

#ifndef __KVM_X86_TDX_OPS_H
#define __KVM_X86_TDX_OPS_H

#include <linux/compiler.h>

#include <asm/pgtable_types.h>
#include <asm/cacheflush.h>
#include <asm/asm.h>
#include <asm/kvm_host.h>

#include "tdx_errno.h"
#include "tdx_arch.h"
#include "x86.h"

static inline u64 __tdx_seamcall(u64 op, struct tdx_module_args *in,
				 struct tdx_module_args *out, bool need_saved)
{
	u64 ret;

	if (need_saved)
		ret = seamcall_saved_ret(op, in);
	else
		ret = seamcall_ret(op, in);

	if (unlikely(ret == TDX_SEAMCALL_UD)) {
		/*
		 * SEAMCALLs fail with TDX_SEAMCALL_UD returned when VMX is off.
		 * This can happen when the host gets rebooted or live
		 * updated. In this case, the instruction execution is ignored
		 * as KVM is shut down, so the error code is suppressed. Other
		 * than this, the error is unexpected and the execution can't
		 * continue as the TDX features reply on VMX to be on.
		 */
		kvm_spurious_fault();
		return 0;
	}

	if (out)
		*out = *in;

	return ret;
}

static inline u64 tdx_seamcall(u64 op, struct tdx_module_args *in,
			       struct tdx_module_args *out)
{
	return __tdx_seamcall(op, in, out, false);
}

static inline u64 tdx_seamcall_saved(u64 op, struct tdx_module_args *in,
				     struct tdx_module_args *out)
{
	return __tdx_seamcall(op, in, out, true);
}

#ifdef CONFIG_INTEL_TDX_HOST
void pr_tdx_error(u64 op, u64 error_code, const struct tdx_module_args *out);
#endif

static inline int pg_level_to_tdx_sept_level(enum pg_level level)
{
	WARN_ON_ONCE(level == PG_LEVEL_NONE);
	return level - 1;
}

static inline enum pg_level tdx_sept_level_to_pg_level(int tdx_level)
{
	return tdx_level + 1;
}

static inline void tdx_clflush_page(hpa_t addr, enum pg_level level)
{
	clflush_cache_range(__va(addr), KVM_HPAGE_SIZE(level));
}

static inline u64 tdh_mng_addcx(hpa_t tdr, hpa_t addr)
{
	struct tdx_module_args in = {
		.rcx = addr,
		.rdx = tdr,
	};

	tdx_clflush_page(addr, PG_LEVEL_4K);
	return tdx_seamcall(TDH_MNG_ADDCX, &in, NULL);
}

static inline u64 tdh_mem_page_add(hpa_t tdr, gpa_t gpa, hpa_t hpa, hpa_t source,
				   struct tdx_module_args *out)
{
	/* TDH.MEM.PAGE.ADD() suports only 4K page. tdx 4K page level = 0 */
	struct tdx_module_args in = {
		.rcx = gpa,
		.rdx = tdr,
		.r8 = hpa,
		.r9 = source,
	};

	tdx_clflush_page(hpa, PG_LEVEL_4K);
	return tdx_seamcall(TDH_MEM_PAGE_ADD, &in, out);
}

static inline u64 tdh_mem_sept_add(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
				   struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = tdr,
		.r8 = page,
	};

	tdx_clflush_page(page, PG_LEVEL_4K);
	return tdx_seamcall(TDH_MEM_SEPT_ADD, &in, out);
}

static inline u64 tdh_mem_sept_rd(hpa_t tdr, gpa_t gpa, int level,
				  struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = tdr,
	};

	return tdx_seamcall(TDH_MEM_SEPT_RD, &in, out);
}

static inline u64 tdh_mem_sept_remove(hpa_t tdr, gpa_t gpa, int level,
				      struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = tdr,
	};

	return tdx_seamcall(TDH_MEM_SEPT_REMOVE, &in, out);
}

static inline u64 tdh_vp_addcx(hpa_t tdvpr, hpa_t addr)
{
	struct tdx_module_args in = {
		.rcx = addr,
		.rdx = tdvpr,
	};

	tdx_clflush_page(addr, PG_LEVEL_4K);
	return tdx_seamcall(TDH_VP_ADDCX, &in, NULL);
}

static inline u64 tdh_mem_page_relocate(hpa_t tdr, gpa_t gpa, hpa_t hpa,
					struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa,
		.rdx = tdr,
		.r8 = hpa,
	};

	tdx_clflush_page(hpa, PG_LEVEL_4K);
	return tdx_seamcall(TDH_MEM_PAGE_RELOCATE, &in, out);
}

static inline u64 tdh_mem_page_aug(hpa_t tdr, gpa_t gpa, int level, hpa_t hpa,
				   struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = tdr,
		.r8 = hpa,
	};

	tdx_clflush_page(hpa, tdx_sept_level_to_pg_level(level));
	return tdx_seamcall(TDH_MEM_PAGE_AUG, &in, out);
}

static inline u64 tdh_mem_range_block(hpa_t tdr, gpa_t gpa, int level,
				      struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = tdr,
	};

	return tdx_seamcall(TDH_MEM_RANGE_BLOCK, &in, out);
}

static inline u64 tdh_mng_key_config(hpa_t tdr)
{
	struct tdx_module_args in = {
		.rcx = tdr,
	};

	return tdx_seamcall(TDH_MNG_KEY_CONFIG, &in, NULL);
}

static inline u64 tdh_mng_create(hpa_t tdr, int hkid)
{
	struct tdx_module_args in = {
		.rcx = tdr,
		.rdx = hkid,
	};

	tdx_clflush_page(tdr, PG_LEVEL_4K);
	return tdx_seamcall(TDH_MNG_CREATE, &in, NULL);
}

static inline u64 tdh_vp_create(hpa_t tdr, hpa_t tdvpr)
{
	struct tdx_module_args in = {
		.rcx = tdvpr,
		.rdx = tdr,
	};

	tdx_clflush_page(tdvpr, PG_LEVEL_4K);
	return tdx_seamcall(TDH_VP_CREATE, &in, NULL);
}

static inline u64 tdh_mng_rd(hpa_t tdr, u64 field, struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = tdr,
		.rdx = field,
	};

	return tdx_seamcall(TDH_MNG_RD, &in, out);
}

static inline u64 tdh_mem_page_demote(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
				      struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = tdr,
		.r8 = page,
	};

	tdx_clflush_page(page, PG_LEVEL_4K);
	return tdx_seamcall(TDH_MEM_PAGE_DEMOTE, &in, out);
}

static inline u64 tdh_mem_page_promote(hpa_t tdr, gpa_t gpa, int level,
				       struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = tdr,
	};

	return tdx_seamcall(TDH_MEM_PAGE_PROMOTE, &in, out);
}

static inline u64 tdh_mr_extend(hpa_t tdr, gpa_t gpa,
				struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa,
		.rdx = tdr,
	};

	return tdx_seamcall(TDH_MR_EXTEND, &in, out);
}

static inline u64 tdh_mr_finalize(hpa_t tdr)
{
	struct tdx_module_args in = {
		.rcx = tdr,
	};

	return tdx_seamcall(TDH_MR_FINALIZE, &in, NULL);
}

static inline u64 tdh_vp_flush(hpa_t tdvpr)
{
	struct tdx_module_args in = {
		.rcx = tdvpr,
	};

	return tdx_seamcall(TDH_VP_FLUSH, &in, NULL);
}

static inline u64 tdh_mng_vpflushdone(hpa_t tdr)
{
	struct tdx_module_args in = {
		.rcx = tdr,
	};

	return tdx_seamcall(TDH_MNG_VPFLUSHDONE, &in, NULL);
}

static inline u64 tdh_mng_key_freeid(hpa_t tdr)
{
	struct tdx_module_args in = {
		.rcx = tdr,
	};

	return tdx_seamcall(TDH_MNG_KEY_FREEID, &in, NULL);
}

static inline u64 tdh_mng_init(hpa_t tdr, hpa_t td_params,
			       struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = tdr,
		.rdx = td_params,
	};

	return tdx_seamcall(TDH_MNG_INIT, &in, out);
}

static inline u64 tdh_vp_init(hpa_t tdvpr, u64 rcx)
{
	struct tdx_module_args in = {
		.rcx = tdvpr,
		.rdx = rcx,
	};

	return tdx_seamcall(TDH_VP_INIT, &in, NULL);
}

static inline u64 tdh_vp_rd(hpa_t tdvpr, u64 field,
			    struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = tdvpr,
		.rdx = field,
	};

	return tdx_seamcall(TDH_VP_RD, &in, out);
}

static inline u64 tdh_mng_key_reclaimid(hpa_t tdr)
{
	struct tdx_module_args in = {
		.rcx = tdr,
	};

	return tdx_seamcall(TDH_MNG_KEY_RECLAIMID, &in, NULL);
}

static inline u64 tdh_phymem_page_reclaim(hpa_t page,
					  struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = page,
	};

	return tdx_seamcall(TDH_PHYMEM_PAGE_RECLAIM, &in, out);
}

static inline u64 tdh_mem_page_remove(hpa_t tdr, gpa_t gpa, int level,
				      struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = tdr,
	};

	return tdx_seamcall(TDH_MEM_PAGE_REMOVE, &in, out);
}

static inline u64 tdh_sys_lp_shutdown(void)
{
	struct tdx_module_args in = {
	};

	return tdx_seamcall(TDH_SYS_LP_SHUTDOWN, &in, NULL);
}

static inline u64 tdh_mem_track(hpa_t tdr)
{
	struct tdx_module_args in = {
		.rcx = tdr,
	};

	return tdx_seamcall(TDH_MEM_TRACK, &in, NULL);
}

static inline u64 tdh_mem_range_unblock(hpa_t tdr, gpa_t gpa, int level,
					struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa | level,
		.rdx = tdr,
	};

	return tdx_seamcall(TDH_MEM_RANGE_UNBLOCK, &in, out);
}

static inline u64 tdh_phymem_cache_wb(bool resume)
{
	struct tdx_module_args in = {
		.rcx = resume ? 1 : 0,
	};

	return tdx_seamcall(TDH_PHYMEM_CACHE_WB, &in, NULL);
}

static inline u64 tdh_phymem_page_wbinvd(hpa_t page)
{
	struct tdx_module_args in = {
		.rcx = page,
	};

	return tdx_seamcall(TDH_PHYMEM_PAGE_WBINVD, &in, NULL);
}

static inline u64 tdh_vp_wr(hpa_t tdvpr, u64 field, u64 val, u64 mask,
			    struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = tdvpr,
		.rdx = field,
		.r8 = val,
		.r9 = mask,
	};

	return tdx_seamcall(TDH_VP_WR, &in, out);
}

static inline u64 tdh_servtd_bind(hpa_t servtd_tdr,
				  hpa_t target_tdr,
				  u64 slot_idx,
				  u64 attr,
				  u64 type,
				  struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = target_tdr,
		.rdx = servtd_tdr,
		.r8 = slot_idx,
		.r9 = type,
		.r10 = attr,
	};

	return tdx_seamcall_saved(TDH_SERVTD_BIND, &in, out);
}

enum kvm_tdx_servtd_type {
	KVM_TDX_SERVTD_TYPE_MIGTD = 0,

	KVM_TDX_SERVTD_TYPE_MAX,
};

static inline u64 tdh_servtd_prebind(hpa_t target_tdr,
				     hpa_t hash_addr,
				     u64 slot_idx,
				     u64 attr,
				     enum kvm_tdx_servtd_type type)
{
	struct tdx_module_args in = {
		.rcx = target_tdr,
		.rdx = hash_addr,
		.r8 = slot_idx,
		.r9 = type,
		.r10 = attr,
	};

	return tdx_seamcall(TDH_SERVTD_PREBIND, &in, NULL);
}

static inline u64 tdh_mig_stream_create(hpa_t tdr, hpa_t migsc)
{
	struct tdx_module_args in = {
		.rcx = migsc,
		.rdx = tdr,
	};

	return tdx_seamcall(TDH_MIG_STREAM_CREATE, &in, NULL);
}

static inline u64 tdh_export_state_immutable(hpa_t tdr,
					     u64 mbmd_info,
					     u64 page_list_info,
					     u64 mig_stream_info,
					     struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = tdr,
		.r8 = mbmd_info,
		.r9 = page_list_info,
		.r10 = mig_stream_info,
	};

	return tdx_seamcall(TDH_EXPORT_STATE_IMMUTABLE, &in, out);
}

static inline u64 tdh_import_state_immutable(hpa_t tdr,
					     u64 mbmd_info,
					     u64 page_list_info,
					     u64 mig_stream_info,
					     struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = tdr,
		.r8 = mbmd_info,
		.r9 = page_list_info,
		.r10 = mig_stream_info,
	};

	return tdx_seamcall(TDH_IMPORT_STATE_IMMUTABLE, &in, out);
}

static inline u64 tdh_export_blockw(hpa_t tdr,
				    u64 gpa_list_info,
				    struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa_list_info,
		.rdx = tdr,
	};

	return tdx_seamcall(TDH_EXPORT_BLOCKW, &in, out);
}

static inline u64 tdh_export_unblockw(hpa_t tdr,
				      u64 ept_info,
				      struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = ept_info,
		.rdx = tdr,
	};

	return tdx_seamcall(TDH_EXPORT_UNBLOCKW, &in, out);
}

static inline u64 tdh_export_track(hpa_t tdr,
				   u64 mbmd_info,
				   u64 mig_stream_info)
{
	struct tdx_module_args in = {
		.rcx = tdr,
		.r8 = mbmd_info,
		.r10 = mig_stream_info,
	};

	return tdx_seamcall(TDH_EXPORT_TRACK, &in, NULL);
}

static inline u64 tdh_import_track(hpa_t tdr,
				   u64 mbmd_info,
				   u64 mig_stream_info)
{
	struct tdx_module_args in = {
		.rcx = tdr,
		.r8 = mbmd_info,
		.r10 = mig_stream_info,
	};

	return tdx_seamcall(TDH_IMPORT_TRACK, &in, NULL);
}

static inline u64 tdh_import_commit(hpa_t tdr)
{
	struct tdx_module_args in = {
		.rcx = tdr,
	};

	return tdx_seamcall(TDH_IMPORT_COMMIT, &in, NULL);
}

static inline u64 tdh_export_mem(hpa_t tdr,
				 u64 mbmd_info,
				 u64 gpa_list_info,
				 u64 buf_list_info,
				 u64 mac_list0_info,
				 u64 mac_list1_info,
				 u64 mig_stream_info,
				 struct tdx_module_args *out)

{
	struct tdx_module_args in = {
		.rcx = gpa_list_info,
		.rdx = tdr,
		.r8 = mbmd_info,
		.r9 = buf_list_info,
		.r10 = mig_stream_info,
		.r11 = mac_list0_info,
		.r12 = mac_list1_info,
	};

	return tdx_seamcall_saved(TDH_EXPORT_MEM, &in, out);
}

static inline u64 tdh_import_mem(hpa_t tdr,
				 u64 mbmd_info,
				 u64 gpa_list_info,
				 u64 buf_list_info,
				 u64 mac_list0_info,
				 u64 mac_list1_info,
				 u64 td_page_list_info,
				 u64 mig_stream_info,
				 struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = gpa_list_info,
		.rdx = tdr,
		.r8 = mbmd_info,
		.r9 = buf_list_info,
		.r10 = mig_stream_info,
		.r11 = mac_list0_info,
		.r12 = mac_list1_info,
		.r13 = td_page_list_info,
	};

	return tdx_seamcall_saved(TDH_IMPORT_MEM, &in, out);
}

static inline u64 tdh_export_pasue(hpa_t tdr)
{
	struct tdx_module_args in = {
		.rcx = tdr,
	};

	return tdx_seamcall(TDH_EXPORT_PAUSE, &in, NULL);
}

static inline u64 tdh_export_state_td(hpa_t tdr,
				      u64 mbmd_info,
				      u64 page_list_info,
				      u64 mig_stream_info,
				      struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = tdr,
		.r8 = mbmd_info,
		.r9 = page_list_info,
		.r10 = mig_stream_info,
	};

	return tdx_seamcall(TDH_EXPORT_STATE_TD, &in, out);
}

static inline u64 tdh_import_state_td(hpa_t tdr,
				      u64 mbmd_info,
				      u64 page_list_info,
				      u64 mig_stream_info,
				      struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = tdr,
		.r8 = mbmd_info,
		.r9 = page_list_info,
		.r10 = mig_stream_info,
	};

	return tdx_seamcall(TDH_IMPORT_STATE_TD, &in, out);
}

static inline u64 tdh_export_state_vp(hpa_t tdvpr,
				      u64 mbmd_info,
				      u64 page_list_info,
				      u64 mig_stream_info,
				      struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = tdvpr,
		.r8 = mbmd_info,
		.r9 = page_list_info,
		.r10 = mig_stream_info,
	};

	return tdx_seamcall(TDH_EXPORT_STATE_VP, &in, out);
}

static inline u64 tdh_import_state_vp(hpa_t tdvpr,
				      u64 mbmd_info,
				      u64 page_list_info,
				      u64 mig_stream_info,
				      struct tdx_module_args *out)
{
	struct tdx_module_args in = {
		.rcx = tdvpr,
		.r8 = mbmd_info,
		.r9 = page_list_info,
		.r10 = mig_stream_info,
	};

	return tdx_seamcall(TDH_IMPORT_STATE_VP, &in, out);
}

#endif /* __KVM_X86_TDX_OPS_H */
