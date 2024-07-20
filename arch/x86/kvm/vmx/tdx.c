// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>

#include <asm/tdx.h>

#include "capabilities.h"
#include "x86_ops.h"
#include "mmu.h"
#include "tdx.h"
#include "x86.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/* TDX KeyID pool */
static DEFINE_IDA(tdx_guest_keyid_pool);

static int tdx_guest_keyid_alloc(void)
{
	return ida_alloc_range(&tdx_guest_keyid_pool, tdx_guest_keyid_start,
			       tdx_guest_keyid_start + tdx_nr_guest_keyids - 1,
			       GFP_KERNEL);
}

static void tdx_guest_keyid_free(int keyid)
{
	ida_free(&tdx_guest_keyid_pool, keyid);
}

#define KVM_TDX_CPUID_NO_SUBLEAF	((__u32)-1)

struct tdx_info {
	u64 features0;
	u64 attributes_fixed0;
	u64 attributes_fixed1;
	u64 xfam_fixed0;
	u64 xfam_fixed1;

	u16 max_vcpus_per_td;
	u8 nr_tdcs_pages;
	u8 nr_tdcx_pages;

	u16 num_cpuid_config;
	/* This must the last member. */
	DECLARE_FLEX_ARRAY(struct kvm_tdx_cpuid_config, cpuid_configs);
};

/* Info about the TDX module. */
static struct tdx_info *tdx_info;

struct kvm_tdx_caps {
	u64 supported_attrs;
	u64 supported_xfam;

	u16 num_cpuid_config;
	/* This must the last member. */
	DECLARE_FLEX_ARRAY(struct kvm_tdx_cpuid_config, cpuid_configs);
};

static struct kvm_tdx_caps *kvm_tdx_caps;

int tdx_vm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	int r;

	switch (cap->cap) {
	case KVM_CAP_MAX_VCPUS: {
		if (cap->flags || cap->args[0] == 0)
			return -EINVAL;
		if (cap->args[0] > KVM_MAX_VCPUS ||
		    cap->args[0] > tdx_info->max_vcpus_per_td)
			return -E2BIG;

		mutex_lock(&kvm->lock);
		if (kvm->created_vcpus)
			r = -EBUSY;
		else {
			kvm->max_vcpus = cap->args[0];
			r = 0;
		}
		mutex_unlock(&kvm->lock);
		break;
	}
	default:
		r = -EINVAL;
		break;
	}
	return r;
}

/*
 * Some TDX SEAMCALLs (TDH.MNG.CREATE, TDH.PHYMEM.CACHE.WB,
 * TDH.MNG.KEY.RECLAIMID, TDH.MNG.KEY.FREEID etc) tries to acquire a global lock
 * internally in TDX module.  If failed, TDX_OPERAND_BUSY is returned without
 * spinning or waiting due to a constraint on execution time.  It's caller's
 * responsibility to avoid race (or retry on TDX_OPERAND_BUSY).  Use this mutex
 * to avoid race in TDX module because the kernel knows better about scheduling.
 */
static DEFINE_MUTEX(tdx_lock);
static struct mutex *tdx_mng_key_config_lock;

static __always_inline hpa_t set_hkid_to_hpa(hpa_t pa, u16 hkid)
{
	return pa | ((hpa_t)hkid << boot_cpu_data.x86_phys_bits);
}

static inline bool is_td_vcpu_created(struct vcpu_tdx *tdx)
{
	return tdx->td_vcpu_created;
}

static inline bool is_td_created(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr_pa;
}

static inline void tdx_hkid_free(struct kvm_tdx *kvm_tdx)
{
	tdx_guest_keyid_free(kvm_tdx->hkid);
	kvm_tdx->hkid = -1;
}

static inline bool is_hkid_assigned(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->hkid > 0;
}

static inline bool is_td_finalized(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->finalized;
}

static void tdx_clear_page(unsigned long page_pa)
{
	const void *zero_page = (const void *) __va(page_to_phys(ZERO_PAGE(0)));
	void *page = __va(page_pa);
	unsigned long i;

	/*
	 * When re-assign one page from old keyid to a new keyid, MOVDIR64B is
	 * required to clear/write the page with new keyid to prevent integrity
	 * error when read on the page with new keyid.
	 *
	 * clflush doesn't flush cache with HKID set.  The cache line could be
	 * poisoned (even without MKTME-i), clear the poison bit.
	 */
	for (i = 0; i < PAGE_SIZE; i += 64)
		movdir64b(page + i, zero_page);
	/*
	 * MOVDIR64B store uses WC buffer.  Prevent following memory reads
	 * from seeing potentially poisoned cache.
	 */
	__mb();
}

static u64 ____tdx_reclaim_page(hpa_t pa, u64 *rcx, u64 *rdx, u64 *r8)
{
	u64 err;

	do {
		err = tdh_phymem_page_reclaim(pa, rcx, rdx, r8);
		/*
		 * TDH.PHYMEM.PAGE.RECLAIM is allowed only when TD is shutdown.
		 * state.  i.e. destructing TD.
		 * TDH.PHYMEM.PAGE.RECLAIM requires TDR and target page.
		 * Because we're destructing TD, it's rare to contend with TDR.
		 */
	} while (unlikely(err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_RCX) ||
			  err == (TDX_OPERAND_BUSY | TDX_OPERAND_ID_TDR)));
	return err;
}

static int __tdx_reclaim_page(hpa_t pa)
{
	u64 err, rcx, rdx, r8;

	err = ____tdx_reclaim_page(pa, &rcx, &rdx, &r8);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error_3(TDH_PHYMEM_PAGE_RECLAIM, err, rcx, rdx, r8);
		return -EIO;
	}

	return 0;
}

static int tdx_reclaim_page(hpa_t pa)
{
	int r;

	r = __tdx_reclaim_page(pa);
	if (!r)
		tdx_clear_page(pa);
	return r;
}

static void tdx_reclaim_control_page(unsigned long td_page_pa)
{
	/*
	 * TDCX are being reclaimed.  TDX module maps TDCX with HKID
	 * assigned to the TD.  Here the cache associated to the TD
	 * was already flushed by TDH.PHYMEM.CACHE.WB before here, So
	 * cache doesn't need to be flushed again.
	 */
	if (tdx_reclaim_page(td_page_pa))
		/*
		 * Leak the page on failure:
		 * tdx_reclaim_page() returns an error if and only if there's an
		 * unexpected, fatal error, e.g. a SEAMCALL with bad params,
		 * incorrect concurrency in KVM, a TDX Module bug, etc.
		 * Retrying at a later point is highly unlikely to be
		 * successful.
		 * No log here as tdx_reclaim_page() already did.
		 */
		return;
	free_page((unsigned long)__va(td_page_pa));
}

static void tdx_do_tdh_phymem_cache_wb(void *unused)
{
	u64 err = 0;

	do {
		err = tdh_phymem_cache_wb(!!err);
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	/* Other thread may have done for us. */
	if (err == TDX_NO_HKID_READY_TO_WBCACHE)
		err = TDX_SUCCESS;
	if (WARN_ON_ONCE(err))
		pr_tdx_error(TDH_PHYMEM_CACHE_WB, err);
}

void tdx_mmu_release_hkid(struct kvm *kvm)
{
	bool packages_allocated, targets_allocated;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages, targets;
	u64 err;
	int i;

	if (!is_hkid_assigned(kvm_tdx))
		return;

	if (!is_td_created(kvm_tdx)) {
		tdx_hkid_free(kvm_tdx);
		return;
	}

	packages_allocated = zalloc_cpumask_var(&packages, GFP_KERNEL);
	targets_allocated = zalloc_cpumask_var(&targets, GFP_KERNEL);
	cpus_read_lock();

	/*
	 * We can destroy multiple guest TDs simultaneously.  Prevent
	 * tdh_phymem_cache_wb from returning TDX_BUSY by serialization.
	 */
	mutex_lock(&tdx_lock);

	/*
	 * Go through multiple TDX HKID state transitions with three SEAMCALLs
	 * to make TDH.PHYMEM.PAGE.RECLAIM() usable.  Make the transition atomic
	 * to other functions to operate private pages and Secure-EPT pages.
	 *
	 * Avoid race for kvm_gmem_release() to call kvm_mmu_unmap_gfn_range().
	 * This function is called via mmu notifier, mmu_release().
	 * kvm_gmem_release() is called via fput() on process exit.
	 */
	write_lock(&kvm->mmu_lock);

	for_each_online_cpu(i) {
		if (packages_allocated &&
		    cpumask_test_and_set_cpu(topology_physical_package_id(i),
					     packages))
			continue;
		if (targets_allocated)
			cpumask_set_cpu(i, targets);
	}
	if (targets_allocated)
		on_each_cpu_mask(targets, tdx_do_tdh_phymem_cache_wb, NULL, true);
	else
		on_each_cpu(tdx_do_tdh_phymem_cache_wb, NULL, true);
	/*
	 * In the case of error in tdx_do_tdh_phymem_cache_wb(), the following
	 * tdh_mng_key_freeid() will fail.
	 */
	err = tdh_mng_key_freeid(kvm_tdx);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MNG_KEY_FREEID, err);
		pr_err("tdh_mng_key_freeid() failed. HKID %d is leaked.\n",
		       kvm_tdx->hkid);
	} else
		tdx_hkid_free(kvm_tdx);

	write_unlock(&kvm->mmu_lock);
	mutex_unlock(&tdx_lock);
	cpus_read_unlock();
	free_cpumask_var(targets);
	free_cpumask_var(packages);
}

void tdx_vm_free(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u64 err;
	int i;

	/*
	 * tdx_mmu_release_hkid() failed to reclaim HKID.  Something went wrong
	 * heavily with TDX module.  Give up freeing TD pages.  As the function
	 * already warned, don't warn it again.
	 */
	if (is_hkid_assigned(kvm_tdx))
		return;

	if (kvm_tdx->tdcs_pa) {
		for (i = 0; i < tdx_info->nr_tdcs_pages; i++) {
			if (kvm_tdx->tdcs_pa[i])
				tdx_reclaim_control_page(kvm_tdx->tdcs_pa[i]);
		}
		kfree(kvm_tdx->tdcs_pa);
		kvm_tdx->tdcs_pa = NULL;
	}

	if (!kvm_tdx->tdr_pa)
		return;
	if (__tdx_reclaim_page(kvm_tdx->tdr_pa))
		return;
	/*
	 * TDX module maps TDR with TDX global HKID.  TDX module may access TDR
	 * while operating on TD (Especially reclaiming TDCS).  Cache flush with
	 * TDX global HKID is needed.
	 */
	err = tdh_phymem_page_wbinvd(set_hkid_to_hpa(kvm_tdx->tdr_pa,
						     tdx_global_keyid));
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_PHYMEM_PAGE_WBINVD, err);
		return;
	}
	tdx_clear_page(kvm_tdx->tdr_pa);

	free_page((unsigned long)__va(kvm_tdx->tdr_pa));
	kvm_tdx->tdr_pa = 0;
}

static int tdx_do_tdh_mng_key_config(void *param)
{
	struct kvm_tdx *kvm_tdx = param;
	u64 err;

	do {
		err = tdh_mng_key_config(kvm_tdx);

		/*
		 * If it failed to generate a random key, retry it because this
		 * is typically caused by an entropy error of the CPU's random
		 * number generator.
		 */
	} while (err == TDX_KEY_GENERATION_FAILED);

	if (KVM_BUG_ON(err, &kvm_tdx->kvm)) {
		pr_tdx_error(TDH_MNG_KEY_CONFIG, err);
		return -EIO;
	}

	return 0;
}

int tdx_vm_init(struct kvm *kvm)
{
	kvm->arch.has_private_mem = true;

	/*
	 * This function initializes only KVM software construct.  It doesn't
	 * initialize TDX stuff, e.g. TDCS, TDR, TDCX, HKID etc.
	 * It is handled by KVM_TDX_INIT_VM, __tdx_td_init().
	 */

	/*
	 * TDX has its own limit of the number of vcpus in addition to
	 * KVM_MAX_VCPUS.
	 */
	kvm->max_vcpus = min(kvm->max_vcpus, tdx_info->max_vcpus_per_td);

	return 0;
}

int tdx_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);

	/* TDX only supports x2APIC, which requires an in-kernel local APIC. */
	if (!vcpu->arch.apic)
		return -EINVAL;

	fpstate_set_confidential(&vcpu->arch.guest_fpu);

	vcpu->arch.efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NX;

	vcpu->arch.cr0_guest_owned_bits = -1ul;
	vcpu->arch.cr4_guest_owned_bits = -1ul;

	vcpu->arch.tsc_offset = to_kvm_tdx(vcpu->kvm)->tsc_offset;
	vcpu->arch.l1_tsc_offset = vcpu->arch.tsc_offset;
	vcpu->arch.guest_state_protected =
		!(to_kvm_tdx(vcpu->kvm)->attributes & TDX_TD_ATTR_DEBUG);

	if ((kvm_tdx->xfam & XFEATURE_MASK_XTILE) == XFEATURE_MASK_XTILE)
		vcpu->arch.xfd_no_write_intercept = true;

	return 0;
}

void tdx_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int i;

	/*
	 * This methods can be called when vcpu allocation/initialization
	 * failed. So it's possible that hkid, tdvpx and tdvpr are not assigned
	 * yet.
	 */
	if (is_hkid_assigned(to_kvm_tdx(vcpu->kvm)))
		return;

	if (tdx->tdcx_pa) {
		for (i = 0; i < tdx_info->nr_tdcx_pages; i++) {
			if (tdx->tdcx_pa[i])
				tdx_reclaim_control_page(tdx->tdcx_pa[i]);
		}
		kfree(tdx->tdcx_pa);
		tdx->tdcx_pa = NULL;
	}
	if (tdx->tdvpr_pa) {
		tdx_reclaim_control_page(tdx->tdvpr_pa);
		tdx->tdvpr_pa = 0;
	}
}

void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{

	/* Ignore INIT silently because TDX doesn't support INIT event. */
	if (init_event)
		return;
	if (is_td_vcpu_created(to_tdx(vcpu)))
		return;

	/*
	 * Don't update mp_state to runnable because more initialization
	 * is needed by TDX_VCPU_INIT.
	 */
}

static int tdx_get_capabilities(struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx_capabilities __user *user_caps;
	struct kvm_tdx_capabilities *caps = NULL;
	int ret = 0;

	/* flags is reserved for future use */
	if (cmd->flags)
		return -EINVAL;

	caps = kmalloc(sizeof(*caps), GFP_KERNEL);
	if (!caps)
		return -ENOMEM;

	user_caps = u64_to_user_ptr(cmd->data);
	if (copy_from_user(caps, user_caps, sizeof(*caps))) {
		ret = -EFAULT;
		goto out;
	}

	if (caps->nr_cpuid_configs < tdx_info->num_cpuid_config) {
		ret = -E2BIG;
		goto out;
	}

	caps->supported_attrs = kvm_tdx_caps->supported_attrs;
	caps->supported_xfam = kvm_tdx_caps->supported_xfam;
	caps->nr_cpuid_configs = kvm_tdx_caps->num_cpuid_config;

	if (copy_to_user(user_caps, caps, sizeof(*caps))) {
		ret = -EFAULT;
		goto out;
	}

	if (copy_to_user(user_caps->cpuid_configs, &kvm_tdx_caps->cpuid_configs,
			 kvm_tdx_caps->num_cpuid_config *
			 sizeof(kvm_tdx_caps->cpuid_configs[0])))
		ret = -EFAULT;

out:
	/* kfree() accepts NULL. */
	kfree(caps);
	return ret;
}

static int setup_tdparams_eptp_controls(struct kvm_cpuid2 *cpuid,
					struct td_params *td_params)
{
	const struct kvm_cpuid_entry2 *entry;
	int guest_pa;

	entry = kvm_find_cpuid_entry2(cpuid->entries, cpuid->nent, 0x80000008, 0);
	if (!entry)
		return -EINVAL;

	guest_pa = (entry->eax >> 16) & 0xff;

	if (guest_pa != 48 && guest_pa != 52)
		return -EINVAL;

	if (guest_pa == 52 && !cpu_has_vmx_ept_5levels())
		return -EINVAL;

	td_params->eptp_controls = VMX_EPTP_MT_WB;
	if (guest_pa == 52) {
		td_params->eptp_controls |= VMX_EPTP_PWL_5;
		td_params->exec_controls |= TDX_EXEC_CONTROL_MAX_GPAW;
	} else {
		td_params->eptp_controls |= VMX_EPTP_PWL_4;
	}

	return 0;
}

static int setup_tdparams_cpuids(struct kvm_cpuid2 *cpuid,
				 struct td_params *td_params)
{
	const struct kvm_tdx_cpuid_config *c;
	const struct kvm_cpuid_entry2 *entry;
	struct tdx_cpuid_value *value;
	int i;

	/*
	 * td_params.cpuid_values: The number and the order of cpuid_value must
	 * be same to the one of struct tdsysinfo.{num_cpuid_config, cpuid_configs}
	 * It's assumed that td_params was zeroed.
	 */
	for (i = 0; i < tdx_info->num_cpuid_config; i++) {
		c = &kvm_tdx_caps->cpuid_configs[i];
		entry = kvm_find_cpuid_entry2(cpuid->entries, cpuid->nent,
					      c->leaf, c->sub_leaf);
		if (!entry)
			continue;

		/*
		 * Check the user input value doesn't set any non-configurable
		 * bits reported by kvm_tdx_caps.
		 */
		if ((entry->eax & c->eax) != entry->eax ||
		    (entry->ebx & c->ebx) != entry->ebx ||
		    (entry->ecx & c->ecx) != entry->ecx ||
		    (entry->edx & c->edx) != entry->edx)
			return -EINVAL;

		value = &td_params->cpuid_values[i];
		value->eax = entry->eax;
		value->ebx = entry->ebx;
		value->ecx = entry->ecx;
		value->edx = entry->edx;

		if (c->leaf == 0x80000008)
			value->eax &= 0xff00ffff;
	}

	return 0;
}

static int setup_tdparams(struct kvm *kvm, struct td_params *td_params,
			struct kvm_tdx_init_vm *init_vm)
{
	struct kvm_cpuid2 *cpuid = &init_vm->cpuid;
	int ret;

	if (kvm->created_vcpus)
		return -EBUSY;

	if (init_vm->attributes & ~kvm_tdx_caps->supported_attrs)
		return -EINVAL;

	if (init_vm->xfam & ~kvm_tdx_caps->supported_xfam)
		return -EINVAL;

	td_params->max_vcpus = kvm->max_vcpus;
	td_params->attributes = init_vm->attributes | tdx_info->attributes_fixed1;
	td_params->xfam = init_vm->xfam | tdx_info->xfam_fixed1;

	/* td_params->exec_controls = TDX_CONTROL_FLAG_NO_RBP_MOD; */
	td_params->tsc_frequency = TDX_TSC_KHZ_TO_25MHZ(kvm->arch.default_tsc_khz);

	ret = setup_tdparams_eptp_controls(cpuid, td_params);
	if (ret)
		return ret;

	ret = setup_tdparams_cpuids(cpuid, td_params);
	if (ret)
		return ret;

#define MEMCPY_SAME_SIZE(dst, src)				\
	do {							\
		BUILD_BUG_ON(sizeof(dst) != sizeof(src));	\
		memcpy((dst), (src), sizeof(dst));		\
	} while (0)

	MEMCPY_SAME_SIZE(td_params->mrconfigid, init_vm->mrconfigid);
	MEMCPY_SAME_SIZE(td_params->mrowner, init_vm->mrowner);
	MEMCPY_SAME_SIZE(td_params->mrownerconfig, init_vm->mrownerconfig);

	return 0;
}

static int __tdx_td_init(struct kvm *kvm, struct td_params *td_params,
			 u64 *seamcall_err)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	cpumask_var_t packages;
	unsigned long *tdcs_pa = NULL;
	unsigned long tdr_pa = 0;
	unsigned long va;
	int ret, i;
	u64 err, rcx;

	*seamcall_err = 0;
	ret = tdx_guest_keyid_alloc();
	if (ret < 0)
		return ret;
	kvm_tdx->hkid = ret;

	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va)
		goto free_hkid;
	tdr_pa = __pa(va);

	tdcs_pa = kcalloc(tdx_info->nr_tdcs_pages, sizeof(*kvm_tdx->tdcs_pa),
			  GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!tdcs_pa)
		goto free_tdr;
	for (i = 0; i < tdx_info->nr_tdcs_pages; i++) {
		va = __get_free_page(GFP_KERNEL_ACCOUNT);
		if (!va)
			goto free_tdcs;
		tdcs_pa[i] = __pa(va);
	}

	if (!zalloc_cpumask_var(&packages, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto free_tdcs;
	}
	cpus_read_lock();
	/*
	 * Need at least one CPU of the package to be online in order to
	 * program all packages for host key id.  Check it.
	 */
	for_each_present_cpu(i)
		cpumask_set_cpu(topology_physical_package_id(i), packages);
	for_each_online_cpu(i)
		cpumask_clear_cpu(topology_physical_package_id(i), packages);
	if (!cpumask_empty(packages)) {
		ret = -EIO;
		/*
		 * Because it's hard for human operator to figure out the
		 * reason, warn it.
		 */
#define MSG_ALLPKG	"All packages need to have online CPU to create TD. Online CPU and retry.\n"
		pr_warn_ratelimited(MSG_ALLPKG);
		goto free_packages;
	}

	/*
	 * Acquire global lock to avoid TDX_OPERAND_BUSY:
	 * TDH.MNG.CREATE and other APIs try to lock the global Key Owner
	 * Table (KOT) to track the assigned TDX private HKID.  It doesn't spin
	 * to acquire the lock, returns TDX_OPERAND_BUSY instead, and let the
	 * caller to handle the contention.  This is because of time limitation
	 * usable inside the TDX module and OS/VMM knows better about process
	 * scheduling.
	 *
	 * APIs to acquire the lock of KOT:
	 * TDH.MNG.CREATE, TDH.MNG.KEY.FREEID, TDH.MNG.VPFLUSHDONE, and
	 * TDH.PHYMEM.CACHE.WB.
	 */
	mutex_lock(&tdx_lock);
	kvm_tdx->tdr_pa = tdr_pa;
	err = tdh_mng_create(kvm_tdx, kvm_tdx->hkid);
	mutex_unlock(&tdx_lock);
	if (err == TDX_RND_NO_ENTROPY) {
		kvm_tdx->tdr_pa = 0;
		ret = -EAGAIN;
		goto free_packages;
	}
	if (WARN_ON_ONCE(err)) {
		kvm_tdx->tdr_pa = 0;
		pr_tdx_error(TDH_MNG_CREATE, err);
		ret = -EIO;
		goto free_packages;
	}

	for_each_online_cpu(i) {
		int pkg = topology_physical_package_id(i);

		if (cpumask_test_and_set_cpu(pkg, packages))
			continue;

		/*
		 * Program the memory controller in the package with an
		 * encryption key associated to a TDX private host key id
		 * assigned to this TDR.  Concurrent operations on same memory
		 * controller results in TDX_OPERAND_BUSY.  Avoid this race by
		 * mutex.
		 */
		mutex_lock(&tdx_mng_key_config_lock[pkg]);
		ret = smp_call_on_cpu(i, tdx_do_tdh_mng_key_config,
				      kvm_tdx, true);
		mutex_unlock(&tdx_mng_key_config_lock[pkg]);
		if (ret)
			break;
	}
	cpus_read_unlock();
	free_cpumask_var(packages);
	if (ret) {
		i = 0;
		goto teardown;
	}

	kvm_tdx->tdcs_pa = tdcs_pa;
	for (i = 0; i < tdx_info->nr_tdcs_pages; i++) {
		err = tdh_mng_addcx(kvm_tdx, tdcs_pa[i]);
		if (err == TDX_RND_NO_ENTROPY) {
			/* Here it's hard to allow userspace to retry. */
			ret = -EBUSY;
			goto teardown;
		}
		if (WARN_ON_ONCE(err)) {
			pr_tdx_error(TDH_MNG_ADDCX, err);
			ret = -EIO;
			goto teardown;
		}
	}

	err = tdh_mng_init(kvm_tdx, __pa(td_params), &rcx);
	if ((err & TDX_SEAMCALL_STATUS_MASK) == TDX_OPERAND_INVALID) {
		/*
		 * Because a user gives operands, don't warn.
		 * Return a hint to the user because it's sometimes hard for the
		 * user to figure out which operand is invalid.  SEAMCALL status
		 * code includes which operand caused invalid operand error.
		 */
		*seamcall_err = err;
		ret = -EINVAL;
		goto teardown;
	} else if (WARN_ON_ONCE(err)) {
		pr_tdx_error_1(TDH_MNG_INIT, err, rcx);
		ret = -EIO;
		goto teardown;
	}

	return 0;

	/*
	 * The sequence for freeing resources from a partially initialized TD
	 * varies based on where in the initialization flow failure occurred.
	 * Simply use the full teardown and destroy, which naturally play nice
	 * with partial initialization.
	 */
teardown:
	for (; i < tdx_info->nr_tdcs_pages; i++) {
		if (tdcs_pa[i]) {
			free_page((unsigned long)__va(tdcs_pa[i]));
			tdcs_pa[i] = 0;
		}
	}
	if (!kvm_tdx->tdcs_pa)
		kfree(tdcs_pa);
	tdx_mmu_release_hkid(kvm);
	tdx_vm_free(kvm);
	return ret;

free_packages:
	cpus_read_unlock();
	free_cpumask_var(packages);
free_tdcs:
	for (i = 0; i < tdx_info->nr_tdcs_pages; i++) {
		if (tdcs_pa[i])
			free_page((unsigned long)__va(tdcs_pa[i]));
	}
	kfree(tdcs_pa);
	kvm_tdx->tdcs_pa = NULL;

free_tdr:
	if (tdr_pa)
		free_page((unsigned long)__va(tdr_pa));
	kvm_tdx->tdr_pa = 0;
free_hkid:
	if (is_hkid_assigned(kvm_tdx))
		tdx_hkid_free(kvm_tdx);
	return ret;
}

static u64 tdx_td_metadata_field_read(struct kvm_tdx *tdx, u64 field_id,
				      u64 *data)
{
	u64 err;

	err = tdh_mng_rd(tdx, field_id, data);

	return err;
}

#define TDX_MD_UNREADABLE_LEAF_MASK	GENMASK(30, 7)
#define TDX_MD_UNREADABLE_SUBLEAF_MASK	GENMASK(31, 7)

static int tdx_mask_cpuid(struct kvm_tdx *tdx, struct kvm_cpuid_entry2 *entry)
{
	u64 field_id = TD_MD_FIELD_ID_CPUID_VALUES;
	u64 ebx_eax, edx_ecx;
	u64 err = 0;

	if (entry->function & TDX_MD_UNREADABLE_LEAF_MASK ||
	    entry->index & TDX_MD_UNREADABLE_SUBLEAF_MASK)
		return -EINVAL;

	/*
	 * bit 23:17, REVSERVED: reserved, must be 0;
	 * bit 16,    LEAF_31: leaf number bit 31;
	 * bit 15:9,  LEAF_6_0: leaf number bits 6:0, leaf bits 30:7 are
	 *                      implicitly 0;
	 * bit 8,     SUBLEAF_NA: sub-leaf not applicable flag;
	 * bit 7:1,   SUBLEAF_6_0: sub-leaf number bits 6:0. If SUBLEAF_NA is 1,
	 *                         the SUBLEAF_6_0 is all-1.
	 *                         sub-leaf bits 31:7 are implicitly 0;
	 * bit 0,     ELEMENT_I: Element index within field;
	 */
	field_id |= ((entry->function & 0x80000000) ? 1 : 0) << 16;
	field_id |= (entry->function & 0x7f) << 9;
	if (entry->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX)
		field_id |= (entry->index & 0x7f) << 1;
	else
		field_id |= 0x1fe;

	err = tdx_td_metadata_field_read(tdx, field_id, &ebx_eax);
	if (err) //TODO check for specific errors
		goto err_out;

	entry->eax &= (u32) ebx_eax;
	entry->ebx &= (u32) (ebx_eax >> 32);

	field_id++;
	err = tdx_td_metadata_field_read(tdx, field_id, &edx_ecx);
	/*
	 * It's weird that reading edx_ecx fails while reading ebx_eax
	 * succeeded.
	 */
	if (WARN_ON_ONCE(err))
		goto err_out;

	entry->ecx &= (u32) edx_ecx;
	entry->edx &= (u32) (edx_ecx >> 32);
	return 0;

err_out:
	entry->eax = 0;
	entry->ebx = 0;
	entry->ecx = 0;
	entry->edx = 0;

	return -EIO;
}

static int tdx_td_init(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_vm *init_vm = NULL;
	struct td_params *td_params = NULL;
	int ret;

	BUILD_BUG_ON(sizeof(*init_vm) != 8 * 1024);
	BUILD_BUG_ON(sizeof(struct td_params) != 1024);

	if (is_hkid_assigned(kvm_tdx))
		return -EINVAL;

	if (cmd->flags)
		return -EINVAL;

	init_vm = kzalloc(sizeof(*init_vm) +
			  sizeof(init_vm->cpuid.entries[0]) * KVM_MAX_CPUID_ENTRIES,
			  GFP_KERNEL);
	if (!init_vm)
		return -ENOMEM;
	if (copy_from_user(init_vm, u64_to_user_ptr(cmd->data), sizeof(*init_vm))) {
		ret = -EFAULT;
		goto out;
	}
	if (init_vm->cpuid.nent > KVM_MAX_CPUID_ENTRIES) {
		ret = -E2BIG;
		goto out;
	}
	if (copy_from_user(init_vm->cpuid.entries,
			   u64_to_user_ptr(cmd->data) + sizeof(*init_vm),
			   flex_array_size(init_vm, cpuid.entries, init_vm->cpuid.nent))) {
		ret = -EFAULT;
		goto out;
	}

	if (memchr_inv(init_vm->reserved, 0, sizeof(init_vm->reserved))) {
		ret = -EINVAL;
		goto out;
	}
	if (init_vm->cpuid.padding) {
		ret = -EINVAL;
		goto out;
	}

	td_params = kzalloc(sizeof(struct td_params), GFP_KERNEL);
	if (!td_params) {
		ret = -ENOMEM;
		goto out;
	}

	ret = setup_tdparams(kvm, td_params, init_vm);
	if (ret)
		goto out;

	ret = __tdx_td_init(kvm, td_params, &cmd->hw_error);
	if (ret)
		goto out;

	kvm_tdx->tsc_offset = td_tdcs_exec_read64(kvm_tdx, TD_TDCS_EXEC_TSC_OFFSET);
	kvm_tdx->attributes = td_params->attributes;
	kvm_tdx->xfam = td_params->xfam;

	if (td_params->exec_controls & TDX_EXEC_CONTROL_MAX_GPAW)
		kvm->arch.gfn_direct_bits = gpa_to_gfn(BIT_ULL(51));
	else
		kvm->arch.gfn_direct_bits = gpa_to_gfn(BIT_ULL(47));

out:
	/* kfree() accepts NULL. */
	kfree(init_vm);
	kfree(td_params);
	return ret;
}

int tdx_vm_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;

	/*
	 * Userspace should never set @error. It is used to fill
	 * hardware-defined error by the kernel.
	 */
	if (tdx_cmd.hw_error)
		return -EINVAL;

	mutex_lock(&kvm->lock);

	switch (tdx_cmd.id) {
	case KVM_TDX_CAPABILITIES:
		r = tdx_get_capabilities(&tdx_cmd);
		break;
	case KVM_TDX_INIT_VM:
		r = tdx_td_init(kvm, &tdx_cmd);
		break;
	default:
		r = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &tdx_cmd, sizeof(struct kvm_tdx_cmd)))
		r = -EFAULT;

out:
	mutex_unlock(&kvm->lock);
	return r;
}

/* VMM can pass one 64bit auxiliary data to vcpu via RCX for guest BIOS. */
static int tdx_td_vcpu_init(struct kvm_vcpu *vcpu, u64 vcpu_rcx)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	unsigned long *tdcx_pa = NULL;
	unsigned long tdvpr_pa;
	unsigned long va;
	int ret, i;
	u64 err;

	if (is_td_vcpu_created(tdx))
		return -EINVAL;

	/*
	 * vcpu_free method frees allocated pages.  Avoid partial setup so
	 * that the method can't handle it.
	 */
	va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!va)
		return -ENOMEM;
	tdvpr_pa = __pa(va);

	tdcx_pa = kcalloc(tdx_info->nr_tdcx_pages, sizeof(*tdx->tdcx_pa),
			   GFP_KERNEL_ACCOUNT);
	if (!tdcx_pa) {
		ret = -ENOMEM;
		goto free_tdvpr;
	}

	tdx->tdcx_pa = tdcx_pa;
	for (i = 0; i < tdx_info->nr_tdcx_pages; i++) {
		va = __get_free_page(GFP_KERNEL_ACCOUNT);
		if (!va) {
			ret = -ENOMEM;
			goto free_tdvpx;
		}
		tdcx_pa[i] = __pa(va);
	}

	tdx->tdvpr_pa = tdvpr_pa;
	err = tdh_vp_create(tdx);
	if (KVM_BUG_ON(err, vcpu->kvm)) {
		tdx->tdvpr_pa = 0;
		ret = -EIO;
		pr_tdx_error(TDH_VP_CREATE, err);
		goto free_tdvpx;
	}

	for (i = 0; i < tdx_info->nr_tdcx_pages; i++) {
		err = tdh_vp_addcx(tdx, tdcx_pa[i]);
		if (KVM_BUG_ON(err, vcpu->kvm)) {
			pr_tdx_error(TDH_VP_ADDCX, err);
			for (; i < tdx_info->nr_tdcx_pages; i++) {
				free_page((unsigned long)__va(tdcx_pa[i]));
				tdcx_pa[i] = 0;
			}
			/* vcpu_free method frees TDCX and TDR donated to TDX */
			return -EIO;
		}
	}

	if (tdx_info->features0 & MD_FIELD_ID_FEATURES0_TOPOLOGY_ENUM)
		err = tdh_vp_init_apicid(tdx, vcpu_rcx, vcpu->vcpu_id);
	else
		err = tdh_vp_init(tdx, vcpu_rcx);
	if (KVM_BUG_ON(err, vcpu->kvm)) {
		pr_tdx_error(TDH_VP_INIT, err);
		return -EIO;
	}

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	tdx->td_vcpu_created = true;
	return 0;

free_tdvpx:
	for (i = 0; i < tdx_info->nr_tdcx_pages; i++) {
		if (tdcx_pa[i])
			free_page((unsigned long)__va(tdcx_pa[i]));
		tdcx_pa[i] = 0;
	}
	kfree(tdcx_pa);
	tdx->tdcx_pa = NULL;
free_tdvpr:
	if (tdvpr_pa)
		free_page((unsigned long)__va(tdvpr_pa));
	tdx->tdvpr_pa = 0;

	return ret;
}

static int tdx_get_kvm_supported_cpuid(struct kvm_cpuid2 **cpuid) {
	int r;
	static const u32 funcs[] = {
		0, 0x80000000, KVM_CPUID_SIGNATURE,
	};
	struct kvm_cpuid_entry2 *entry;

	*cpuid = kzalloc(sizeof(struct kvm_cpuid2) +
			sizeof(struct kvm_cpuid_entry2) * KVM_MAX_CPUID_ENTRIES,
			GFP_KERNEL);
	if (!*cpuid)
		return -ENOMEM;
	(*cpuid)->nent = KVM_MAX_CPUID_ENTRIES;
	r = kvm_get_supported_cpuid_internal(*cpuid, funcs, ARRAY_SIZE(funcs));
	if (r)
		goto err;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x0, 0);
	if (WARN_ON(!entry))
		goto err;
	entry->eax |= 0x000000FF;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x1, 0);
	if (WARN_ON(!entry))
		goto err;

	/* 
	 * TODO: Drop the below, if this makes it upstream:
	 * https://lore.kernel.org/kvm/20240517173926.965351-34-seanjc@google.com/#t
	 */
	cpuid_entry_set(entry, X86_FEATURE_TSC_DEADLINE_TIMER);
	cpuid_entry_set(entry, X86_FEATURE_HT);
	entry->eax |= 0x0000000F;
	entry->ebx |= 0x00ff0000;
	entry->ecx |= 0xF0000011;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x4, 0);
	if (WARN_ON(!entry))
		goto err;
	entry->eax |= 0x0FF3390D;
	entry->ebx |= 0xFF000000;
	entry->ecx |= 0x00044988;
	entry->edx |= 0xA0400001;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x4, 1);
	if (WARN_ON(!entry))
		goto err;
	entry->ebx |= 0xFF000000;
	entry->edx |= 0x00000001;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x4, 2);
	if (WARN_ON(!entry))
		goto err;
	entry->ecx |= 0x00000F00;
	entry->edx |= 0x00000001;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x4, 3);
	if (WARN_ON(!entry))
		goto err;
	entry->ebx |= 0x0F000000;
	entry->edx |= 0x00000007;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x7, 0);
	if (WARN_ON(!entry))
		goto err;
	cpuid_entry_set(entry, X86_FEATURE_AVX512_4VNNIW);
	cpuid_entry_set(entry, X86_FEATURE_FLUSH_L1D);
	cpuid_entry_set(entry, X86_FEATURE_ARCH_CAPABILITIES);
	cpuid_entry_set(entry, X86_FEATURE_CORE_CAPABILITIES);
	cpuid_entry_set(entry, X86_FEATURE_SPEC_CTRL_SSBD);

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0xb, 0);
	if (WARN_ON(!entry))
		goto err;
	entry->ebx |= 0x00000001;
	entry->ecx |= 0x00000100;

	entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x1f, 0);
	if (WARN_ON(!entry))
		goto err;
	entry->eax |= 0x0000011F;
	entry->ebx |= 0x00000101;
	entry->ecx |= 0x0000FFFF;

	for(int i = 1; i <= 5; i++) {
		entry = kvm_find_cpuid_entry2((*cpuid)->entries, (*cpuid)->nent, 0x1f, i);
		if (!entry) {
			entry = &(*cpuid)->entries[(*cpuid)->nent];
			entry->function = 0x1f;
			entry->index = 0;
			entry->flags = 0;
			(*cpuid)->nent++;
		}
		entry->eax |= 0x0000FFFF;
		entry->ebx |= 0x0000FFFF;
		entry->ecx |= 0x0000FFFF;
	}

	return 0;
err:
	kfree(*cpuid);
	*cpuid = NULL;
	return r;
}

static int tdx_vcpu_get_cpuid(struct kvm_vcpu *vcpu, struct kvm_tdx_cmd *cmd)
{
	struct kvm_cpuid2 __user *output, *td_cpuid;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct kvm_cpuid2 *supported_cpuid;
	int r = 0, i, j = 0;

	output = u64_to_user_ptr(cmd->data);
	td_cpuid = kzalloc(sizeof(*td_cpuid) +
			sizeof(output->entries[0]) * KVM_MAX_CPUID_ENTRIES,
			GFP_KERNEL);
	if (!td_cpuid)
		return -ENOMEM;

	r = tdx_get_kvm_supported_cpuid(&supported_cpuid);
	if (r)
		goto out;

	for (i = 0; i < supported_cpuid->nent; i++) {
		struct kvm_cpuid_entry2 *supported = &supported_cpuid->entries[i];
		struct kvm_cpuid_entry2 *output_e = &td_cpuid->entries[j];

		*output_e = *supported;

		/* Only allow values of bits that KVM's supports to be exposed */
		if (tdx_mask_cpuid(kvm_tdx, output_e))
			continue;

		/*
		 * Work around missing support on old TDX modules, fetch
		 * guest maxpa from gfn_direct_bits.
		 */
		if (output_e->function == 0x80000008) {
			gpa_t gpa_bits = gfn_to_gpa(kvm_gfn_direct_bits(vcpu->kvm));
			unsigned int g_maxpa = __ffs(gpa_bits) + 1;

			output_e->eax &= ~0x00ff0000;
			output_e->eax |= g_maxpa << 16;
		}

		j++;
	}
	td_cpuid->nent = j;

	if (copy_to_user(output, td_cpuid, sizeof(*output))) {
		r = -EFAULT;
		goto out;
	}
	if (copy_to_user(output->entries, td_cpuid->entries, td_cpuid->nent * sizeof(struct kvm_cpuid_entry2)))
		r = -EFAULT;

out:
	kfree(td_cpuid);
	kfree(supported_cpuid);
	return r;
}

static int tdx_vcpu_init(struct kvm_vcpu *vcpu, struct kvm_tdx_cmd *cmd)
{
	struct msr_data apic_base_msr;
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int ret;

	if (cmd->flags)
		return -EINVAL;
	if (tdx->initialized)
		return -EINVAL;

	/*
	 * As TDX requires X2APIC, set local apic mode to X2APIC.  User space
	 * VMM, e.g. qemu, is required to set CPUID[0x1].ecx.X2APIC=1 by
	 * KVM_SET_CPUID2.  Otherwise kvm_set_apic_base() will fail.
	 */
	apic_base_msr = (struct msr_data) {
		.host_initiated = true,
		.data = APIC_DEFAULT_PHYS_BASE | LAPIC_MODE_X2APIC |
		(kvm_vcpu_is_reset_bsp(vcpu) ? MSR_IA32_APICBASE_BSP : 0),
	};
	if (kvm_set_apic_base(vcpu, &apic_base_msr))
		return -EINVAL;

	ret = tdx_td_vcpu_init(vcpu, (u64)cmd->data);
	if (ret)
		return ret;

	tdx->initialized = true;
	return 0;
}

int tdx_vcpu_ioctl(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct kvm_tdx_cmd cmd;
	int ret;

	if (!is_hkid_assigned(kvm_tdx) || is_td_finalized(kvm_tdx))
		return -EINVAL;

	if (copy_from_user(&cmd, argp, sizeof(cmd)))
		return -EFAULT;

	if (cmd.hw_error)
		return -EINVAL;

	switch (cmd.id) {
	case KVM_TDX_INIT_VCPU:
		ret = tdx_vcpu_init(vcpu, &cmd);
		break;
	case KVM_TDX_GET_CPUID:
		ret = tdx_vcpu_get_cpuid(vcpu, &cmd);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}


#define KVM_SUPPORTED_TD_ATTRS (TDX_TD_ATTR_SEPT_VE_DISABLE)

static int __init setup_kvm_tdx_caps(void)
{
	struct kvm_tdx_cpuid_config *dest, *source;
	struct kvm_cpuid_entry2 *cpuid_e;
	struct kvm_cpuid2 *supported_cpuid;
	u64 kvm_supported;
	int i, r;

	kvm_tdx_caps = kzalloc(sizeof(*kvm_tdx_caps) +
			       sizeof(struct kvm_tdx_cpuid_config) * tdx_info->num_cpuid_config + 1,
			       GFP_KERNEL);
	if (!kvm_tdx_caps)
		return -ENOMEM;

	kvm_supported = KVM_SUPPORTED_TD_ATTRS;
	if (((kvm_supported | tdx_info->attributes_fixed1) & tdx_info->attributes_fixed0) != kvm_supported)
		return -EIO;
	kvm_tdx_caps->supported_attrs = kvm_supported;

	kvm_supported = kvm_caps.supported_xcr0 | kvm_caps.supported_xss;
	/*
	 * PT and CET can be exposed to TD guest regardless of KVM's XSS, PT
	 * and, CET support.
	 */
	kvm_supported |= XFEATURE_MASK_PT | XFEATURE_MASK_CET_USER |
			 XFEATURE_MASK_CET_KERNEL;
	if (((kvm_supported | tdx_info->xfam_fixed1) & tdx_info->xfam_fixed0) != kvm_supported)
		return -EIO;
	kvm_tdx_caps->supported_xfam = kvm_supported;

	r = tdx_get_kvm_supported_cpuid(&supported_cpuid);
	if (r)
		goto out;

	kvm_tdx_caps->num_cpuid_config = tdx_info->num_cpuid_config;
	for (i = 0; i < tdx_info->num_cpuid_config; i++)
	{
		source = &tdx_info->cpuid_configs[i];
		dest = &kvm_tdx_caps->cpuid_configs[i];
		memcpy(dest, source, sizeof(struct kvm_tdx_cpuid_config));
		if (dest->sub_leaf == KVM_TDX_CPUID_NO_SUBLEAF)
			dest->sub_leaf = 0;

		/* Work around missing support on old TDX modules */
		if (dest->leaf == 0x80000008)
			dest->eax |= 0x00ff0000;

		cpuid_e = kvm_find_cpuid_entry2(supported_cpuid->entries, supported_cpuid->nent,
						dest->leaf, dest->sub_leaf);
		if (!cpuid_e) {
			dest->eax = dest->ebx = dest->ecx = dest->edx = 0;
		} else {
			dest->eax &= cpuid_e->eax;
			dest->ebx &= cpuid_e->ebx;
			dest->ecx &= cpuid_e->ecx;
			dest->edx &= cpuid_e->edx;
		}
	}

out:
	kfree(supported_cpuid);
	return r;
}

static int __init tdx_module_setup(void)
{
	struct st {
		u16 num_cpuid_config;
		u16 tdcs_base_size;
		u16 tdvps_base_size;
	} st;
	u64 tmp;
	int ret;
	u32 i;

#define TDX_INFO_MAP(_field_id, _member)		\
	TD_SYSINFO_MAP(_field_id, struct st, _member)

	struct tdx_metadata_field_mapping st_fields[] = {
		TDX_INFO_MAP(NUM_CPUID_CONFIG, num_cpuid_config),
		TDX_INFO_MAP(TDCS_BASE_SIZE, tdcs_base_size),
		TDX_INFO_MAP(TDVPS_BASE_SIZE, tdvps_base_size),
	};
#undef TDX_INFO_MAP

#define TDX_INFO_MAP(_field_id, _member)			\
	TD_SYSINFO_MAP(_field_id, struct tdx_info, _member)

	struct tdx_metadata_field_mapping fields[] = {
		TDX_INFO_MAP(FEATURES0, features0),
		TDX_INFO_MAP(ATTRS_FIXED0, attributes_fixed0),
		TDX_INFO_MAP(ATTRS_FIXED1, attributes_fixed1),
		TDX_INFO_MAP(XFAM_FIXED0, xfam_fixed0),
		TDX_INFO_MAP(XFAM_FIXED1, xfam_fixed1),
	};
#undef TDX_INFO_MAP

	ret = tdx_enable();
	if (ret)
		return ret;

	ret = tdx_sys_metadata_read(st_fields, ARRAY_SIZE(st_fields), &st);
	if (ret)
		return ret;

	tdx_info = kzalloc(sizeof(*tdx_info) +
			   sizeof(*tdx_info->cpuid_configs) * st.num_cpuid_config,
			   GFP_KERNEL);
	if (!tdx_info)
		return -ENOMEM;
	tdx_info->num_cpuid_config = st.num_cpuid_config;

	/*
	 * TDX module may not support MD_FIELD_ID_MAX_VCPUS_PER_TD depending
	 * on its version.
	 */
	tdx_info->max_vcpus_per_td = U16_MAX;
	if (!tdx_sys_metadata_field_read(MD_FIELD_ID_MAX_VCPUS_PER_TD, &tmp))
		tdx_info->max_vcpus_per_td = (u16)tmp;

	ret = tdx_sys_metadata_read(fields, ARRAY_SIZE(fields), tdx_info);
	if (ret)
		goto error_out;

	for (i = 0; i < st.num_cpuid_config; i++) {
		struct kvm_tdx_cpuid_config *c = &tdx_info->cpuid_configs[i];
		struct cpuid_st {
			u64 leaf;
			u64 eax_ebx;
			u64 ecx_edx;
		} cpuid_st;

#define TDX_INFO_MAP(_field_id, _member)			\
	TD_SYSINFO_MAP(_field_id, struct cpuid_st, _member)

		struct tdx_metadata_field_mapping cpuid_fields[] = {
			TDX_INFO_MAP(CPUID_CONFIG_LEAVES + i, leaf),
			TDX_INFO_MAP(CPUID_CONFIG_VALUES + i * 2, eax_ebx),
			TDX_INFO_MAP(CPUID_CONFIG_VALUES + i * 2 + 1, ecx_edx),
		};
#undef TDX_INFO_MAP

		ret = tdx_sys_metadata_read(cpuid_fields, ARRAY_SIZE(cpuid_fields),
					    &cpuid_st);
		if (ret)
			goto error_out;

		c->leaf = (u32)cpuid_st.leaf;
		c->sub_leaf = cpuid_st.leaf >> 32;
		c->eax = (u32)cpuid_st.eax_ebx;
		c->ebx = cpuid_st.eax_ebx >> 32;
		c->ecx = (u32)cpuid_st.ecx_edx;
		c->edx = cpuid_st.ecx_edx >> 32;
	}

	tdx_info->nr_tdcs_pages = st.tdcs_base_size / PAGE_SIZE;
	/*
	 * TDVPS = TDVPR(4K page) + TDCX(multiple 4K pages).
	 * -1 for TDVPR.
	 */
	tdx_info->nr_tdcx_pages = st.tdvps_base_size / PAGE_SIZE - 1;

	/*
	 * Make TDH.VP.ENTER preserve RBP so that the stack unwinder
	 * always work around it.  Query the feature.
	 */
	if (!(tdx_info->features0 & MD_FIELD_ID_FEATURES0_NO_RBP_MOD) &&
	    !IS_ENABLED(CONFIG_FRAME_POINTER)) {
		pr_err("Too old version of TDX module. Consider upgrade.\n");
		ret = -EOPNOTSUPP;
		goto error_out;
	}

	ret = setup_kvm_tdx_caps();
	if (ret)
		goto error_out;

	return 0;

error_out:
	/* kfree() accepts NULL. */
	kfree(tdx_info);
	return ret;
}

struct tdx_enabled {
	cpumask_var_t enabled;
	atomic_t err;
};

static void __init tdx_on(void *_enable)
{
	struct tdx_enabled *enable = _enable;
	int r;

	r = vmx_hardware_enable();
	if (!r) {
		cpumask_set_cpu(smp_processor_id(), enable->enabled);
		r = tdx_cpu_enable();
	}
	if (r)
		atomic_set(&enable->err, r);
}

static void __init vmx_off(void *_enabled)
{
	cpumask_var_t *enabled = (cpumask_var_t *)_enabled;

	if (cpumask_test_cpu(smp_processor_id(), *enabled))
		vmx_hardware_disable();
}

int __init tdx_hardware_setup(struct kvm_x86_ops *x86_ops)
{
	struct tdx_enabled enable = {
		.err = ATOMIC_INIT(0),
	};
	int max_pkgs;
	int r = 0;
	int i;

	if (!cpu_feature_enabled(X86_FEATURE_MOVDIR64B)) {
		pr_warn("MOVDIR64B is reqiured for TDX\n");
		return -EOPNOTSUPP;
	}
	if (!enable_ept) {
		pr_warn("Cannot enable TDX with EPT disabled\n");
		return -EINVAL;
	}

	max_pkgs = topology_max_packages();
	tdx_mng_key_config_lock = kcalloc(max_pkgs, sizeof(*tdx_mng_key_config_lock),
				   GFP_KERNEL);
	if (!tdx_mng_key_config_lock)
		return -ENOMEM;
	for (i = 0; i < max_pkgs; i++)
		mutex_init(&tdx_mng_key_config_lock[i]);

	if (!zalloc_cpumask_var(&enable.enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out;
	}

	/* tdx_enable() in tdx_module_setup() requires cpus lock. */
	cpus_read_lock();
	on_each_cpu(tdx_on, &enable, true); /* TDX requires vmxon. */
	r = atomic_read(&enable.err);
	if (!r)
		r = tdx_module_setup();
	else
		r = -EIO;
	on_each_cpu(vmx_off, &enable.enabled, true);
	cpus_read_unlock();
	free_cpumask_var(enable.enabled);

out:
	return r;
}

void tdx_hardware_unsetup(void)
{
	kfree(tdx_info);
	kfree(tdx_mng_key_config_lock);
}

int tdx_offline_cpu(void)
{
	int i, curr_cpu = smp_processor_id();

	/* No TD is running.  Allow any cpu to be offline. */
	if (ida_is_empty(&tdx_guest_keyid_pool))
		return 0;

	/*
	 * In order to reclaim TDX HKID, (i.e. when deleting guest TD), need to
	 * call TDH.PHYMEM.PAGE.WBINVD on all packages to program all memory
	 * controller with pconfig.  If we have active TDX HKID, refuse to
	 * offline the last online cpu.
	 */
	for_each_online_cpu(i) {
		/*
		 * Found another online cpu on the same package.
		 * Allow to offline.
		 */
		if (i != curr_cpu && topology_physical_package_id(i) ==
				topology_physical_package_id(curr_cpu))
			return 0;
	}

	/*
	 * This is the last cpu of this package.  Don't offline it.
	 *
	 * Because it's hard for human operator to understand the
	 * reason, warn it.
	 */
#define MSG_ALLPKG_ONLINE \
	"TDX requires all packages to have an online CPU. Delete all TDs in order to offline all CPUs of a package.\n"
	pr_warn_ratelimited(MSG_ALLPKG_ONLINE);
	return -EBUSY;
}
