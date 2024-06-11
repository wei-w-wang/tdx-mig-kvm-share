// SPDX-License-Identifier: GPL-2.0

#define TDX_MIG_MAX_STREAM_NR 1

#define TDX_MIG_MBMD_NPAGES 1

#define TDX_MIGTD_ATTR 0x000007ff00000000

/* A SHA384 hash takes up 48 bytes */
#define KVM_TDX_SERVTD_HASH_SIZE 48

/*
 * A binding table is TDX internal implementation for each TD to hold its
 * binding information (details in the TDX ABI spec). For simplicity,
 * statically reserve index 0 of the binding table from the user TD for MigTD.
 */
#define TDX_SERVTD_BINDING_TABLE_INDEX_MIGTD	0

/* Defined by the TDX ABI spec */
#define TDX_SERVTD_TYPE_MIGTD		0

struct tdx_mig_state {
	uint32_t nr_ubuf_pages;
	uint32_t nr_streams;
	/*
	 * Array to store physical addresses of the migration stream context
	 * pages that have been added to the TDX module. The pages can be
	 * reclaimed from TDX when TD is torn down.
	 */
	hpa_t *migsc_paddrs;
	hpa_t backward_migsc_paddr;
};

struct tdx_mig_capabilities {
	uint32_t max_migs;
	uint32_t immutable_state_pages;
	uint32_t td_state_pages;
	uint32_t vcpu_state_pages;
};

static struct tdx_mig_capabilities tdx_mig_caps;

static void tdx_reclaim_control_page(unsigned long td_page_pa);

static int tdx_mig_capabilities_setup(void)
{
	uint64_t value;
	int ret;

	ret = tdx_sys_metadata_field_read(MD_FIELD_ID_MAX_MIGS, &value);
	if (ret)
		return ret;
	tdx_mig_caps.max_migs = (uint32_t)value;

	ret = tdx_sys_metadata_field_read(MD_FIELD_ID_IMMUTABLE_STATE_PAGES,
					  &value);
	if (ret)
		return ret;
	tdx_mig_caps.immutable_state_pages = (uint32_t)value;

	ret = tdx_sys_metadata_field_read(MD_FIELD_ID_TD_STATE_PAGES, &value);
	if (ret)
		return ret;
	tdx_mig_caps.td_state_pages = (uint32_t)value;

	ret = tdx_sys_metadata_field_read(MD_FIELD_ID_VP_STATE_PAGES, &value);
	if (ret)
		return ret;
	tdx_mig_caps.vcpu_state_pages = (uint32_t)value;

	return 0;
}

int tdx_mig_enable_cap(struct kvm *kvm, struct kvm_cap_cgm *cap_cgm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	unsigned int nr_immutable_pages, nr_vcpu_pages, nr_memory_pages;

	nr_immutable_pages = tdx_mig_caps.immutable_state_pages +
			     TDX_MIG_MBMD_NPAGES;
	/* The first vcpu state is combined together with TD state data */
	nr_vcpu_pages = tdx_mig_caps.vcpu_state_pages + TDX_MIG_MBMD_NPAGES +
			tdx_mig_caps.td_state_pages + TDX_MIG_MBMD_NPAGES;
	/* Plus 1 MBMD page, 1 GPA list page and 1 MAC list page */
	nr_memory_pages = cap_cgm->nr_ubuf_pages + 3;

	mig_state->nr_ubuf_pages = (uint32_t)max3(nr_immutable_pages,
						  nr_vcpu_pages,
						  nr_memory_pages);
	mig_state->nr_streams = min_t(uint32_t, TDX_MIG_MAX_STREAM_NR,
				      cap_cgm->nr_threads);
	cap_cgm->nr_ubuf_pages = mig_state->nr_ubuf_pages;
	cap_cgm->nr_threads = mig_state->nr_streams;

	return 0;
}

static int tdx_mig_state_create(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state;
	hpa_t *migsc_paddrs;

	if (kvm_tdx->mig_state) {
		pr_warn("unexpected: mig_state already created\n");
		return -EEXIST;
	}

	mig_state = kzalloc(sizeof(struct tdx_mig_state), GFP_KERNEL_ACCOUNT);
	if (!mig_state)
		return -ENOMEM;

	migsc_paddrs = kcalloc(tdx_mig_caps.max_migs, sizeof(hpa_t),
			       GFP_KERNEL_ACCOUNT);
	if (!migsc_paddrs) {
		kfree(mig_state);
		return -ENOMEM;
	}

	mig_state->migsc_paddrs = migsc_paddrs;
	kvm_tdx->mig_state = mig_state;
	return 0;
}

static void tdx_mig_state_destroy(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	uint32_t i;

	if (!mig_state)
		return;

	if (mig_state->backward_migsc_paddr)
		tdx_reclaim_control_page(mig_state->backward_migsc_paddr);

	for (i = 0; i < tdx_mig_caps.max_migs; i++) {
		if (!mig_state->migsc_paddrs[i])
			break;

		tdx_reclaim_control_page(mig_state->migsc_paddrs[i]);
	}

	kfree(mig_state->migsc_paddrs);
	kfree(mig_state);
	kvm_tdx->mig_state = NULL;
}

static int tdx_mig_prebind_migtd(struct kvm_tdx *kvm_tdx, void *hash)
{
	struct page *hash_page;
	u64 err;

	hash_page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!hash_page)
		return -ENOMEM;

	memcpy(page_to_virt(hash_page), hash, KVM_TDX_SERVTD_HASH_SIZE);

	err = tdh_servtd_prebind(kvm_tdx->tdr_pa,
				 page_to_phys(hash_page),
				 TDX_SERVTD_BINDING_TABLE_INDEX_MIGTD,
				 TDX_MIGTD_ATTR,
				 TDX_SERVTD_TYPE_MIGTD);
	__free_page(hash_page);
	if (err) {
		pr_warn("failed to prebind migtd, err=%llx\n", err);
		return -EIO;
	}

	return 0;
}

static void tdx_notify_migtd(struct kvm_tdx *tdx)
{
	struct kvm *kvm;
	struct kvm_vcpu *vcpu;
	unsigned long i;

	kvm = &tdx->kvm;
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (vcpu->arch.mp_state == KVM_MP_STATE_HALTED) {
			vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
			kvm_vcpu_kick(vcpu);
		}
	}
}

static void tdx_put_binding_info(struct kvm_tdx *tdx)
{
	struct tdx_binding_info *binding_info = tdx->binding_info;

	if (!binding_info)
		return;

	if (refcount_dec_and_test(&binding_info->users_count))
		kfree(binding_info);

	tdx->binding_info = NULL;
}

static void tdx_mig_set_binding_info(struct tdx_binding_info *info,
				     bool is_src, uint64_t handle,
				     uint64_t uuid0, uint64_t uuid1,
				     uint64_t uuid2, uint64_t uuid3)
{
	info->is_src = is_src;
	info->handle = handle;
	memcpy(&info->uuid[0], &uuid0, sizeof(uint64_t));
	memcpy(&info->uuid[8], &uuid1, sizeof(uint64_t));
	memcpy(&info->uuid[16], &uuid2, sizeof(uint64_t));
	memcpy(&info->uuid[24], &uuid3, sizeof(uint64_t));
}

static int tdx_bind_migtd(struct kvm_tdx *usertd_tdx,
			  struct kvm_tdx *migtd_tdx,
			  bool is_src)
{
	u64 err;
	struct tdx_module_args out;
	struct tdx_binding_info *binding_info;

	if (usertd_tdx->binding_info) {
		binding_info = usertd_tdx->binding_info;
		memset(binding_info, 0, sizeof(struct tdx_binding_info));
	} else {
		binding_info = kzalloc(sizeof(struct tdx_binding_info),
				       GFP_KERNEL);
		if (!binding_info)
			return -ENOMEM;
	}

	/*TODO: check max binding_slots_id from rdall */
	err = tdh_servtd_bind(migtd_tdx->tdr_pa,
			      usertd_tdx->tdr_pa,
			      TDX_SERVTD_BINDING_TABLE_INDEX_MIGTD,
			      TDX_MIGTD_ATTR,
			      TDX_SERVTD_TYPE_MIGTD,
			      &out);
	if (KVM_BUG_ON(err, &usertd_tdx->kvm)) {
		pr_tdx_error(TDH_SERVTD_BIND, err, &out);
		return -EIO;
	}
	tdx_mig_set_binding_info(binding_info, is_src, out.rcx,
				 out.r10, out.r11, out.r12, out.r13);

	refcount_set(&binding_info->users_count, 2);
	usertd_tdx->binding_info = binding_info;
	migtd_tdx->binding_info = binding_info;

	return 0;
}

static int tdx_mig_stream_create(struct kvm_tdx *kvm_tdx, hpa_t *migsc_paddr)
{
	unsigned long migsc_va, migsc_pa;
	uint64_t err;

	/*
	 * This migration stream has been created, e.g. the previous migration
	 * session is aborted and the migration stream is retained during the
	 * TD guest lifecycle (required by the TDX migration architecture)
	 * for later re-migration). No need to proceed to the creation in this
	 * case.
	 */
	if (*migsc_paddr)
		return 0;

	migsc_va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!migsc_va)
		return -ENOMEM;
	migsc_pa = __pa(migsc_va);

	err = tdh_mig_stream_create(kvm_tdx->tdr_pa, migsc_pa);
	if (WARN_ON_ONCE(err)) {
		pr_tdx_error(TDH_MIG_STREAM_CREATE, err, NULL);
		free_page(migsc_va);
		return -EIO;
	}

	*migsc_paddr = migsc_pa;

	return 0;
}

static int tdx_mig_state_setup(struct kvm_tdx *kvm_tdx)
{
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	int i, ret;

	ret = tdx_mig_stream_create(kvm_tdx, &mig_state->backward_migsc_paddr);
	if (ret)
		return ret;

	for (i = 0; i < mig_state->nr_streams; i++) {
		ret = tdx_mig_stream_create(kvm_tdx, &mig_state->migsc_paddrs[i]);
		if (ret)
			return ret;
	}

	return 0;
}

int tdx_mig_prepare(struct kvm *kvm, struct kvm_cgm_prepare *prepare)
{
	int ret;
	struct kvm *migtd_kvm;
	struct kvm_tdx *migtd_tdx;
	struct kvm_tdx *usertd_tdx = to_kvm_tdx(kvm);

	migtd_kvm = kvm_get_target_kvm(&prepare->vmid);
	if (!migtd_kvm || !is_td(migtd_kvm)) {
		return -ENOENT;
	}
	migtd_tdx = to_kvm_tdx(migtd_kvm);

	ret = tdx_bind_migtd(usertd_tdx, migtd_tdx, prepare->is_src);
	if (ret)
		return ret;

	tdx_notify_migtd(migtd_tdx);

	return tdx_mig_state_setup(usertd_tdx);
}
