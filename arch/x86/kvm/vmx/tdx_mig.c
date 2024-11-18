// SPDX-License-Identifier: GPL-2.0

#define TDX_MIG_MAX_STREAM_NR 1

#define TDX_MIG_MBMD_NPAGES 1

struct tdx_mig_mbmd_data {
	__u16 size;
	__u16 mig_version;
	__u16 migs_index;
	__u8  mb_type;
	__u8  rsvd0;
	__u32 mb_counter;
	__u32 mig_epoch;
	__u64 iv_counter;
	__u8  type_specific_info[];
} __packed;

struct tdx_mig_mbmd {
	struct tdx_mig_mbmd_data *data;
	uint64_t addr_and_size;
};

/*
 * A MAC list specifies a list of MACs (message authentication code), and is
 * used by TDH.EXPORT.MEM and TDH.IMPORT.MEM via its physical address, @hpa.
 * The list is pointed by @entries and each entry in the list is 128-bit
 * MAC containing a single AES-GMAC-256. Each MAC in the list is calculated by
 * the TDX module over a 4KB guest private page and its corresponding GPA entry
 * (from the gpa_list) to ensure their integrity during migration. The size of
 * the list is 4KB, allowing it to accommodate up to 256 entries.
 */
struct tdx_mig_mac_list {
	void *entries;
	hpa_t hpa;
};

union tdx_mig_gpa_list_entry {
	uint64_t val;
	struct{
		uint64_t level          : 2;   // Bits 1:0  :  Mapping level
		uint64_t pending        : 1;   // Bit 2     :  Page is pending
		uint64_t reserved_0     : 4;   // Bits 6:3
		uint64_t l2_map         : 3;   // Bits 9:7  :  L2 mapping flags
		uint64_t mig_type       : 2;   // Bits 11:10:  Migration type
		uint64_t gfn            : 40;  // Bits 51:12
#define GPA_LIST_OP_NOP		0
#define GPA_LIST_OP_BLOCKW	1
#define GPA_LIST_OP_EXPORT	1
#define GPA_LIST_OP_RESTORE	1
#define GPA_LIST_OP_CANCEL	2
		uint64_t operation      : 2;   // Bits 53:52
		uint64_t reserved_1     : 2;   // Bits 55:54
#define GPA_LIST_S_SUCCESS	0
		uint64_t status         : 5;   // Bits 56:52
		uint64_t reserved_2     : 3;   // Bits 63:61
	};
};

/*
 * A GPA list specifies a list of GPAs, and is used by TDH.EXPORT.MEM and
 * TDH.IMPORT.MEM, TDH.EXPORT.BLOCKW, and TDH.EXPORT.RESTORE via its physical
 * address contained in @info. The list is pointed by @entries, and each entry
 * is a 64-bit value containing a guest physical address and relevant info. The
 * size of the list is 4KB, allowing it to accommodate up to 512 entries.
 */
union tdx_mig_gpa_list_info {
	uint64_t val;
	struct {
		uint64_t rsvd0		: 3;
		uint64_t first_entry	: 9;
		uint64_t pfn		: 40;
		uint64_t rsvd1		: 3;
		uint64_t last_entry	: 9;
	};
};

struct tdx_mig_gpa_list {
	union tdx_mig_gpa_list_entry *entries;
	union tdx_mig_gpa_list_info info;
};

/*
 * A buffer list specifies a list of 4KB pages, and is used by TDH.EXPORT.MEM
 * and TDH.IMPORT.MEM via its physical address, @hpa, to export and import
 * guest private memory page data. The list is pointed by @entries and each
 * entry is a 64-bit value containing the physical address of a 4KB page that
 * is used as a buffer. The size of the list is 4KB, allowing it to accommodate
 * up to 512 entries.
 */
union tdx_mig_buf_list_entry {
	uint64_t val;
	struct {
		uint64_t rsvd0		: 12;
		uint64_t pfn		: 40;
		uint64_t rsvd1		: 11;
		uint64_t invalid	: 1;
	};
};

struct tdx_mig_buf_list {
	union tdx_mig_buf_list_entry *entries;
	hpa_t hpa;
};

/*
 * A page list specifies a list of 4KB pages to be used by the non-memory
 * states export and import, i.e. TDH.EXPORT.STATE.* and TDH.IMPORT.STATE.* via
 * its physical address contained in @info. The list is pointed by @entries and
 * each entry is a 64-bit value containing the physical address of a 4KB page
 * that is used as a buffer. The size of the list is 4KB, allowing it to
 * accommodate up to 512 entries.
 */
union tdx_mig_page_list_info {
	uint64_t val;
	struct {
		uint64_t rsvd0		: 12;
		uint64_t pfn		: 40;
		uint64_t rsvd1		: 3;
		uint64_t last_entry	: 9;
	};
};

struct tdx_mig_page_list {
	hpa_t *entries;
	union tdx_mig_page_list_info info;
};

struct tdx_mig_stream {
	uint16_t idx;
	struct tdx_mig_mbmd mbmd;
	/* List of MACs used when export/import the TD private memory */
	struct tdx_mig_mac_list mac_list;
	/* List of GPA entries used when export/import the TD private memory */
	struct tdx_mig_gpa_list gpa_list;
	/* List of buffers to export/import the TD private memory data */
	struct tdx_mig_buf_list mem_buf_list;
	/* List of buffers to export/miport the TD non-memory state data */
	struct tdx_mig_page_list page_list;
	/*
	 * Array of "struct page" to use with pin_user_pages() on ubufs (i.e.,
	 * buffers shared from userspace) to export/import the TD private
	 * state.
	 */
	struct page **pages;
};

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
	struct tdx_mig_stream stream;
};

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

static void tdx_reclaim_control_page(unsigned long td_page_pa);

int tdx_mig_enable_cap(struct kvm *kvm, struct kvm_cap_cgm *cap_cgm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	const struct tdx_sys_info_td_mig_cap *td_mig_cap =
						&tdx_sysinfo->td_mig_cap;
	unsigned int nr_immutable_pages, nr_vcpu_pages, nr_memory_pages;

	nr_immutable_pages = td_mig_cap->immutable_state_pages +
			     TDX_MIG_MBMD_NPAGES;
	/* The first vcpu state is combined together with TD state data */
	nr_vcpu_pages = td_mig_cap->vcpu_state_pages + TDX_MIG_MBMD_NPAGES +
			td_mig_cap->td_state_pages + TDX_MIG_MBMD_NPAGES;
	/* Plus 1 MBMD page, 1 GPA list page and 1 MAC list page */
	nr_memory_pages = cap_cgm->nr_ubuf_pages + 3;

	mig_state->nr_ubuf_pages = (uint32_t)max3(nr_immutable_pages,
						  nr_vcpu_pages,
						  nr_memory_pages);
	mig_state->nr_streams = min(TDX_MIG_MAX_STREAM_NR,
				    cap_cgm->nr_threads);
	cap_cgm->nr_ubuf_pages = mig_state->nr_ubuf_pages;
	cap_cgm->nr_threads = mig_state->nr_streams;

	return 0;
}

static int tdx_mig_state_create(struct kvm_tdx *kvm_tdx)
{
	const struct tdx_sys_info_td_mig_cap *td_mig_cap =
						&tdx_sysinfo->td_mig_cap;
	struct tdx_mig_state *mig_state;
	hpa_t *migsc_paddrs;

	if (kvm_tdx->mig_state) {
		pr_warn("unexpected: mig_state already created\n");
		return -EEXIST;
	}

	mig_state = kzalloc(sizeof(struct tdx_mig_state), GFP_KERNEL_ACCOUNT);
	if (!mig_state)
		return -ENOMEM;

	migsc_paddrs = kcalloc(td_mig_cap->max_migs, sizeof(hpa_t),
			       GFP_KERNEL_ACCOUNT);
	if (!migsc_paddrs) {
		kfree(mig_state);
		return -ENOMEM;
	}

	mig_state->migsc_paddrs = migsc_paddrs;
	kvm_tdx->mig_state = mig_state;
	return 0;
}

static void tdx_mig_stream_buffer_cleanup(struct tdx_mig_stream *stream)
{
	free_page((unsigned long)stream->gpa_list.entries);
	free_page((unsigned long)stream->mac_list.entries);
	free_page((unsigned long)stream->mem_buf_list.entries);
	free_page((unsigned long)stream->page_list.entries);
	kvfree(stream->pages);
}

static void tdx_mig_state_destroy(struct kvm_tdx *kvm_tdx)
{
	const struct tdx_sys_info_td_mig_cap *td_mig_cap =
						&tdx_sysinfo->td_mig_cap;
	struct tdx_mig_state *mig_state = kvm_tdx->mig_state;
	uint32_t i;

	if (!mig_state)
		return;

	if (mig_state->backward_migsc_paddr)
		tdx_reclaim_control_page(mig_state->backward_migsc_paddr);

	for (i = 0; i < td_mig_cap->max_migs; i++) {
		if (!mig_state->migsc_paddrs[i])
			break;

		tdx_reclaim_control_page(mig_state->migsc_paddrs[i]);
	}

	tdx_mig_stream_buffer_cleanup(&mig_state->stream);
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
	struct kvm *kvm = &tdx->kvm;
	struct kvm_vcpu *vcpu;
	unsigned long i;

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

static int tdx_bind_migtd(struct kvm_tdx *usertd_tdx,
			  struct kvm_tdx *migtd_tdx,
			  bool is_src)
{
	u64 err;
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
	err = tdh_servtd_bind(migtd_tdx->tdr_pa, usertd_tdx->tdr_pa,
			      TDX_SERVTD_BINDING_TABLE_INDEX_MIGTD,
			      TDX_MIGTD_ATTR, TDX_SERVTD_TYPE_MIGTD,
			      &binding_info->handle, &binding_info->uuid[0],
			      &binding_info->uuid[1], &binding_info->uuid[2],
			      &binding_info->uuid[3]);
	if (KVM_BUG_ON(err, &usertd_tdx->kvm)) {
		pr_tdx_error(TDH_SERVTD_BIND, err);
		return -EIO;
	}
	binding_info->is_src = is_src;

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
		pr_tdx_error(TDH_MIG_STREAM_CREATE, err);
		free_page(migsc_va);
		return -EIO;
	}

	*migsc_paddr = migsc_pa;

	return 0;
}

static void *tdx_mig_stream_list_alloc(hpa_t *hpa)
{
	struct page *page;

	/*
	 * Allocate the buf list page, which has 512 entries pointing to up to
	 * 512 pages used as buffers to export/import migration data.
	 */
	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page)
		return NULL;
	*hpa = page_to_phys(page);

	return page_address(page);
}

static int tdx_mig_stream_buffer_setup(struct tdx_mig_stream *stream,
				       uint16_t idx, uint32_t nr_ubuf_pages)
{
	void *vaddr;
	hpa_t paddr;

	/* Already retained from the previous sessions? */
	if (stream->mem_buf_list.entries) {
		WARN_ON(!stream->page_list.entries);
		return 0;
	}

	vaddr = tdx_mig_stream_list_alloc(&paddr);
	if (!vaddr)
		return -ENOMEM;
	stream->gpa_list.entries = vaddr;
	stream->gpa_list.info.pfn = PHYS_PFN(paddr);

	vaddr = tdx_mig_stream_list_alloc(&paddr);
	if (!vaddr)
		goto err_mac_list;
	stream->mac_list.entries = vaddr;
	stream->mac_list.hpa = paddr;

	vaddr = tdx_mig_stream_list_alloc(&paddr);
	if (!vaddr)
		goto err_mem_buf_list;
	stream->mem_buf_list.entries = vaddr;
	stream->mem_buf_list.hpa = paddr;

	vaddr = tdx_mig_stream_list_alloc(&paddr);
	if (!vaddr)
		goto err_page_list;
	stream->page_list.entries = vaddr;
	stream->page_list.info.pfn = PHYS_PFN(paddr);

	stream->pages = kvmalloc_array(nr_ubuf_pages,
				       sizeof(struct page *), GFP_KERNEL);
	if (!stream->pages)
		goto err_stream_pages;

	stream->idx = idx;
	return 0;
err_stream_pages:
	free_page((unsigned long)stream->page_list.entries);
err_mac_list:
	free_page((unsigned long)stream->gpa_list.entries);
err_mem_buf_list:
	free_page((unsigned long)stream->mac_list.entries);
err_page_list:
	free_page((unsigned long)stream->mem_buf_list.entries);
	return -ENOMEM;
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

	return tdx_mig_stream_buffer_setup(&mig_state->stream, 0,
					   mig_state->nr_ubuf_pages);
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
