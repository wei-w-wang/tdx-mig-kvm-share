// SPDX-License-Identifier: GPL-2.0
#include <linux/backing-dev.h>
#include <linux/falloc.h>
#include <linux/kvm_host.h>
#include <linux/pagemap.h>
#include <linux/anon_inodes.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/kvm.h>

#include "kvm_mm.h"

struct kvm_gmem {
	struct kvm *kvm;
	struct xarray bindings;
	u64 flags;
	struct list_head entry;
	struct {
	  		struct hstate *h;
			struct hugepage_subpool *spool;
			struct resv_map *resv_map;
			struct file *file;
	} hugetlb;
};

static struct folio *kvm_gmem_hugetlb_alloc_and_cache_folio(struct inode *inode, 
						pgoff_t hindex)
{

	int err;
	struct folio *folio;
	struct kvm_gmem *gmem;
	struct hstate *h;
	struct resv_map *resv_map;
	unsigned long offset;
	struct vm_area_struct pseudo_vma;

	gmem = inode->i_mapping->private_data;
	h = gmem->hugetlb.h;
	resv_map = gmem->hugetlb.resv_map;
	offset = hindex << huge_page_shift(h);

	vma_init(&pseudo_vma, NULL);
	vm_flags_init(&pseudo_vma, VM_HUGETLB | VM_MAYSHARE | VM_SHARED);
	/* vma infrastructure is dependent on vm_file being set */
	pseudo_vma.vm_file = gmem->hugetlb.file; 

	/* TODO setup NUMA policy. Meanwhile, fallback to get_task_policy(). */
	pseudo_vma.vm_policy = NULL;
	folio = alloc_hugetlb_folio_from_subpool(
        gmem->hugetlb.spool, h, resv_map, &pseudo_vma, offset, 0);

	/* Remember to take and drop refcount from vm_policy */
	if (IS_ERR(folio))
		return folio;
	/*
	 * FIXME: Skip clearing pages when trusted firmware will do it when
	 * assigning memory to the guest.
	 */
	clear_huge_page(&folio->page, offset, pages_per_huge_page(h));
	__folio_mark_uptodate(folio);
	err = hugetlb_filemap_add_folio(inode->i_mapping, h, folio, hindex);
	if (unlikely(err)) {
		restore_reserve_on_error(resv_map, hindex, true, folio);
        folio_put(folio);
        folio = ERR_PTR(err);
       }
	
	return folio;
}

/**
 * Gets a hugetlb folio, from @file, at @index (in terms of PAGE_SIZE) within
 * the file.
 *
 * The returned folio will be in @file's page cache, and locked.
 */

static struct folio *kvm_gmem_hugetlb_get_folio(struct inode *inode, pgoff_t index)
{
	struct folio *folio;
	u32 hash;
	/* hindex is in terms of huge_page_size(h) and not PAGE_SIZE */
	pgoff_t hindex;
	struct hstate *h;
	struct address_space *mapping;

	struct kvm_gmem *gmem = inode->i_mapping->private_data;
	h = gmem->hugetlb.h;

	hindex = index >> huge_page_order(h);
	mapping = inode->i_mapping;

	hash = hugetlb_fault_mutex_hash(mapping, hindex);
	mutex_lock(&hugetlb_fault_mutex_table[hash]);

	/* delete the rcu_read_lock()/unlock() */
	folio = filemap_lock_folio(mapping, hindex);
	if (!IS_ERR(folio))
		goto folio_valid;

	folio = kvm_gmem_hugetlb_alloc_and_cache_folio(inode, hindex);
	/*
	 * TODO Perhaps the interface of kvm_gmem_get_folio should change to better
	 * report errors
	 */
	if (IS_ERR(folio))
        folio = NULL;

folio_valid:
	mutex_unlock(&hugetlb_fault_mutex_table[hash]);

	return folio;
}


static struct folio *kvm_gmem_get_huge_folio(struct inode *inode, pgoff_t index)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	unsigned long huge_index = round_down(index, HPAGE_PMD_NR);
	unsigned long flags = (unsigned long)inode->i_private;
	struct address_space *mapping  = inode->i_mapping;
	gfp_t gfp = mapping_gfp_mask(mapping);
	struct folio *folio;

	if (!(flags & KVM_GUEST_MEMFD_ALLOW_HUGEPAGE))
		return NULL;

	if (filemap_range_has_page(mapping, huge_index << PAGE_SHIFT,
				   (huge_index + HPAGE_PMD_NR - 1) << PAGE_SHIFT))
		return NULL;

	folio = filemap_alloc_folio(gfp, HPAGE_PMD_ORDER);
	if (!folio)
		return NULL;

	if (filemap_add_folio(mapping, folio, huge_index, gfp)) {
		folio_put(folio);
		return NULL;
	}

	return folio;
#else
	return NULL;
#endif
}

static struct folio *kvm_gmem_get_folio(struct inode *inode, pgoff_t index)
{
	struct folio *folio;
    struct kvm_gmem *gmem = inode->i_mapping->private_data;

	if (gmem->flags & KVM_GUEST_MEMFD_HUGETLB) {
		folio = kvm_gmem_hugetlb_get_folio(inode, index);
	/*
     * Don't need to clear pages because
     * kvm_gmem_hugetlb_alloc_and_cache_folio() already clears pages
     * when allocating
     */
    } else {
		folio = kvm_gmem_get_huge_folio(inode, index);
		if (!folio) {
			folio = filemap_grab_folio(inode->i_mapping, index);
			if (IS_ERR_OR_NULL(folio))
				return NULL;
		}
	}
	/*
	 * Use the up-to-date flag to track whether or not the memory has been
	 * zeroed before being handed off to the guest.  There is no backing
	 * storage for the memory, so the folio will remain up-to-date until
	 * it's removed.
	 *
	 * TODO: Skip clearing pages when trusted firmware will do it when
	 * assigning memory to the guest.
	 */
	if (!folio_test_uptodate(folio)) {
		unsigned long nr_pages = folio_nr_pages(folio);
		unsigned long i;

		for (i = 0; i < nr_pages; i++)
			clear_highpage(folio_page(folio, i));

		folio_mark_uptodate(folio);
	}

	/*
	 * Ignore accessed, referenced, and dirty flags.  The memory is
	 * unevictable and there is no storage to write back to.
	 */
	return folio;
}

static void kvm_gmem_invalidate_begin(struct kvm_gmem *gmem, pgoff_t start,
				      pgoff_t end)
{
	bool flush = false, found_memslot = false;
	struct kvm_memory_slot *slot;
	struct kvm *kvm = gmem->kvm;
	unsigned long index;

	xa_for_each_range(&gmem->bindings, index, slot, start, end - 1) {
		pgoff_t pgoff = slot->gmem.pgoff;

		struct kvm_gfn_range gfn_range = {
			.start = slot->base_gfn + max(pgoff, start) - pgoff,
			.end = slot->base_gfn + min(pgoff + slot->npages, end) - pgoff,
			.slot = slot,
			.may_block = true,
			/* guest memfd is relevant to only private mappings. */
			.only_private = true,
			.only_shared = false,
		};

		if (!found_memslot) {
			found_memslot = true;

			KVM_MMU_LOCK(kvm);
			kvm_mmu_invalidate_begin(kvm);
		}

		flush |= kvm_mmu_unmap_gfn_range(kvm, &gfn_range);
	}

	if (flush)
		kvm_flush_remote_tlbs(kvm);

	if (found_memslot)
		KVM_MMU_UNLOCK(kvm);
}

static void kvm_gmem_invalidate_end(struct kvm_gmem *gmem, pgoff_t start,
				    pgoff_t end)
{
	struct kvm *kvm = gmem->kvm;

	if (xa_find(&gmem->bindings, &start, end - 1, XA_PRESENT)) {
		KVM_MMU_LOCK(kvm);
		kvm_mmu_invalidate_end(kvm);
		KVM_MMU_UNLOCK(kvm);
	}
}

static void kvm_gmem_hugetlb_truncate_range(struct inode *inode,
                                           loff_t offset, loff_t len)
{
       loff_t hsize;
       loff_t full_hpage_start;
       loff_t full_hpage_end;
       struct kvm_gmem *gmem;
       struct hstate *h;
       struct address_space *mapping;

       mapping = inode->i_mapping;
       gmem = mapping->private_data; 
       h = gmem->hugetlb.h;
       hsize = huge_page_size(h);
       full_hpage_start = round_up(offset, hsize);
       full_hpage_end = round_down(offset + len, hsize);

       /* If range starts before first full page, zero partial page. */
       if (offset < full_hpage_start) {
               hugetlb_zero_partial_page(
                       h, mapping, offset, min(offset + len, full_hpage_start));
       }

       /* Remove full pages from the file. */
       if (full_hpage_end > full_hpage_start) {
               remove_mapping_hugepages(mapping, h, gmem->hugetlb.spool,
                                        gmem->hugetlb.resv_map, inode,
                                        full_hpage_start, full_hpage_end);
       }


       /* If range extends beyond last full page, zero partial page. */
       if ((offset + len) > full_hpage_end && (offset + len) > full_hpage_start) {
               hugetlb_zero_partial_page(
                       h, mapping, full_hpage_end, offset + len);
       }
}



static long kvm_gmem_punch_hole(struct inode *inode, loff_t offset, loff_t len)
{
	struct list_head *gmem_list = &inode->i_mapping->private_list;
	pgoff_t start = offset >> PAGE_SHIFT;
	pgoff_t end = (offset + len) >> PAGE_SHIFT;
	struct kvm_gmem *gmem;

	/*
	 * Bindings must be stable across invalidation to ensure the start+end
	 * are balanced.
	 */
	filemap_invalidate_lock(inode->i_mapping);

	list_for_each_entry(gmem, gmem_list, entry)
	{
		kvm_gmem_invalidate_begin(gmem, start, end);

		if (gmem->flags & KVM_GUEST_MEMFD_HUGETLB)
			kvm_gmem_hugetlb_truncate_range(inode, offset, len);
		else
			truncate_inode_pages_range(inode->i_mapping, offset, offset + len - 1);
	}
	list_for_each_entry(gmem, gmem_list, entry)
		kvm_gmem_invalidate_end(gmem, start, end);

	filemap_invalidate_unlock(inode->i_mapping);

	return 0;
}

static long kvm_gmem_allocate(struct inode *inode, loff_t offset, loff_t len)
{
	struct address_space *mapping = inode->i_mapping;
	struct kvm_gmem *gmem = inode->i_mapping->private_data;
	pgoff_t start, index, end;
	int r;

	/* Dedicated guest is immutable by default. */
	if (offset + len > i_size_read(inode))
		return -EINVAL;

	filemap_invalidate_lock_shared(mapping);

       if (gmem->flags & KVM_GUEST_MEMFD_HUGETLB) {
               start = offset >> huge_page_shift(gmem->hugetlb.h);
               end = ALIGN(offset + len, huge_page_size(gmem->hugetlb.h)) >> PAGE_SHIFT;
       } else {
               start = offset >> PAGE_SHIFT;
               /* Align so that at least 1 page is allocated */
               end = ALIGN(offset + len, PAGE_SIZE) >> PAGE_SHIFT;
       }



	r = 0;
	for (index = start; index < end; ) {
		struct folio *folio;

		if (signal_pending(current)) {
			r = -EINTR;
			break;
		}

		folio = kvm_gmem_get_folio(inode, index);
		if (!folio) {
			r = -ENOMEM;
			break;
		}

       index += folio_nr_pages(folio);

		folio_unlock(folio);
		folio_put(folio);

		/* 64-bit only, wrapping the index should be impossible. */
		if (WARN_ON_ONCE(!index))
			break;

		cond_resched();
	}

	filemap_invalidate_unlock_shared(mapping);

	return r;
}

static long kvm_gmem_fallocate(struct file *file, int mode, loff_t offset,
			       loff_t len)
{
	int ret;

	if (!(mode & FALLOC_FL_KEEP_SIZE))
		return -EOPNOTSUPP;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	if (!PAGE_ALIGNED(offset) || !PAGE_ALIGNED(len))
		return -EINVAL;

	if (mode & FALLOC_FL_PUNCH_HOLE)
		ret = kvm_gmem_punch_hole(file_inode(file), offset, len);
	else
		ret = kvm_gmem_allocate(file_inode(file), offset, len);

	if (!ret)
		file_modified(file);
	return ret;
}

static int kvm_gmem_release(struct inode *inode, struct file *file)
{
	struct kvm_gmem *gmem = file->private_data;
	struct kvm_memory_slot *slot;
	struct kvm *kvm = gmem->kvm;
	unsigned long index;

	/*
	 * Prevent concurrent attempts to *unbind* a memslot.  This is the last
	 * reference to the file and thus no new bindings can be created, but
	 * dereferencing the slot for existing bindings needs to be protected
	 * against memslot updates, specifically so that unbind doesn't race
	 * and free the memslot (kvm_gmem_get_file() will return NULL).
	 */
	mutex_lock(&kvm->slots_lock);

	filemap_invalidate_lock(inode->i_mapping);

	xa_for_each(&gmem->bindings, index, slot)
		rcu_assign_pointer(slot->gmem.file, NULL);

	synchronize_rcu();

	/*
	 * All in-flight operations are gone and new bindings can be created.
	 * Zap all SPTEs pointed at by this file.  Do not free the backing
	 * memory, as its lifetime is associated with the inode, not the file.
	 */
	kvm_gmem_invalidate_begin(gmem, 0, -1ul);

	if (gmem->flags & KVM_GUEST_MEMFD_HUGETLB) {
        truncate_inode_pages_final_prepare(inode->i_mapping);
        remove_mapping_hugepages(
            inode->i_mapping, gmem->hugetlb.h, gmem->hugetlb.spool,
            gmem->hugetlb.resv_map, inode, 0, LLONG_MAX);
        resv_map_release(&gmem->hugetlb.resv_map->refs);
        hugepage_put_subpool(gmem->hugetlb.spool);
	} else {
	  		truncate_inode_pages_final(inode->i_mapping);
	}

	kvm_gmem_invalidate_end(gmem, 0, -1ul);

	list_del(&gmem->entry);

	filemap_invalidate_unlock(inode->i_mapping);

	mutex_unlock(&kvm->slots_lock);

	xa_destroy(&gmem->bindings);
	kfree(gmem);

	kvm_put_kvm(kvm);

	return 0;
}

static struct file *kvm_gmem_get_file(struct kvm_memory_slot *slot)
{
	struct file *file;

	rcu_read_lock();

	file = rcu_dereference(slot->gmem.file);
	if (file && !get_file_rcu(file))
		file = NULL;

	rcu_read_unlock();

	return file;
}

static struct file_operations kvm_gmem_fops = {
	.open		= generic_file_open,
	.release	= kvm_gmem_release,
	.fallocate	= kvm_gmem_fallocate,
};

void kvm_gmem_init(struct module *module)
{
	kvm_gmem_fops.owner = module;
}
EXPORT_SYMBOL_GPL(kvm_gmem_init);

static int kvm_gmem_migrate_folio(struct address_space *mapping,
				  struct folio *dst, struct folio *src,
				  enum migrate_mode mode)
{
	WARN_ON_ONCE(1);
	return -EINVAL;
}

static int kvm_gmem_error_page(struct address_space *mapping, struct page *page)
{
	struct list_head *gmem_list = &mapping->private_list;
	struct kvm_gmem *gmem;
	pgoff_t start, end;

	filemap_invalidate_lock_shared(mapping);

	start = page->index;
	end = start + thp_nr_pages(page);

	list_for_each_entry(gmem, gmem_list, entry)
		kvm_gmem_invalidate_begin(gmem, start, end);

	/*
	 * Do not truncate the range, what action is taken in response to the
	 * error is userspace's decision (assuming the architecture supports
	 * gracefully handling memory errors).  If/when the guest attempts to
	 * access a poisoned page, kvm_gmem_get_pfn() will return -EHWPOISON,
	 * at which point KVM can either terminate the VM or propagate the
	 * error to userspace.
	 */

	list_for_each_entry(gmem, gmem_list, entry)
		kvm_gmem_invalidate_end(gmem, start, end);

	filemap_invalidate_unlock_shared(mapping);

	return MF_DELAYED;
}

static const struct address_space_operations kvm_gmem_aops = {
	.dirty_folio = noop_dirty_folio,
#ifdef CONFIG_MIGRATION
	.migrate_folio	= kvm_gmem_migrate_folio,
#endif
	.error_remove_page = kvm_gmem_error_page,
};

static int kvm_gmem_getattr(struct mnt_idmap *idmap, const struct path *path,
			    struct kstat *stat, u32 request_mask,
			    unsigned int query_flags)
{
	struct inode *inode = path->dentry->d_inode;

	generic_fillattr(idmap, request_mask, inode, stat);
	return 0;
}

static int kvm_gmem_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			    struct iattr *attr)
{
	return -EINVAL;
}
static const struct inode_operations kvm_gmem_iops = {
	.getattr	= kvm_gmem_getattr,
	.setattr	= kvm_gmem_setattr,
};

static int kvm_gmem_hugetlb_setup(struct inode *inode, struct file *file, struct kvm_gmem *gmem,
                                 loff_t size, u64 flags)
{
       int page_size_log;
       int hstate_idx;
       long hpages;
       struct resv_map *resv_map;
       struct hugepage_subpool *spool;
       struct hstate *h;

       page_size_log = (flags >> KVM_GUEST_MEMFD_HUGE_SHIFT) & KVM_GUEST_MEMFD_HUGE_MASK;
       hstate_idx = get_hstate_idx(page_size_log);
       if (hstate_idx < 0)
               return -ENOENT;

       h = &hstates[hstate_idx];
       /* Round up to accommodate size requests that don't align with huge pages */
       hpages = round_up(size, huge_page_size(h)) >> huge_page_shift(h);
       spool = hugepage_new_subpool(h, hpages, hpages);
       if (!spool)
               goto out;

       resv_map = resv_map_alloc();
       if (!resv_map)
               goto out_subpool;

       inode->i_blkbits = huge_page_shift(h);

	   gmem->flags = flags;
       gmem->hugetlb.h = h;
	   gmem->hugetlb.file=file;

       gmem->hugetlb.spool = spool;
       gmem->hugetlb.resv_map = resv_map;

       return 0;

out_subpool:
       kfree(spool);
out:
       return -ENOMEM;
}

#define KVM_GUEST_MEMFD_ALL_FLAGS (KVM_GUEST_MEMFD_HUGE_PMD | KVM_GUEST_MEMFD_HUGETLB)

static int __kvm_gmem_create(struct kvm *kvm, loff_t size, u64 flags)
{
	const char *anon_name = "[kvm-gmem]";
	struct kvm_gmem *gmem;
	struct inode *inode;
	struct file *file;
	int fd, err;

	fd = get_unused_fd_flags(0);
	if (fd < 0)
		return fd;

	gmem = kzalloc(sizeof(*gmem), GFP_KERNEL);
	if (!gmem) {
		err = -ENOMEM;
		goto err_fd;
	}

	file = anon_inode_create_getfile(anon_name, &kvm_gmem_fops, gmem,
					 O_RDWR, NULL);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_gmem;
	}

	file->f_flags |= O_LARGEFILE;

	inode = file->f_inode;
	WARN_ON(file->f_mapping != inode->i_mapping);

	inode->i_private = (void *)(unsigned long)flags;
	inode->i_op = &kvm_gmem_iops;
	inode->i_mapping->a_ops = &kvm_gmem_aops;
	inode->i_mapping->private_data = gmem; 
	inode->i_mode |= S_IFREG;
	inode->i_size = size;
	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	mapping_set_large_folios(inode->i_mapping);
	mapping_set_unmovable(inode->i_mapping);
	/* Unmovable mappings are supposed to be marked unevictable as well. */
	WARN_ON_ONCE(!mapping_unevictable(inode->i_mapping));

	if (flags & KVM_GUEST_MEMFD_HUGETLB) {
		err = kvm_gmem_hugetlb_setup(inode, file, gmem, size, flags);
		if (err)
			goto err_gmem;
	}

	gmem->flags = flags;
	kvm_get_kvm(kvm);
	gmem->kvm = kvm;
	xa_init(&gmem->bindings);
	list_add(&gmem->entry, &inode->i_mapping->private_list);

	fd_install(fd, file);
	return fd;

err_gmem:
	kfree(gmem);
err_fd:
	put_unused_fd(fd);
	return err;
}

int kvm_gmem_create(struct kvm *kvm, struct kvm_create_guest_memfd *args)
{
	loff_t size = args->size;
	u64 flags = args->flags;
	u64 valid_flags = 0;

	if (IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE))
		valid_flags |= KVM_GUEST_MEMFD_ALLOW_HUGEPAGE;

	if (size <= 0 || !PAGE_ALIGNED(size))
		return -EINVAL;

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if ((flags & KVM_GUEST_MEMFD_ALLOW_HUGEPAGE) &&
	    !IS_ALIGNED(size, HPAGE_PMD_SIZE))
		return -EINVAL;
#endif
	if (!(flags & KVM_GUEST_MEMFD_HUGETLB)) {
	if (flags & ~(unsigned int)KVM_GUEST_MEMFD_ALL_FLAGS)
		return -EINVAL;
	} else {
		/* Allow huge page size encoding in flags. */
		if (flags & ~(unsigned int)(KVM_GUEST_MEMFD_ALL_FLAGS |
			(KVM_GUEST_MEMFD_HUGE_MASK << KVM_GUEST_MEMFD_HUGE_SHIFT)))
			return -EINVAL;
   }
	return __kvm_gmem_create(kvm, size, flags);
}

int kvm_gmem_bind(struct kvm *kvm, struct kvm_memory_slot *slot,
		  unsigned int fd, loff_t offset)
{
	loff_t size = slot->npages << PAGE_SHIFT;
	unsigned long start, end;
	struct kvm_gmem *gmem;
	struct inode *inode;
	struct file *file;
	int r = -EINVAL;

	BUILD_BUG_ON(sizeof(gfn_t) != sizeof(slot->gmem.pgoff));

	file = fget(fd);
	if (!file)
		return -EBADF;

	if (file->f_op != &kvm_gmem_fops)
		goto err;

	gmem = file->private_data;
	if (gmem->kvm != kvm)
		goto err;

	inode = file_inode(file);

	if (offset < 0 || !PAGE_ALIGNED(offset) ||
	    offset + size > i_size_read(inode))
		goto err;

	filemap_invalidate_lock(inode->i_mapping);

	start = offset >> PAGE_SHIFT;
	end = start + slot->npages;

	if (!xa_empty(&gmem->bindings) &&
	    xa_find(&gmem->bindings, &start, end - 1, XA_PRESENT)) {
		filemap_invalidate_unlock(inode->i_mapping);
		goto err;
	}

	/*
	 * No synchronize_rcu() needed, any in-flight readers are guaranteed to
	 * be see either a NULL file or this new file, no need for them to go
	 * away.
	 */
	rcu_assign_pointer(slot->gmem.file, file);
	slot->gmem.pgoff = start;

	xa_store_range(&gmem->bindings, start, end - 1, slot, GFP_KERNEL);
	filemap_invalidate_unlock(inode->i_mapping);

	/*
	 * Drop the reference to the file, even on success.  The file pins KVM,
	 * not the other way 'round.  Active bindings are invalidated if the
	 * file is closed before memslots are destroyed.
	 */
	r = 0;
err:
	fput(file);
	return r;
}

void kvm_gmem_unbind(struct kvm_memory_slot *slot)
{
	unsigned long start = slot->gmem.pgoff;
	unsigned long end = start + slot->npages;
	struct kvm_gmem *gmem;
	struct file *file;

	/*
	 * Nothing to do if the underlying file was already closed (or is being
	 * closed right now), kvm_gmem_release() invalidates all bindings.
	 */
	file = kvm_gmem_get_file(slot);
	if (!file)
		return;

	gmem = file->private_data;

	filemap_invalidate_lock(file->f_mapping);
	xa_store_range(&gmem->bindings, start, end - 1, NULL, GFP_KERNEL);
	rcu_assign_pointer(slot->gmem.file, NULL);
	synchronize_rcu();
	filemap_invalidate_unlock(file->f_mapping);

	fput(file);
}

int kvm_gmem_get_pfn(struct kvm *kvm, struct kvm_memory_slot *slot,
		     gfn_t gfn, kvm_pfn_t *pfn, int *max_order)
{
	pgoff_t index, huge_index;
	struct kvm_gmem *gmem;
	struct folio *folio;
	struct page *page;
	struct file *file;
	int r;

	file = kvm_gmem_get_file(slot);
	if (!file)
		return -EFAULT;

	gmem = file->private_data;

	index = gfn - slot->base_gfn + slot->gmem.pgoff;
	if (WARN_ON_ONCE(xa_load(&gmem->bindings, index) != slot)) {
		r = -EIO;
		goto out_fput;
	}

	folio = kvm_gmem_get_folio(file_inode(file), index);

	if (!folio) {
		r = -ENOMEM;
		goto out_fput;
	}

	if (folio_test_hwpoison(folio)) {
		r = -EHWPOISON;
		goto out_unlock;
	}

    /*
     * folio_file_page() always returns the head page for hugetlb
     * folios. Reimplement to get the page within this folio, even for
     * hugetlb pages.
     */
    page = folio_page(folio, index & (folio_nr_pages(folio) - 1));
 
	*pfn = page_to_pfn(page);
	if (!max_order)
		goto success;

	*max_order = compound_order(compound_head(page));
	if (!*max_order)
		goto success;

	/*
	 * The folio can be mapped with a hugepage if and only if the folio is
	 * fully contained by the range the memslot is bound to.  Note, the
	 * caller is responsible for handling gfn alignment, this only deals
	 * with the file binding.
	 */
	huge_index = ALIGN(index, 1ull << *max_order);
	if (huge_index < ALIGN(slot->gmem.pgoff, 1ull << *max_order) ||
	    huge_index + (1ull << *max_order) > slot->gmem.pgoff + slot->npages)
		*max_order = 0;
success:
	r = 0;

out_unlock:
	folio_unlock(folio);
out_fput:
	fput(file);

	return r;
}
