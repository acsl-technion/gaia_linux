/*
 *	linux/mm/msync.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * The msync() system call.
 */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/memcontrol.h>

#include <linux/pagevec.h>
#include <linux/slab.h>

#include <linux/ucm.h>
#include <linux/rmap.h>

#include <linux/workqueue.h>

#include <linux/time.h>

#include "internal.h"
/*
 * MS_SYNC syncs the entire file - including mappings.
 *
 * MS_ASYNC does not start I/O (it used to, up to 2.5.67).
 * Nor does it marks the relevant pages dirty (it used to up to 2.6.17).
 * Now it doesn't do anything, since dirty pages are properly tracked.
 *
 * The application may now run fsync() to
 * write out the dirty pages and wait on the writeout and check the result.
 * Or the application may run fadvise(FADV_DONTNEED) against the fd to start
 * async writeout immediately.
 * So by _not_ starting I/O in MS_ASYNC we provide complete flexibility to
 * applications.
 */
SYSCALL_DEFINE3(msync, unsigned long, start, size_t, len, int, flags)
{
	unsigned long end;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int unmapped_error = 0;
	int error = -EINVAL;

	if (flags & ~(MS_ASYNC | MS_INVALIDATE | MS_SYNC))
		goto out;
	if (offset_in_page(start))
		goto out;
	if ((flags & MS_ASYNC) && (flags & MS_SYNC))
		goto out;
	error = -ENOMEM;
	len = (len + ~PAGE_MASK) & PAGE_MASK;
	end = start + len;
	if (end < start)
		goto out;
	error = 0;
	if (end == start)
		goto out;
	/*
	 * If the interval [start,end) covers some unmapped address ranges,
	 * just ignore them, but return -ENOMEM at the end.
	 */
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, start);
	for (;;) {
		struct file *file;
		loff_t fstart, fend;

		/* Still start < end. */
		error = -ENOMEM;
		if (!vma)
			goto out_unlock;
		/* Here start < vma->vm_end. */
		if (start < vma->vm_start) {
			start = vma->vm_start;
			if (start >= end)
				goto out_unlock;
			unmapped_error = -ENOMEM;
		}
		/* Here vma->vm_start <= start < vma->vm_end. */
		if ((flags & MS_INVALIDATE) &&
				(vma->vm_flags & VM_LOCKED)) {
			error = -EBUSY;
			goto out_unlock;
		}
		file = vma->vm_file;
		fstart = (start - vma->vm_start) +
			 ((loff_t)vma->vm_pgoff << PAGE_SHIFT);
		fend = fstart + (min(end, vma->vm_end) - start) - 1;
		start = vma->vm_end;
		if ((flags & MS_SYNC) && file &&
				(vma->vm_flags & VM_SHARED)) {
			get_file(file);
			up_read(&mm->mmap_sem);
			error = vfs_fsync_range(file, fstart, fend, 1);
			fput(file);
			if (error || start >= end)
				goto out;
			down_read(&mm->mmap_sem);
			vma = find_vma(mm, start);
		} else {
			if (start >= end) {
				error = 0;
				goto out_unlock;
			}
			vma = vma->vm_next;
		}
	}
out_unlock:
	up_read(&mm->mmap_sem);
out:
	return error ? : unmapped_error;
}

#define AQUIRE_PAGES_THREASHOLD 1024
SYSCALL_DEFINE3(maquire, unsigned long, start, size_t, len, int, flags)
{
	unsigned long end_byte;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *shared_vma, *cpu_vma;
	int unmapped_error = 0;
	int error = -EINVAL;
	struct file *mfile = NULL;
	int nr_pages;
 	pgoff_t index, end; 
	unsigned i;
	int gpu_page_idx = -1;
	int gpu_missing = 0;
	int *pages_idx;
	unsigned long tagged, tagged_gpu;

	struct page **cached_pages = NULL;

	int stat_gpu_deleted = -1;
	int stat_cpu_marked = 0;

	struct timespec tstart, tend;
	int ret;


	if (flags & ~(MA_PROC_NVIDIA | MA_PROC_AMD)) {
		UCM_ERR("What GPU should I aquire for??? Exit\n");
		goto out;
	}
	if (offset_in_page(start))
			goto out;
	if ((flags & MS_ASYNC) && (flags & MS_SYNC))
			goto out;

	error = -ENOMEM;
	if ( start + len <= start)
			goto out;
	error = 0;

	/*
	 * If the interval [start,end) covers some unmapped address ranges,
	 * just ignore them, but return -ENOMEM at the end.
	 */
	down_read(&mm->mmap_sem);
	shared_vma = find_vma(mm, start);
	if (!shared_vma) {
		UCM_ERR("no shared_vma found starting at 0x%llx\n", start);
		goto out_unlock;
	}
	if (!shared_vma->gpu_mapped_shared) {
		UCM_ERR("Aquire is not supported for a NOT-GPU maped vma\n");
		error = -EINVAL;
		goto out_unlock;
	}
	if (!shared_vma->ucm_vm_ops || !shared_vma->ucm_vm_ops->get_mmaped_file || !shared_vma->ucm_vm_ops->invalidate_cached_page) {
		UCM_ERR("ucm_vm_ops not povided\n");
		error = -EINVAL;
		goto out_unlock;
	}


	unsigned long int cpu_addr = shared_vma->ucm_vm_ops->get_cpu_addr(shared_vma, start, end);
	if (!cpu_addr) {
		UCM_ERR("Didn't find CPU addr?!?!?\n");
		error = -EINVAL;
                goto out_unlock;
	}	
	cpu_vma = find_vma(mm, cpu_addr);
	if (!cpu_vma) {
		UCM_ERR("no cpu_vma found starting at 0x%llx\n", cpu_addr);
		goto out_unlock;
	}

	index = (cpu_addr - cpu_vma->vm_start) / PAGE_SIZE;
	end = (cpu_addr + len - cpu_vma->vm_start) / PAGE_SIZE + 1;


	 //Do the msync here
	 get_file(cpu_vma->vm_file);
	up_read(&mm->mmap_sem);

	if (vfs_fsync_range(cpu_vma->vm_file, index, end, 0))
		UCM_ERR("vfs sync failed\n");
	fput(cpu_vma->vm_file);
	down_read(&mm->mmap_sem);

	 while ((index <= end) ) {
			/*(nr_pages = pagevec_lookup_tag(&pvec, cpu_vma->vm_file->f_mapping, &index,
				PAGECACHE_TAG_DIRTY,
				min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1)) != 0)*/
		int num_pages = min(AQUIRE_PAGES_THREASHOLD +1, end-index);
		pgoff_t start = index;
		pages_idx = (int*)kzalloc(sizeof(int)*(num_pages + 1), GFP_KERNEL);
		if (!pages_idx) {
			UCM_ERR("Error allocating memory!\n");
			error = -ENOMEM;
         	       goto out_unlock;
		}
		nr_pages = find_get_taged_pages_idx(cpu_vma->vm_file->f_mapping, &index,
			num_pages, pages_idx, PAGECACHE_TAG_CPU_DIRTY);
		index += nr_pages;
		stat_cpu_marked += nr_pages;
		if (!nr_pages) {
			//UCM_DBG("No pages taged as DIRTY ON CPU!!! index=%d end - %d\n", index, end);
			kfree(pages_idx);
			break;
		} 
		for (i = 0; i < nr_pages; i++) {
			int page_idx = pages_idx[i];
			/* until radix tree lookup accepts end_index */
			if (page_idx > end) {
				UCM_DBG("page_idx (%d) > end (%d). continue..\n", page_idx, end);
				continue;
			}
			if (1/*(gpu_page_idx == -1) || (gpu_page_idx != page_idx % 16)*/) {
				struct page *gpu_page = pagecache_get_gpu_page(cpu_vma->vm_file->f_mapping, page_idx, GPU_NVIDIA, true);

				if (gpu_page) {
					struct mem_cgroup *memcg;
					unsigned long flags;
					struct ucm_page_data *pdata = (struct ucm_page_data *)gpu_page->private;

					memcg = mem_cgroup_begin_page_stat(gpu_page);
					gpu_page_idx = gpu_page->index;
					//Remove the page from page cache
					__set_page_locked(gpu_page);
					spin_lock_irqsave(&cpu_vma->vm_file->f_mapping->tree_lock, flags);
					__delete_from_page_cache_gpu(gpu_page, NULL, memcg, GPU_NVIDIA);
					ClearPageonGPU(gpu_page);
					spin_unlock_irqrestore(&cpu_vma->vm_file->f_mapping->tree_lock, flags);
					mem_cgroup_end_page_stat(memcg);
					__clear_page_locked(gpu_page);
					//The virtual address of the page in the shared VM is saved ar page->private
					if (stat_gpu_deleted < 0)
						stat_gpu_deleted = 0;
					stat_gpu_deleted++;
					if (shared_vma->ucm_vm_ops->invalidate_cached_page(shared_vma, pdata->shared_addr ))
						UCM_ERR("Error invalidating page at virt addr 0x%llx on GPU!!!\n", pdata->shared_addr );
				} else
					gpu_missing++;
				radix_tree_tag_clear(&cpu_vma->vm_file->f_mapping->page_tree, page_idx,
                                   		PAGECACHE_TAG_CPU_DIRTY);
			}
		}
		kfree(pages_idx);
	}

out_unlock:
        up_read(&mm->mmap_sem);
out:
	UCM_DBG("done: stat_gpu_deleted=%d, stat_cpu_marked=%d gpu_missing=%d\n", stat_gpu_deleted, stat_cpu_marked, gpu_missing);
        return stat_gpu_deleted;
}


SYSCALL_DEFINE3(mrelease, unsigned long, start, size_t, len, int, flags)
{
	unsigned long end_byte;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *shared_vma, *cpu_vma;
	int unmapped_error = 0;
	int error = -EINVAL;
	struct file *mfile = NULL;

	int nr_pages;
 	pgoff_t index, end;

 	int num_gpu_pages = 0;
 	int num_cpu_invalidated = 0;
 	int num_cache_taged = 0;
 	unsigned long int cpu_addr;


UCM_DBG("Enter: start = 0x%llx len = %ld, flags =0x%lx\n", start, len, flags);
	if (flags & ~(MA_PROC_NVIDIA | MA_PROC_AMD)) {
		UCM_ERR("What GPU should I aquire for??? Exit\n");
                goto out;
	}
    if (offset_in_page(start))
    	goto out;
	if ((flags & MS_ASYNC) && (flags & MS_SYNC))
		goto out;

	error = -ENOMEM;
	if ( start + len <= start)
		goto out;
	error = 0;

	down_read(&mm->mmap_sem);

	shared_vma = find_vma(mm, start);
	if (!shared_vma) {
UCM_ERR("no shared_vma found starting at 0x%llx\n", start);
		goto out_unlock;
	}
	if (!shared_vma->gpu_mapped_shared) {
		UCM_ERR("Aquire is not supported for a NOT-GPU maped vma\n");
		error = -EINVAL;
		goto out_unlock;
	}

	if (!shared_vma->ucm_vm_ops) {
			UCM_ERR("ucm_vm_ops not povided\n");
			error = -EINVAL;
			goto out_unlock;
		}
	if (!shared_vma->ucm_vm_ops->is_gpu_page_dirty ) {
		UCM_ERR("is_gpu_page_dirty not povided\n");
		error = -EINVAL;
		goto out_unlock;
	}
	if (!shared_vma->ucm_vm_ops->get_cpu_addr) {
		UCM_ERR("get_cpu_addr not povided shared_vma\n");
		error = -EINVAL;
		goto out_unlock;
	}

	cpu_addr = shared_vma->ucm_vm_ops->get_cpu_addr(shared_vma, start, end);
	if (!cpu_addr) {
		UCM_ERR("Didn't find CPU addr?!?!?\n");
		error = -EINVAL;
                goto out_unlock;
	}
	cpu_vma = find_vma(mm, cpu_addr);
	if (!cpu_vma || !cpu_vma->vm_file) {
		UCM_ERR("no cpu_vma found (or !cpu_vma->vm_file) starting at 0x%llx\n", cpu_addr);
		goto out_unlock;
	}

	index = 0; //(cpu_addr - cpu_vma->vm_start) / PAGE_SIZE;
	end = (cpu_vma->vm_end - cpu_vma->vm_start)/PAGE_SIZE; //(cpu_addr + len - cpu_vma->vm_start) / PAGE_SIZE + 1;
	while ((index <= end) ) {
		unsigned i;
		int gpu_page_idx = -1;
		int *pages_idx;
		unsigned long tagged, tagged_gpu;

		int num_pages = min(AQUIRE_PAGES_THREASHOLD +1, end-index);

		pages_idx = (int*)kzalloc(sizeof(int)*(num_pages +1), GFP_KERNEL);
		if (!pages_idx) {
			UCM_ERR("Error allocating memory!\n");
			error = -ENOMEM;
         	       goto out_unlock;
		}
		nr_pages = find_get_taged_pages_idx(cpu_vma->vm_file->f_mapping, &index,
				num_pages, pages_idx, PAGECACHE_TAG_ON_GPU);
		num_cache_taged += nr_pages;
		if (!nr_pages) {
			//UCM_DBG("No pages taged as ON_GPU: index = %ld, nrpages=%ld\n", index, end - index + 1);
			kfree(pages_idx);
			break;
		}
		for (i = 0; i < nr_pages; i++) {
			int page_idx = pages_idx[i];
			/* until radix tree lookup accepts end_index */
			if (page_idx > end)
				continue;

			if (1) {
				struct page *gpu_page = pagecache_get_gpu_page(cpu_vma->vm_file->f_mapping, page_idx, GPU_NVIDIA, true);
				spin_lock_irqsave(&cpu_vma->vm_file->f_mapping->tree_lock, flags);
				if (gpu_page) {
					struct ucm_page_data *pdata = (struct ucm_page_data *)gpu_page->private;
					unsigned long cpu_page_addr;
					unsigned long gpu_page_addr;
					int j;
					int gpu_dirty = 0;

					if (!pdata) {
						UCM_ERR("GPu page at idx %ld has pdata =null\n", gpu_page->index);
						spin_unlock_irqrestore(&cpu_vma->vm_file->f_mapping->tree_lock, flags);
						continue;
					}
					cpu_page_addr = pdata->shared_addr - shared_vma->vm_start + cpu_vma->vm_start;
					gpu_page_addr = pdata->shared_addr;
					num_gpu_pages++;
					gpu_page_idx = gpu_page->index;

					if (!shared_vma->ucm_vm_ops->is_gpu_page_dirty(shared_vma, gpu_page)) {
						spin_unlock_irqrestore(&cpu_vma->vm_file->f_mapping->tree_lock, flags);
						continue;
					}

					//Now increase the page version on gpu
					increase_page_version(cpu_vma->vm_file->f_mapping, page_idx, GPU_NVIDIA);

					for (j = 0; j <16; j++) {
						struct page *cpu_page = find_get_entry(cpu_vma->vm_file->f_mapping, page_idx + j, NULL);
						int ret;
						if (!cpu_page) {
							UCM_ERR("Didn;t find cpu page in cache???!!!\n");
							spin_unlock_irqrestore(&cpu_vma->vm_file->f_mapping->tree_lock, flags);
							continue;
						}

						__set_page_locked(cpu_page);
						ret = try_to_unmap(cpu_page, TTU_UNMAP|TTU_IGNORE_MLOCK|TTU_IGNORE_ACCESS);
						if (ret != SWAP_SUCCESS) {
							UCM_ERR("\nFailed unmaping page ret = %d\n", ret);
							spin_unlock_irqrestore(&cpu_vma->vm_file->f_mapping->tree_lock, flags);
							continue;
						}
						__clear_page_locked(cpu_page);
						put_page(cpu_page);
					}
				} else
					UCM_ERR("page @idx %d not cached on gpu???\n", page_idx);
				spin_unlock_irqrestore(&cpu_vma->vm_file->f_mapping->tree_lock, flags);
			}
		}
		kfree(pages_idx);
	}

out_unlock:
	//rcu_read_unlock();
	up_read(&mm->mmap_sem);

out:
UCM_DBG("done. num_cpu_invalidated = %d num_gpu_pages=%d  num_cache_taged=%d\n",
		num_cpu_invalidated, num_gpu_pages, num_cache_taged);
    return error ? : unmapped_error;
}


struct my_work_data_t {
	struct delayed_work	ucm_work;
	unsigned long start;
	unsigned long cache_size;
	unsigned long cache_limit;
	struct mm_struct *mm;
	unsigned long interval;
};

struct my_work_data_t my_work_data;


/*
 * When the free space in the GPU cache becomes smaller then CACHE_UP_LIMIT*64K,
 * We start invalidating pages
 */
void ucm_work_handler(struct work_struct *work){
	static int enter_cnt = 0;
	struct vm_area_struct *shared_vma, *cpu_vma;
	unsigned long int cpu_addr;
	struct address_space *mapping;
	struct ucm_page_data *pdata, *tmp;
	struct my_work_data_t *my_data =
			container_of(work, struct my_work_data_t, ucm_work);
	struct mm_struct *mm = my_data->mm;
	int stat_gpu_removed = 0;
	unsigned long flags;

 	if (my_data->cache_size <= my_data->cache_limit) {
 		UCM_ERR("Cache size is too small = %ld gpu pages. cache_limit = %d *64K\n",
 				my_data->cache_size, my_data->cache_limit);
 		return;
 	}
	down_read(&mm->mmap_sem);

	shared_vma = find_vma(mm, my_data->start);
	if (!shared_vma) {
		UCM_ERR("no shared_vma found starting at 0x%llx\n", my_data->start);
		up_read(&mm->mmap_sem);
		return;
	}
	if (!shared_vma->gpu_mapped_shared) {
		UCM_ERR("Aquire is not supported for a NOT-GPU maped vma\n");
		up_read(&mm->mmap_sem);
		return;
	}

	if (!shared_vma->ucm_vm_ops || !shared_vma->ucm_vm_ops->get_mmaped_file || !shared_vma->ucm_vm_ops->invalidate_cached_page) {
		UCM_ERR("ucm_vm_ops not povided\n");
		up_read(&mm->mmap_sem);
		return;
	}

	cpu_addr = shared_vma->ucm_vm_ops->get_cpu_addr(shared_vma, my_data->start,
			my_data->start + shared_vma->vm_start - shared_vma->vm_end);
	if (!cpu_addr) {
		UCM_ERR("Didn't find CPU addr?!?!?\n");
		up_read(&mm->mmap_sem);
		return;
	}
	cpu_vma = find_vma(mm, cpu_addr);
	if (!cpu_vma || !cpu_vma->vm_file) {
		UCM_ERR("no cpu_vma/cpu_vma->vm_file found starting at 0x%llx\n", cpu_addr);
		up_read(&mm->mmap_sem);
		return;
	}
	mapping = cpu_vma->vm_file->f_mapping;
	spin_lock_irqsave(&mapping->tree_lock, flags);
	mapping->gpu_cache_sz = my_data->cache_size;
	mapping->gpu_cache_limit = my_data->cache_limit;


	//Check cache size
	if (mapping->gpu_cache_limit  + mapping->gpu_cached_data_sz > mapping->gpu_cache_sz  ) {
		stat_gpu_removed = 0;
		//UCM_DBG("Need to clean up cache!!! cache_size=%ld (gpu pages), gpu_cached_sz = %ld (gpu pages) CACHE_UP_LIMIT=%d\n",
			//	mapping->gpu_cache_sz/GPU_PAGE_SZ, mapping->gpu_cached_data_sz/GPU_PAGE_SZ, CACHE_UP_LIMIT);
		list_for_each_entry_safe_reverse(pdata, tmp, &mapping->gpu_lra, lra) {
			struct page *gpu_page = pdata->my_page;
			if (!gpu_page) {
				UCM_ERR("gpu_page == null!!!\n");
				goto done;
			}
			if (mapping->gpu_cache_limit + mapping->gpu_cached_data_sz < mapping->gpu_cache_sz  ) {
				goto done;
			}

			struct mem_cgroup *memcg = mem_cgroup_begin_page_stat(gpu_page);
			__set_page_locked(gpu_page);
			__delete_from_page_cache_gpu(gpu_page, NULL, memcg, GPU_NVIDIA);
			mem_cgroup_end_page_stat(memcg);

			__clear_page_locked(gpu_page);
			if (shared_vma->ucm_vm_ops->invalidate_cached_page(shared_vma, pdata->shared_addr ))
				UCM_ERR("Error invalidating page at virt addr 0x%llx on GPU!!!\n", pdata->shared_addr );
			ClearPageonGPU(gpu_page);
			stat_gpu_removed++;
		}
	}
done:
	spin_unlock_irqrestore(&mapping->tree_lock, flags);
out_unlock:
	up_read(&mm->mmap_sem);
	schedule_delayed_work(&my_data->ucm_work, msecs_to_jiffies(my_data->interval));
}


/* Hack this func to start a thread to monitor the GPU page cache */
SYSCALL_DEFINE4(ghack, unsigned long, start, unsigned long, cache_size, unsigned long, cache_limit, unsigned long, intr) {
	static int started=0;

	if (!started) {
		INIT_DELAYED_WORK(&my_work_data.ucm_work, ucm_work_handler);
		my_work_data.start = start;
		my_work_data.cache_size = cache_size;
		my_work_data.mm = current->mm;
		my_work_data.cache_limit = cache_limit;
		my_work_data.interval = intr;
		schedule_delayed_work(&my_work_data.ucm_work, msecs_to_jiffies(intr));
		UCM_DBG("started ucm work gpucachesz = %d gpu pages, cache limit= %d gpu pages (interval = %d ms)\n",
				cache_size, cache_limit, intr);
		started++;
	} else {
		(void) cancel_delayed_work_sync(&my_work_data.ucm_work);
		UCM_DBG("stoped UCM work\n");
		started = 0;
	}
	UCM_DBG("exit\n");
    return 0 ;
}


SYSCALL_DEFINE3(gpull, unsigned long, start, size_t, len, int, flags) {
	unsigned long end_byte;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *shared_vma, *cpu_vma;
	int unmapped_error = 0;
	int error = -EINVAL;
	struct file *mfile = NULL;
	int nr_pages;
 	pgoff_t index, end;

 	int num_gpu_pages = 0;
 	int num_cpu_invalidated = 0;
 	int num_cache_taged = 0;

	if (flags & ~(MA_PROC_NVIDIA | MA_PROC_AMD)) {
		UCM_ERR("What GPU should I aquire for??? Exit\n");
                goto out;
	}
    if (offset_in_page(start))
    	goto out;
	if ((flags & MS_ASYNC) && (flags & MS_SYNC))
		goto out;

	error = -ENOMEM;
	if ( start + len <= start)
		goto out;
	error = 0;

	down_read(&mm->mmap_sem);
	shared_vma = find_vma(mm, start);
	if (!shared_vma) {
		UCM_ERR("no shared_vma found starting at 0x%llx\n", start);
		goto out_unlock;
	}
	if (!shared_vma->gpu_mapped_shared) {
		UCM_ERR("Aquire is not supported for a NOT-GPU maped vma\n");
		error = -EINVAL;
		goto out_unlock;
	}
	if (!shared_vma->ucm_vm_ops ) {
			UCM_ERR("ucm_vm_ops not povided vma=0x%llx\n", shared_vma);
			error = -EINVAL;
			goto out_unlock;
		}
	if (!shared_vma->ucm_vm_ops->is_gpu_page_dirty ) {
				UCM_ERR("is_gpu_page_dirty not povided vma=0x%llx\n", shared_vma);
				error = -EINVAL;
				goto out_unlock;
			}
	if (!shared_vma->ucm_vm_ops->get_cpu_addr) {
				UCM_ERR("get_cpu_addr not povided vma=0x%llx\n", shared_vma);
				error = -EINVAL;
				goto out_unlock;
			}

	unsigned long int cpu_addr = shared_vma->ucm_vm_ops->get_cpu_addr(shared_vma, start, end);
	if (!cpu_addr) {
		UCM_ERR("Didn't find CPU addr?!?!?\n");
		error = -EINVAL;
                goto out_unlock;
	}
	cpu_vma = find_vma(mm, cpu_addr);
	if (!cpu_vma || !cpu_vma->vm_file) {
		UCM_ERR("no cpu_vma found (or !cpu_vma->vm_file) starting at 0x%llx\n", cpu_addr);
		goto out_unlock;
	}

	index = 0; //(cpu_addr - cpu_vma->vm_start) / PAGE_SIZE;
	end = (cpu_vma->vm_end - cpu_vma->vm_start)/PAGE_SIZE; //(cpu_addr + len - cpu_vma->vm_start) / PAGE_SIZE + 1;
	while ((index <= end) ) {
		unsigned i;
		int gpu_page_idx = -1;
		int *pages_idx;
		unsigned long tagged, tagged_gpu;

		pages_idx = (int*)kzalloc(sizeof(int)*(end - index + 1), GFP_KERNEL);
		if (!pages_idx) {
			UCM_ERR("Error allocating memory!\n");
			error = -ENOMEM;
         	       goto out_unlock;
		}
		nr_pages = find_get_taged_pages_idx(cpu_vma->vm_file->f_mapping, &index,
				end - index + 1, pages_idx, PAGECACHE_TAG_ON_GPU);
		num_cache_taged += nr_pages;
		if (!nr_pages) {
			//UCM_DBG("No pages taged as ON_GPU: index = %ld, nrpages=%ld\n", index, end - index + 1);
			break;
		}
		for (i = 0; i < nr_pages; i++) {
			int page_idx = pages_idx[i];
			/* until radix tree lookup accepts end_index */
			if (page_idx > end)
				continue;

			if (1) { //(gpu_page_idx == -1) || (gpu_page_idx != page_idx % 16)) {
				struct page *gpu_page = pagecache_get_gpu_page(cpu_vma->vm_file->f_mapping, page_idx, GPU_NVIDIA, true);
				spin_lock_irqsave(&cpu_vma->vm_file->f_mapping->tree_lock, flags);
				if (gpu_page) {
					struct ucm_page_data *pdata = (struct ucm_page_data *)gpu_page->private;
					unsigned long cpu_page_addr;
					unsigned long gpu_page_addr;
					int j;
					int gpu_dirty = 0;

					if (!pdata) {
						UCM_ERR("GPu page at idx %ld has pdata =null\n", gpu_page->index);
						spin_unlock_irqrestore(&cpu_vma->vm_file->f_mapping->tree_lock, flags);
						continue;
					}
					cpu_page_addr = pdata->shared_addr - shared_vma->vm_start + cpu_vma->vm_start;
					gpu_page_addr = pdata->shared_addr;
					num_gpu_pages++;
					gpu_page_idx = gpu_page->index;

					if (!shared_vma->ucm_vm_ops->is_gpu_page_dirty(shared_vma, gpu_page))
						continue;

					//Now increase the page version on gpu

					increase_page_version(cpu_vma->vm_file->f_mapping, page_idx, GPU_NVIDIA);


					for (j = 0; j <16; j+=2) {
						struct page *cpu_page = find_get_entry(cpu_vma->vm_file->f_mapping, page_idx + j, NULL);
						int ret;
						if (!cpu_page) {
							UCM_ERR("Didn;t find cpu page in cache???!!!\n");
							continue;
						}
						__set_page_locked(cpu_page);
						ret = try_to_unmap(cpu_page, TTU_UNMAP|TTU_IGNORE_MLOCK|TTU_IGNORE_ACCESS);
						if (ret != SWAP_SUCCESS) {
							UCM_ERR("\nFailed unmaping page ret = %d\n", ret);
							spin_unlock_irqrestore(&cpu_vma->vm_file->f_mapping->tree_lock, flags);
							continue;
						}
						if (shared_vma->ucm_vm_ops->retrive_cached_page(shared_vma->vm_start + (cpu_page->index % 16)*PAGE_SIZE, cpu_page)) {
							UCM_ERR("FAIL ++++ retrive_cached_page for idx = %lld FAILED\n",  cpu_page->index );
							//page_cache_release(page);
							//return NULL;
						} else
							(void)set_page_version_as_on(cpu_vma->vm_file->f_mapping, cpu_page->index ,SYS_CPU, GPU_NVIDIA);
						__clear_page_locked(cpu_page);
						put_page(cpu_page);
					}
				} else
					UCM_ERR("page @idx %d not cached on gpu???\n", page_idx);
				spin_unlock_irqrestore(&cpu_vma->vm_file->f_mapping->tree_lock, flags);
			}
		}
		kfree(pages_idx);
	}

out_unlock:
	//rcu_read_unlock();
	up_read(&mm->mmap_sem);

out:
    return error ? : unmapped_error;
}
