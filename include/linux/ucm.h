/*
 * Copyright (C) 2001 Momchil Velikov
 * Portions Copyright (C) 2001 Christoph Hellwig
 * Copyright (C) 2006 Nick Piggin
 * Copyright (C) 2012 Konstantin Khlebnikov
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#ifndef _UCM_H
#define _UCM_H

#define MA_PROC_NVIDIA	0x10
#define MA_PROC_AMD	0x20

#define CACHE_UP_LIMIT	10 //10% of the gpu cache size
#define GPU_PAGE_SZ (64*1024)

enum system_processors {
	GPU_NVIDIA = 0,
	GPU_AMD,
	SYS_CPU, //should go after all of system GPUs
	SYS_DISK,
	SYS_PROCS
};

static char *proc_names[] = {"GPU_NVIDIA", "GPU_AMD", "SYS_CPU", "SYS_DISK", "SYS_PROCS"};

struct ucm_page_data {
	//The virtual address this page is maped to in the nvidia vma
	unsigned long shared_addr;
	struct vm_area_struct *gpu_maped_vma;
	struct list_head lra; //last recently allocated
	struct page *my_page;
};
#endif /* _UCM_H */
