/*
 * Memory management library for rpmsg dma-able buffers.
 *
 * Copyright (C) 2014 Huawei Technologies, Inc.
 *
 * Ajo Jose Panoor <ajo.jose.panoor@huawei.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/rpmsg.h>
#include <linux/mutex.h>
#include <linux/uio.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/dmapool.h>
#include <asm/bitops.h>
#include "virtio_rpmsg.h"

#define MAX_POOL_PKT_SIZE	(8192)
#define MIN_POOL_PKT_SIZE	(32)
#define MIN_POOL_PKT_SIZE_IDX	(ffs(MIN_POOL_PKT_SIZE) - 1)
#define MAX_POOL_PKT_SIZE_IDX	(ffs(MAX_POOL_PKT_SIZE) - 1)
#define DMA_POOL_ARRAY_SIZE	(MAX_POOL_PKT_SIZE_IDX + 1)

#define MAX(X,Y)		((X) > (Y) ? (X) : (Y))
#define MIN(X,Y)		((X) < (Y) ? (X) : (Y))

/*
 * Function will return the round down value of power of 2.
 */
static unsigned int inline fln2(unsigned int val)
{
	unsigned int v = val;
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}
#if 0
/*
 * Function will return the round up value of power of 2.
 */
static unsigned int flp2 (unsigned int x)
{
	x = x | (x >> 1);
	x = x | (x >> 2);
	x = x | (x >> 4);
	x = x | (x >> 8);
	x = x | (x >> 16);
	return x - (x >> 1);
}
#endif
/*
 * This function finds the best fit pool packet sizes needed to DMA the
 * requested buffer to remote size. Function will can work as a first fit
 * algorithm or best fit algorithm based on the request.
 * @p: Pointer to pool_pkt_info to return the pool packet sizes and number of
 *	packets needed to accomodate the request.
 * @v: Size of the buffer that needs to be transmitted.
 * @min: Minimum sized pool packet we can have (MIN_POOL_PKT_SIZE bytes).
 * @pmax: Maximum size pool packet we can round to. If MAX_POOL_PKT_SIZE is
 * 	passed, the allocations would be rounded up to the nearest power of 2
 * 	within MAX_POOL_PKT_SIZE or if we pass MIN(MAX_POOL_PKT_SIZE, flp2(val))
 * 	the packets gets sized to the nearest round down power 2 and residual
 * 	value will be allocated from the lowest pool possible from
 * 	MIN_POOL_PKT_SIZE.
 *
 *	calc_pool_pkt_cnt(&p, val, MIN_POOL_PKT_SIZE, MIN(MAX_POOL_PKT_SIZE,
 *								flp2(val)));
 *	calc_pool_pkt_cnt(&p, val, MIN_POOL_PKT_SIZE, MAX_POOL_PKT_SIZE);
 */
static inline void calc_pool_pkt_cnt(struct pool_pkt_info *p, size_t v,
						size_t min, size_t pmax)
{
	int b, m;
	int max = MAX(min, pmax);

	if (v > max) {
		p->base_size = max;
		p->base_cnt = (b = (v / max)) ? b : 1;
		m = v % max;
		p->mod_size = ((m) ? MAX(min, fln2(m)) : 0);
		p->mod_cnt = p->mod_size ? 1 : 0;
	} else {
		p->base_size = MAX(min, fln2(v));
		p->base_cnt = 1;
		p->mod_size = 0;
		p->mod_cnt = 0;
	}
	p->act_size = v;
}

/*
 * Free up routine to deallocated dma pools.
 */
void rpmsg_dma_pool_destroy(struct virtproc_info *vrp, struct device *dev)
{
	int i;
	int dma_pool_arr_size = DMA_POOL_ARRAY_SIZE;

	for(i = MIN_POOL_PKT_SIZE_IDX; i < dma_pool_arr_size; i++) {
		if(vrp->dma_mem_pool[i].pool)
			dma_pool_destroy(vrp->dma_mem_pool[i].pool);
	}
	kfree(vrp->dma_mem_pool);
}

/*
 * Allocates memory pools starting from 32 Bytes to 8192 Bytes.
 * This can be used by rpmsg_send routines based on the transport mechanisms.
 */
int rpmsg_dma_pool_create(struct virtproc_info *vrp, struct device *dev)
{
	int i, err = 0, dma_pool_arr_size = DMA_POOL_ARRAY_SIZE;
	size_t size;
	char name[20];

	vrp->dma_mem_pool = kzalloc(sizeof(struct rpmsg_dma_pool) *
						dma_pool_arr_size, GFP_KERNEL);
	if(!vrp->dma_mem_pool) {
		dev_err(dev, "failed allocating dma_mem_pool\n");
		return -ENOMEM;
	}
	for(i = MIN_POOL_PKT_SIZE_IDX; i < dma_pool_arr_size; i++) {
		size = 1 << i;
		BUG_ON(size > MAX_POOL_PKT_SIZE);

		snprintf(name, sizeof(name), "rpmsg-buf-%d", (int)size);
		vrp->dma_mem_pool[i].size = size;
		vrp->dma_mem_pool[i].align = MIN(size, PAGE_SIZE);

		vrp->dma_mem_pool[i].pool = dma_pool_create(name, dev,
						vrp->dma_mem_pool[i].size,
						vrp->dma_mem_pool[i].align, 0);
		if(!vrp->dma_mem_pool[i].pool){
			dev_err(dev, "dma_pool_create failed! pool size "
							"= %u\n", (int)size);
			rpmsg_dma_pool_destroy(vrp, dev);
			err = -ENOMEM;
			return err;
		}
	}
	return err;
}
