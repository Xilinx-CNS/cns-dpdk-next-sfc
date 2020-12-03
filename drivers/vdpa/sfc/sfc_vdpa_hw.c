/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2020-2021 Xilinx, Inc.
 */

#include <unistd.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_vfio.h>

#include "efx.h"
#include "sfc_vdpa.h"
#include "sfc_vdpa_ops.h"

extern uint32_t sfc_logtype_driver;

#ifndef PAGE_SIZE
#define PAGE_SIZE   (sysconf(_SC_PAGESIZE))
#endif

int
sfc_vdpa_dma_alloc(struct sfc_vdpa_adapter *sva, const char *name,
		   size_t len, efsys_mem_t *esmp)
{
	void *mcdi_buf;
	uint64_t mcdi_iova;
	size_t mcdi_buff_size;
	int ret;

	mcdi_buff_size = RTE_ALIGN_CEIL(len, PAGE_SIZE);

	sfc_vdpa_log_init(sva, "name=%s, len=%zu", name, len);

	mcdi_buf = rte_zmalloc(name, mcdi_buff_size, PAGE_SIZE);
	if (mcdi_buf == NULL) {
		sfc_vdpa_err(sva, "cannot reserve memory for %s: len=%#x: %s",
			     name, (unsigned int)len, rte_strerror(rte_errno));
		return -ENOMEM;
	}

	/* IOVA address for MCDI would be re-calculated if mapping
	 * using default IOVA would fail.
	 * TODO: Earlier there was no way to get valid IOVA range.
	 * Recently a patch has been submitted to get the IOVA range
	 * using ioctl. VFIO_IOMMU_GET_INFO. This patch is available
	 * in the kernel version >= 5.4. Support to get the default
	 * IOVA address for MCDI buffer using available IOVA range
	 * would be added later. Meanwhile default IOVA for MCDI buffer
	 * is kept at high mem at 2TB. In case of overlap new available
	 * addresses would be searched and same would be used.
	 */
	mcdi_iova = SFC_VDPA_DEFAULT_MCDI_IOVA;

	do {
		ret = rte_vfio_container_dma_map(sva->vfio_container_fd,
						 (uint64_t)mcdi_buf, mcdi_iova,
						 mcdi_buff_size);
		if (ret == 0)
			break;

		mcdi_iova = mcdi_iova >> 1;
		if (mcdi_iova < mcdi_buff_size)	{
			sfc_vdpa_err(sva,
				     "DMA mapping failed for MCDI : %s",
				     rte_strerror(rte_errno));
			return ret;
		}

	} while (ret < 0);

	esmp->esm_addr = mcdi_iova;
	esmp->esm_base = mcdi_buf;
	sva->mcdi_buff_size = mcdi_buff_size;

	sfc_vdpa_info(sva,
		      "DMA name=%s len=%lu => virt=%p iova=%lx",
		      name, len, esmp->esm_base,
		      (unsigned long)esmp->esm_addr);

	return 0;
}

void
sfc_vdpa_dma_free(struct sfc_vdpa_adapter *sva, efsys_mem_t *esmp)
{
	int ret;

	sfc_vdpa_log_init(sva, "name=%s", esmp->esm_mz->name);

	ret = rte_vfio_container_dma_unmap(sva->vfio_container_fd,
					   (uint64_t)esmp->esm_base,
					   esmp->esm_addr, sva->mcdi_buff_size);
	if (ret < 0)
		sfc_vdpa_err(sva, "DMA unmap failed for MCDI : %s",
			     rte_strerror(rte_errno));

	sfc_vdpa_info(sva,
		      "DMA free name=%s => virt=%p iova=%lx",
		      esmp->esm_mz->name, esmp->esm_base,
		      (unsigned long)esmp->esm_addr);

	rte_free((void *)(esmp->esm_base));

	sva->mcdi_buff_size = 0;
	memset(esmp, 0, sizeof(*esmp));
}

static int
sfc_vdpa_mem_bar_init(struct sfc_vdpa_adapter *sva,
		      const efx_bar_region_t *mem_ebrp)
{
	struct rte_pci_device *pci_dev = sva->pdev;
	efsys_bar_t *ebp = &sva->mem_bar;
	struct rte_mem_resource *res =
		&pci_dev->mem_resource[mem_ebrp->ebr_index];

	SFC_BAR_LOCK_INIT(ebp, pci_dev->name);
	ebp->esb_rid = mem_ebrp->ebr_index;
	ebp->esb_dev = pci_dev;
	ebp->esb_base = res->addr;

	return 0;
}

static void
sfc_vdpa_mem_bar_fini(struct sfc_vdpa_adapter *sva)
{
	efsys_bar_t *ebp = &sva->mem_bar;

	SFC_BAR_LOCK_DESTROY(ebp);
	memset(ebp, 0, sizeof(*ebp));
}

static int
sfc_vdpa_nic_probe(struct sfc_vdpa_adapter *sva)
{
	efx_nic_t *enp = sva->nic;
	int rc;

	rc = efx_nic_probe(enp, EFX_FW_VARIANT_DONT_CARE);
	if (rc != 0)
		sfc_vdpa_err(sva, "nic probe failed: %s", rte_strerror(rc));

	return rc;
}

static int
sfc_vdpa_estimate_resource_limits(struct sfc_vdpa_adapter *sva)
{
	efx_drv_limits_t limits;
	int rc;
	uint32_t evq_allocated;
	uint32_t rxq_allocated;
	uint32_t txq_allocated;
	uint32_t max_queue_cnt;

	memset(&limits, 0, sizeof(limits));

	/* Request at least one Rx and Tx queue */
	limits.edl_min_rxq_count = 1;
	limits.edl_min_txq_count = 1;
	/* Management event queue plus event queue for Tx/Rx queue */
	limits.edl_min_evq_count =
		1 + RTE_MAX(limits.edl_min_rxq_count, limits.edl_min_txq_count);

	limits.edl_max_rxq_count = SFC_VDPA_MAX_QUEUE_PAIRS;
	limits.edl_max_txq_count = SFC_VDPA_MAX_QUEUE_PAIRS;
	limits.edl_max_evq_count = 1 + SFC_VDPA_MAX_QUEUE_PAIRS;

	SFC_VDPA_ASSERT(limits.edl_max_evq_count >= limits.edl_min_rxq_count);
	SFC_VDPA_ASSERT(limits.edl_max_rxq_count >= limits.edl_min_rxq_count);
	SFC_VDPA_ASSERT(limits.edl_max_txq_count >= limits.edl_min_rxq_count);

	/* Configure the minimum required resources needed for the
	 * driver to operate, and the maximum desired resources that the
	 * driver is capable of using.
	 */
	sfc_vdpa_log_init(sva, "set drv limit");
	efx_nic_set_drv_limits(sva->nic, &limits);

	sfc_vdpa_log_init(sva, "init nic");
	rc = efx_nic_init(sva->nic);
	if (rc != 0) {
		sfc_vdpa_err(sva, "nic init failed: %s", rte_strerror(rc));
		goto fail_nic_init;
	}

	/* Find resource dimensions assigned by firmware to this function */
	rc = efx_nic_get_vi_pool(sva->nic, &evq_allocated, &rxq_allocated,
				 &txq_allocated);
	if (rc != 0) {
		sfc_vdpa_err(sva, "vi pool get failed: %s", rte_strerror(rc));
		goto fail_get_vi_pool;
	}

	/* It still may allocate more than maximum, ensure limit */
	evq_allocated = RTE_MIN(evq_allocated, limits.edl_max_evq_count);
	rxq_allocated = RTE_MIN(rxq_allocated, limits.edl_max_rxq_count);
	txq_allocated = RTE_MIN(txq_allocated, limits.edl_max_txq_count);


	max_queue_cnt = RTE_MIN(rxq_allocated, txq_allocated);
	/* Subtract management EVQ not used for traffic */
	max_queue_cnt = RTE_MIN(evq_allocated - 1, max_queue_cnt);

	SFC_VDPA_ASSERT(max_queue_cnt > 0);

	sva->max_queue_count = max_queue_cnt;

	return 0;

fail_get_vi_pool:
	efx_nic_fini(sva->nic);
fail_nic_init:
	sfc_vdpa_log_init(sva, "failed: %s", rte_strerror(rc));
	return rc;
}

int
sfc_vdpa_hw_init(struct sfc_vdpa_adapter *sva)
{
	efx_bar_region_t mem_ebr;
	efx_nic_t *enp;
	int rc;

	sfc_vdpa_log_init(sva, "entry");

	sfc_vdpa_log_init(sva, "get family");
	rc = sfc_efx_family(sva->pdev, &mem_ebr, &sva->family);
	if (rc != 0)
		goto fail_family;
	sfc_vdpa_log_init(sva,
			  "family is %u, membar is %u,"
			  "function control window offset is %lu",
			  sva->family, mem_ebr.ebr_index, mem_ebr.ebr_offset);

	sfc_vdpa_log_init(sva, "init mem bar");
	rc = sfc_vdpa_mem_bar_init(sva, &mem_ebr);
	if (rc != 0)
		goto fail_mem_bar_init;

	sfc_vdpa_log_init(sva, "create nic");
	rte_spinlock_init(&sva->nic_lock);
	rc = efx_nic_create(sva->family, (efsys_identifier_t *)sva,
			    &sva->mem_bar, mem_ebr.ebr_offset,
			    &sva->nic_lock, &enp);
	if (rc != 0) {
		sfc_vdpa_err(sva, "nic create failed: %s", rte_strerror(rc));
		goto fail_nic_create;
	}
	sva->nic = enp;

	sfc_vdpa_log_init(sva, "init mcdi");
	rc = sfc_vdpa_mcdi_init(sva);
	if (rc != 0) {
		sfc_vdpa_err(sva, "mcdi init failed: %s", rte_strerror(rc));
		goto fail_mcdi_init;
	}

	sfc_vdpa_log_init(sva, "probe nic");
	rc = sfc_vdpa_nic_probe(sva);
	if (rc != 0)
		goto fail_nic_probe;

	sfc_vdpa_log_init(sva, "reset nic");
	rc = efx_nic_reset(enp);
	if (rc != 0) {
		sfc_vdpa_err(sva, "nic reset failed: %s", rte_strerror(rc));
		goto fail_nic_reset;
	}

	sfc_vdpa_log_init(sva, "estimate resource limits");
	rc = sfc_vdpa_estimate_resource_limits(sva);
	if (rc != 0)
		goto fail_estimate_rsrc_limits;

	sfc_vdpa_log_init(sva, "done");

	return 0;

fail_estimate_rsrc_limits:
fail_nic_reset:
	efx_nic_unprobe(enp);

fail_nic_probe:
	sfc_vdpa_mcdi_fini(sva);

fail_mcdi_init:
	sfc_vdpa_log_init(sva, "destroy nic");
	sva->nic = NULL;
	efx_nic_destroy(enp);

fail_nic_create:
	sfc_vdpa_mem_bar_fini(sva);

fail_mem_bar_init:
fail_family:
	sfc_vdpa_log_init(sva, "failed: %s", rte_strerror(rc));
	return rc;
}

void
sfc_vdpa_hw_fini(struct sfc_vdpa_adapter *sva)
{
	efx_nic_t *enp = sva->nic;

	sfc_vdpa_log_init(sva, "entry");

	sfc_vdpa_log_init(sva, "unprobe nic");
	efx_nic_unprobe(enp);

	sfc_vdpa_log_init(sva, "mcdi fini");
	sfc_vdpa_mcdi_fini(sva);

	sfc_vdpa_log_init(sva, "nic fini");
	efx_nic_fini(enp);

	sfc_vdpa_log_init(sva, "destroy nic");
	sva->nic = NULL;
	efx_nic_destroy(enp);

	sfc_vdpa_mem_bar_fini(sva);
}
