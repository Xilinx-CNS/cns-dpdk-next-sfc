#include "sfc_vdpa.h"
#include <rte_errno.h>
#include <rte_alarm.h>

extern uint32_t sfc_logtype_driver;

#define DRV_LOG(level, fmt, args...) \
        rte_log(RTE_LOG_ ## level, sfc_logtype_driver, \
                "SFC_VDPA %s(): " fmt "\n", __func__, ##args)

uint32_t
sfc_vdpa_register_logtype(struct sfc_vdpa_adapter *sva, const char *lt_prefix_str,
		     uint32_t ll_default)
{
	size_t lt_prefix_str_size = strlen(lt_prefix_str);
	size_t lt_str_size_max;
	char *lt_str = NULL;
	int ret;

	if (SIZE_MAX - PCI_PRI_STR_SIZE - 1 > lt_prefix_str_size) {
		++lt_prefix_str_size; /* Reserve space for prefix separator */
		lt_str_size_max = lt_prefix_str_size + PCI_PRI_STR_SIZE + 1;
	} else {
		return RTE_LOGTYPE_PMD;
	}

	lt_str = rte_zmalloc("logtype_str", lt_str_size_max, 0);
	if (lt_str == NULL)
		return RTE_LOGTYPE_PMD;

	strncpy(lt_str, lt_prefix_str, lt_prefix_str_size);
	lt_str[lt_prefix_str_size - 1] = '.';
	rte_pci_device_name(&sva->pci_addr, lt_str + lt_prefix_str_size,
			    lt_str_size_max - lt_prefix_str_size);
	lt_str[lt_str_size_max - 1] = '\0';

	ret = rte_log_register_type_and_pick_level(lt_str, ll_default);
	rte_free(lt_str);

	return (ret < 0) ? RTE_LOGTYPE_PMD : ret;
}

int
sfc_dma_alloc(const struct sfc_vdpa_adapter *sva, const char *name, uint16_t id,
	      size_t len, efsys_mem_t *esmp)
{
	const struct rte_memzone *mz;
	int ret;

      	mz = rte_memzone_reserve_aligned(name, len, /* sva->socket_id, */  SOCKET_ID_ANY, 
			RTE_MEMZONE_IOVA_CONTIG, sysconf(_SC_PAGESIZE));
	if (mz == NULL) {
		sfc_err(sva, "cannot reserve DMA zone for %s:%u %d: %s",
			name, (unsigned int)id, (unsigned int)len,
			rte_strerror(rte_errno));
		return ENOMEM;
	}

	ret = rte_vfio_container_dma_map(sva->vfio_container_fd,
				(uint64_t)mz->addr, mz->iova, 4096);
        if (ret<0)
        {
           DRV_LOG(ERR, "Praveen40: virtual addr %lx, iova addr %lx ", (uint64_t)mz->addr, mz->iova);

        }

	esmp->esm_addr = mz->iova;
	if (esmp->esm_addr == RTE_BAD_IOVA) {
		(void)rte_memzone_free(mz);
		return EFAULT;
	}

	esmp->esm_mz = mz;
	esmp->esm_base = mz->addr;

	return 0;
}

void
sfc_dma_free(const struct sfc_vdpa_adapter *sva, efsys_mem_t *esmp)
{
	int rc;

	sfc_log_init(sva, "name=%s", esmp->esm_mz->name);

	rc = rte_memzone_free(esmp->esm_mz);
	if (rc != 0)
		sfc_err(sva, "rte_memzone_free(() failed: %d", rc);

	memset(esmp, 0, sizeof(*esmp));
}

static int 
sfc_vdpa_get_device_features(struct sfc_vdpa_adapter *sva)
{
	int rc;
	uint64_t dev_features;

	rc = efx_virtio_get_features(sva->nic, EFX_VIRTIO_DEVICE_TYPE_NET, &dev_features);
	if ( rc < 0) {
		DRV_LOG(ERR, "failed to get device supported features %s", sva->pdev->name);
		goto error;
	}

	sva->dev_features = dev_features;

	return 0; 
	
error:
	return rc;
}

static int
sfc_vdpa_mem_bar_init(struct sfc_vdpa_adapter *sva, unsigned int membar)
{
	struct rte_pci_device *pci_dev = sva->pdev;
	efsys_bar_t *ebp = &sva->mem_bar;
	struct rte_mem_resource *res = &pci_dev->mem_resource[membar];

	SFC_BAR_LOCK_INIT(ebp, "memBAR");
	ebp->esb_rid = membar;
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
sfc_vdpa_get_fw_variant(struct sfc_vdpa_adapter *sva, efx_fw_variant_t *efv)
{
	efx_nic_fw_info_t enfi;
	int rc;

	rc = efx_nic_get_fw_version(sva->nic, &enfi);
	if (rc != 0)
		return rc;
	else if (!enfi.enfi_dpcpu_fw_ids_valid)
		return ENOTSUP;

	/*
  	 * Firmware variant can be uniquely identified by the RxDPCPU
  	 * firmware id
  	 */
	switch (enfi.enfi_rx_dpcpu_fw_id) {
	case EFX_RXDP_FULL_FEATURED_FW_ID:
		*efv = EFX_FW_VARIANT_FULL_FEATURED;
		break;

	case EFX_RXDP_LOW_LATENCY_FW_ID:
		*efv = EFX_FW_VARIANT_LOW_LATENCY;
		break;

	case EFX_RXDP_PACKED_STREAM_FW_ID:
		*efv = EFX_FW_VARIANT_PACKED_STREAM;
		break;

	case EFX_RXDP_DPDK_FW_ID:
		*efv = EFX_FW_VARIANT_DPDK;
		break;

	default:
		/*
	 	* Other firmware variants are not considered, since they are
	 	* not supported in the device parameters
	 	*/
		*efv = EFX_FW_VARIANT_DONT_CARE;
		break;
	}

	return 0;
}

static int
sfc_vdpa_nic_probe(struct sfc_vdpa_adapter *sva)
{
	efx_nic_t *enp = sva->nic;
	efx_fw_variant_t preferred_efv;
	efx_fw_variant_t efv;
	int rc;

	preferred_efv = EFX_FW_VARIANT_FULL_FEATURED;

	rc = efx_nic_probe(enp, preferred_efv);
	if (rc == EACCES) {
		/* Unprivileged functions cannot set FW variant */
		rc = efx_nic_probe(enp, EFX_FW_VARIANT_DONT_CARE);
	}
	if (rc != 0)
		return rc;

	rc = sfc_vdpa_get_fw_variant(sva, &efv);
	if (rc == ENOTSUP) {
		sfc_warn(sva, "FW variant can not be obtained");
		return 0;
	}
	if (rc != 0)
		return rc;

	/* Check that firmware variant was changed to the requested one */
	if (preferred_efv != EFX_FW_VARIANT_DONT_CARE && preferred_efv != efv) {
		sfc_warn(sva, "FW variant has not changed to the requested ");
	}


	return 0;
}

static int
sfc_vdpa_estimate_resource_limits(struct sfc_vdpa_adapter *sva)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(sva->nic);
	efx_drv_limits_t limits;
	int rc;

	memset(&limits, 0, sizeof(limits));

	/* Request at least one Rx and Tx queue */
	limits.edl_min_rxq_count = 1;
	limits.edl_min_txq_count = 1;
	/* Management event queue plus event queue for each Tx and Rx queue */
	limits.edl_min_evq_count = 
		1 + limits.edl_min_rxq_count + limits.edl_min_txq_count;

	/* Divide by number of functions to guarantee that all functions
 	 * will get promised resources
  	 */
	/* FIXME Divide by number of functions (not 2) below */
	limits.edl_max_evq_count = encp->enc_evq_limit / 2;
	SFC_ASSERT(limits.edl_max_evq_count >= limits.edl_min_rxq_count);

	/* Split equally between receive and transmit */
	limits.edl_max_rxq_count =
		MIN(encp->enc_rxq_limit, (limits.edl_max_evq_count - 1) / 2);
	SFC_ASSERT(limits.edl_max_rxq_count >= limits.edl_min_rxq_count);

	limits.edl_max_txq_count =
		MIN(encp->enc_rxq_limit, (limits.edl_max_evq_count - 1) / 2);

	SFC_ASSERT(limits.edl_max_txq_count >= limits.edl_min_rxq_count);

	/* Configure the minimum required resources needed for the
  	 * driver to operate, and the maximum desired resources that the
  	 * driver is capable of using.
  	 */
	efx_nic_set_drv_limits(sva->nic, &limits);

	sfc_log_init(sva, "init nic");
	rc = efx_nic_init(sva->nic);
	if (rc != 0)
		goto fail_nic_init;


	/* Keep NIC initialized */
	return 0;

fail_nic_init:
	efx_nic_fini(sva->nic);
	return rc;
}

int
sfc_vdpa_device_init(struct sfc_vdpa_adapter *sva)
{
	struct rte_pci_device *pci_dev = sva->pdev;
	unsigned int membar;
	efx_nic_t *enp;
	int rc;

	sva->logtype_main = sfc_vdpa_register_logtype(sva, SFC_LOGTYPE_MAIN_STR,
						RTE_LOG_NOTICE);
	sfc_log_init(sva, "entry");

	SFC_ASSERT(sfc_vdpa_adapter_is_locked(sva));

	// TODO need to analyze
	rte_atomic32_init(&sva->restart_required);

	sfc_log_init(sva, "get family");
	rc = efx_family(pci_dev->id.vendor_id, pci_dev->id.device_id,
			&sva->family, &membar);
	if (rc != 0)
		goto fail_family;
	sfc_log_init(sva, "family is %u, membar is %u", sva->family, membar);

	sfc_log_init(sva, "init mem bar");
	rc = sfc_vdpa_mem_bar_init(sva, membar);
	if (rc != 0)
		goto fail_mem_bar_init;

	sfc_log_init(sva, "create nic");
	rte_spinlock_init(&sva->nic_lock);
	rc = efx_nic_create(sva->family, (efsys_identifier_t *)sva,
			    &sva->mem_bar, &sva->nic_lock, &enp);
	if (rc != 0)
		goto fail_nic_create;
	sva->nic = enp;

	rc = sfc_vdpa_mcdi_init(sva);
	if (rc != 0)
		goto fail_mcdi_init;
 
	sfc_log_init(sva, "probe nic");
	rc = sfc_vdpa_nic_probe(sva);
	if (rc != 0)
		goto fail_nic_probe;

	sfc_log_init(sva, "reset nic");
	rc = efx_nic_reset(enp);
	if (rc != 0)
		goto fail_nic_reset;

	sfc_log_init(sva, "estimate resource limits");
	rc = sfc_vdpa_estimate_resource_limits(sva);
	if (rc != 0)
		goto fail_estimate_rsrc_limits;
	
	sfc_log_init(sva, "init mem bar");
	rc = efx_virtio_init(enp);
	if (rc != 0)
		goto fail_virtio_init;

	rc = sfc_vdpa_get_device_features(sva);
	if (rc != 0)
		goto fail_get_dev_feature;

	sfc_log_init(sva, "fini nic");
	efx_nic_fini(enp);

	sfc_log_init(sva, "done");

	sva->state = SFC_VDPA_ADAPTER_INITIALIZED;

	return 0;
	
fail_get_dev_feature:
	efx_virtio_fini(enp);

fail_virtio_init:
fail_estimate_rsrc_limits:
fail_nic_reset:
	efx_nic_unprobe(enp);

fail_nic_probe:
	sfc_vdpa_mcdi_fini(sva);

fail_mcdi_init:
	sfc_log_init(sva, "destroy nic");
	sva->nic = NULL;
	efx_nic_destroy(enp);

fail_nic_create:
	sfc_vdpa_mem_bar_fini(sva);

fail_mem_bar_init:
fail_family:
	sfc_log_init(sva, "failed %d", rc);
	return rc;
}

void
sfc_vdpa_device_fini(struct sfc_vdpa_adapter *sva)
{
	efx_nic_t *enp = sva->nic;

	sfc_log_init(sva, "entry");

	SFC_ASSERT(sfc_vdpa_adapter_is_locked(sva));

	sfc_log_init(sva, "unprobe nic");
	efx_nic_unprobe(enp);

	sfc_vdpa_mcdi_fini(sva);

	sfc_log_init(sva, "destroy nic");
	sva->nic = NULL;
	efx_nic_destroy(enp);

	sfc_vdpa_mem_bar_fini(sva);

	//sfc_vdpa_flow_fini(sva);
	sva->state = SFC_VDPA_ADAPTER_UNINITIALIZED;
}

