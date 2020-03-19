
#ifndef _SFC_VDPA_OPS_H
#define _SFC_VDPA_OPS_H

#include "sfc_vdpa.h"
#include <rte_ethdev.h>
#include <rte_ether.h>

#define SFC_VDPA_MAX_QUEUES		1

enum sfc_vdpa_context {
	SFC_VDPA_AS_PF = 0,
	SFC_VDPA_AS_VF
};

enum sfc_vdpa_state {
	SFC_VDPA_STATE_UNINITIALIZED = 0,
	SFC_VDPA_STATE_INITIALIZED,
	SFC_VDPA_STATE_CONFIGURING,
	SFC_VDPA_STATE_CONFIGURED,
	SFC_VDPA_STATE_CLOSING,
	SFC_VDPA_STATE_STARTING,
	SFC_VDPA_STATE_STARTED,
	SFC_VDPA_STATE_STOPPING,

	SFC_VDPA_STATE_NSTATES
};

struct sfc_vdpa_vring_info {
	uint64_t desc;
	uint64_t avail;
	uint64_t used;
	uint64_t size;
	uint16_t last_avail_idx;
	uint16_t last_used_idx;
};

struct sfc_vdpa_ops_data {
	int vid; /* vhost_id */
	int did; /* dev id */

	enum sfc_vdpa_state state;

	struct rte_pci_device *pci_dev;
	struct rte_pci_addr pf_pci_addr; // move into sva

	/* PF's NIC */
	efx_nic_t *nic;
	
	rte_atomic32_t dev_attached;
	rte_spinlock_t lock;
	
	enum sfc_vdpa_context vdpa_context;

	int fcw_offset;

	uint16_t max_queues;
	uint16_t num_vring;
	
	int vfio_group_fd;
	int vfio_dev_fd;
	int vfio_container_fd;
	
	uint32_t pf_index;
	uint32_t vf_index;
	uint32_t vport_id;

	struct sfc_vdpa_vring_info vring[SFC_VDPA_MAX_QUEUES * 2];
	struct efx_virtio_vq_s *vq[SFC_VDPA_MAX_QUEUES * 2]; /* virtq context */

	uint32_t pidx[SFC_VDPA_MAX_QUEUES *2];
	uint32_t cidx[SFC_VDPA_MAX_QUEUES *2];
	
	uint64_t drv_features; /* Features supported by driver */
	uint64_t dev_features; /* Features supported by device */
	uint64_t req_features;
	
	//rte_ether_addr eth_addr;
    uint8_t eth_addr[6];
	
	/*TODO: Is it ok to use ef10 types ? */
	ef10_filter_handle_t bcast_mac_filter_handle;
	ef10_filter_handle_t unicast_mac_filter_handle;
};

/*
 * Add wrapper functions to acquire/release lock to be able to remove or
 * change the lock in one place.
 */

static inline void
sfc_vdpa_adapter_lock_init(struct sfc_vdpa_ops_data *vdpa_data)
{
	rte_spinlock_init(&vdpa_data->lock);
}

static inline int
sfc_vdpa_adapter_is_locked(struct sfc_vdpa_ops_data *vdpa_data)
{
	return rte_spinlock_is_locked(&vdpa_data->lock);
}

static inline void
sfc_vdpa_adapter_lock(struct sfc_vdpa_ops_data *vdpa_data)
{
	rte_spinlock_lock(&vdpa_data->lock);
}

static inline int
sfc_vdpa_adapter_trylock(struct sfc_vdpa_ops_data *vdpa_data)
{
	return rte_spinlock_trylock(&vdpa_data->lock);
}

static inline void
sfc_vdpa_adapter_unlock(struct sfc_vdpa_ops_data *vdpa_data)
{
	rte_spinlock_unlock(&vdpa_data->lock);
}

static inline void
sfc_vdpa_adapter_lock_fini(__rte_unused struct sfc_vdpa_ops_data *vdpa_data)
{
	/* Just for symmetry of the API */
}


struct sfc_vdpa_ops_data *sfc_vdpa_create_context(void);
void sfc_vdpa_delete_context(struct sfc_vdpa_ops_data *vdpa_data);
uint32_t sfc_vdpa_register_device(struct sfc_vdpa_ops_data *vdpa_data, struct rte_vdpa_dev_addr *dev_addr);
void sfc_vdpa_unregister_device(struct sfc_vdpa_ops_data *vdpa_data);

#endif /* _SFC_VDPA_OPS_H */
