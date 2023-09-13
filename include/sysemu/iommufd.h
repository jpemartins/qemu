#ifndef SYSEMU_IOMMUFD_H
#define SYSEMU_IOMMUFD_H

#include "qom/object.h"
#include "exec/hwaddr.h"
#include "exec/cpu-common.h"

#define TYPE_IOMMUFD_BACKEND "iommufd"
OBJECT_DECLARE_TYPE(IOMMUFDBackend, IOMMUFDBackendClass, IOMMUFD_BACKEND)

struct IOMMUFDBackendClass {
    ObjectClass parent_class;
};

struct IOMMUFDBackend {
    Object parent;

    /*< protected >*/
    int fd;            /* /dev/iommu file descriptor */
    bool owned;        /* is the /dev/iommu opened internally */
    bool hugepages;    /* are hugepages enabled on the IOAS */
    uint32_t users;

    /*< public >*/
};

int iommufd_backend_connect(IOMMUFDBackend *be, Error **errp);
void iommufd_backend_disconnect(IOMMUFDBackend *be);

int iommufd_backend_alloc_ioas(IOMMUFDBackend *be, uint32_t *ioas_id,
                               Error **errp);
void iommufd_backend_free_id(IOMMUFDBackend *be, uint32_t id);
int iommufd_backend_set_option(int fd, uint32_t object_id,
                               uint32_t option_id,
                               uint64_t val64);
int iommufd_backend_map_dma(IOMMUFDBackend *be, uint32_t ioas_id, hwaddr iova,
                            ram_addr_t size, void *vaddr, bool readonly);
int iommufd_backend_unmap_dma(IOMMUFDBackend *be, uint32_t ioas_id,
                              hwaddr iova, ram_addr_t size);

int iommufd_device_get_hw_capabilities(IOMMUFDBackend *be, int dev_id,
                                       uint64_t *caps, Error **errp);
bool iommufd_dirty_pages_supported(IOMMUFDBackend *iommufd, int devid,
                                   Error **errp);
int iommufd_backend_alloc_hwpt(IOMMUFDBackend *be, uint32_t dev_id,
                               uint32_t pt_id, uint32_t flags,
                               uint32_t data_type, uint32_t data_len,
                               void *data_ptr, uint32_t *out_hwpt);
int iommufd_backend_set_dirty_tracking(IOMMUFDBackend *be, uint32_t hwpt_id,
                                       bool start);
int iommufd_backend_get_dirty_bitmap(IOMMUFDBackend *be, uint32_t hwpt_id,
                                     uint64_t iova, ram_addr_t size,
                                     uint64_t page_size, uint64_t *data);

#endif
