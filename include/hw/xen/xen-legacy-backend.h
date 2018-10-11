#ifndef QEMU_HW_XEN_BACKEND_H
#define QEMU_HW_XEN_BACKEND_H

#include "hw/xen/xen_common.h"
#include "hw/xen/xen_pvdev.h"
#include "sysemu/sysemu.h"
#include "net/net.h"

#define TYPE_XENSYSDEV "xen-sysdev"
#define TYPE_XENSYSBUS "xen-sysbus"
#define TYPE_XENBACKEND "xen-backend"

#define XENBACKEND_DEVICE(obj) \
    OBJECT_CHECK(XenLegacyDevice, (obj), TYPE_XENBACKEND)

typedef void XenLegacyDeviceHandler(struct XenLegacyDevice *device);
typedef int XenEvtchnHandler(int port, XenLegacyDeviceHandler *cb,
                             struct XenLegacyDevice *dev);

/* variables */
extern struct xs_handle *xenstore;
extern const char *xen_protocol;
extern DeviceState *xen_sysdev;
extern BusState *xen_sysbus;
extern XenEvtchnHandler *xen_legacy_handler;

int xenstore_mkdir(char *path, int p);
int xenstore_mkdir_other(char *path, int be_id, int p);
int xenstore_write_be_str(struct XenLegacyDevice *xendev, const char *node,
                          const char *val);
int xenstore_write_be_int(struct XenLegacyDevice *xendev, const char *node,
                          int ival);
int xenstore_write_be_int64(struct XenLegacyDevice *xendev, const char *node,
                            int64_t ival);
char *xenstore_read_be_str(struct XenLegacyDevice *xendev, const char *node);
int xenstore_read_be_int(struct XenLegacyDevice *xendev, const char *node,
                         int *ival);
void xenstore_update_fe(char *watch, struct XenLegacyDevice *xendev);
void xenstore_update_be(char *watch, char *type, int dom,
                        struct XenDevOps *ops);
char *xenstore_read_fe_str(struct XenLegacyDevice *xendev, const char *node);
int xenstore_read_fe_int(struct XenLegacyDevice *xendev, const char *node,
                         int *ival);
int xenstore_read_fe_uint64(struct XenLegacyDevice *xendev, const char *node,
                            uint64_t *uval);

void xen_be_check_state(struct XenLegacyDevice *xendev);

/* xen backend driver bits */
int xen_be_xenstore_open(void);
void xen_be_xenstore_close(void);
void xen_be_sysdev_init(void);
int xen_be_init(void);
void xen_be_register_common(void);
int xen_be_register(const char *type, struct XenDevOps *ops);
int xen_be_set_state(struct XenLegacyDevice *xendev, enum xenbus_state state);
int xen_be_bind_evtchn(struct XenLegacyDevice *xendev);
void xen_be_set_max_grant_refs(struct XenLegacyDevice *xendev,
                               unsigned int nr_refs);
void *xen_be_map_grant_refs(struct XenLegacyDevice *xendev, uint32_t *refs,
                            unsigned int nr_refs, int prot);
void xen_be_unmap_grant_refs(struct XenLegacyDevice *xendev, void *ptr,
                             unsigned int nr_refs);

typedef struct XenGrantCopySegment {
    union {
        void *virt;
        struct {
            uint32_t ref;
            off_t offset;
        } foreign;
    } source, dest;
    size_t len;
} XenGrantCopySegment;

int xen_be_copy_grant_refs(struct XenLegacyDevice *xendev,
                           bool to_domain, XenGrantCopySegment segs[],
                           unsigned int nr_segs);

static inline void *xen_be_map_grant_ref(struct XenLegacyDevice *xendev,
                                         uint32_t ref, int prot)
{
    return xen_be_map_grant_refs(xendev, &ref, 1, prot);
}

static inline void xen_be_unmap_grant_ref(struct XenLegacyDevice *xendev,
                                          void *ptr)
{
    return xen_be_unmap_grant_refs(xendev, ptr, 1);
}

int xen_send_notify(struct XenLegacyDevice *xendev);

struct XenLegacyBackendOps {
    void (*set_max_grefs)(struct XenLegacyDevice *xendev, unsigned int nr_refs);
    void * (*map_grefs)(struct XenLegacyDevice *xendev, uint32_t *refs,
                        unsigned int nr_refs, int prot);
    void (*unmap_grefs)(struct XenLegacyDevice *xendev, void *ptr,
                        unsigned int nr_refs);
    int (*copy_grefs)(struct XenLegacyDevice *xendev, bool to_domain,
                      XenGrantCopySegment segs[], unsigned int nr_segs);
    int (*send_notify)(struct XenLegacyDevice *xendev);
};

extern struct XenLegacyBackendOps xen_legacy_gnt_ops;

/* actual backend drivers */
extern struct XenDevOps xen_console_ops;      /* xen_console.c     */
extern struct XenDevOps xen_kbdmouse_ops;     /* xen_framebuffer.c */
extern struct XenDevOps xen_framebuffer_ops;  /* xen_framebuffer.c */
extern struct XenDevOps xen_blkdev_ops;       /* xen_disk.c        */
#ifdef CONFIG_VIRTFS
extern struct XenDevOps xen_9pfs_ops;       /* xen-9p-backend.c        */
#endif
extern struct XenDevOps xen_netdev_ops;       /* xen_nic.c         */
#ifdef CONFIG_USB_LIBUSB
extern struct XenDevOps xen_usb_ops;          /* xen-usb.c         */
#endif

typedef struct XenBackendType {
    char                *type;
    uint16_t            domid;
} XenBackendType;

#define DEFINE_XEN_PROPERTIES(_state, _conf)                  \
    DEFINE_PROP_STRING("backendtype", _state, _conf.type),    \
    DEFINE_PROP_UINT16("backend", _state, _conf.domid, 0)

/* configuration (aka xenbus setup) */
void xen_config_cleanup(void);
int xen_config_dev_blk(DriveInfo *disk);
int xen_config_dev_blk_by_conf(DriveInfo *disk, XenBackendType *be);
int xen_config_dev_nic(NICInfo *nic);
int xen_config_dev_nic_by_conf(NetClientState *netdev, MACAddr macaddr,
                               XenBackendType *be);
int xen_config_dev_vfb(int vdev, const char *type);
int xen_config_dev_vkbd(int vdev);
int xen_config_dev_console(int vdev);

#endif /* QEMU_HW_XEN_BACKEND_H */
