#ifndef SNOOP_UCX_H
#define SNOOP_UCX_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef uintptr_t ucx_ptr;

#define SNOOP_MD_COMPONENT_NAME_SIZE 16
#define SNOOP_TL_NAME_SIZE 16
#define SNOOP_TL_DEV_NAME_SIZE 16
#define SNOOP_CM_NAME_SIZE 16
#define SNOOP_UCT_FUNC_NAME 32

#define SNOOP_LOG_ZCOPY                                                        \
  int maxsize, i;                                                              \
  maxsize = 0;                                                                 \
  for (i = 0; i < iovcnt; i++) {                                               \
    maxsize += iov[i].count * iov[i].length;                                   \
  }                                                                            \
  snoop_uct_send_f(ep, maxsize);

typedef struct snoop_uct_ep_addr {
  size_t addr_size;
  char *addr;
} snoop_uct_ep_addr_t;

typedef struct snoop_uct_ep {
  char cm_name[SNOOP_CM_NAME_SIZE];
  snoop_uct_ep_addr_t current_addr;
  snoop_uct_ep_addr_t remote_addr;
  ucx_ptr ep_ptr;
  ucx_ptr iface_ptr;

  snoop_uct_ep_addr_t current_dev_addr;
  snoop_uct_ep_addr_t remote_dev_addr;
  /*
  0x0: no name?
  0x1: name in cm_name.
  0x2: name in iface (check iface ptr)
  */
  char flags;
} snoop_uct_ep_t;

typedef struct snoop_uct_iface_tl_resources {
  char device_name[SNOOP_TL_DEV_NAME_SIZE];
  unsigned int type;
  unsigned int sysdev;
} snoop_uct_iface_tl_resources_t;

typedef struct snoop_uct_iface {
  ucx_ptr iface_ptr;
  ucx_ptr md_ptr;
  char md_component_name[SNOOP_MD_COMPONENT_NAME_SIZE];
  char tl_name[SNOOP_TL_NAME_SIZE];
  snoop_uct_iface_tl_resources_t *tl_device_resources;
  unsigned int tl_device_resources_count;
} snoop_uct_iface_t;

typedef struct snoop_uct_comm {
  /*
  Keep in mind ep is not a pointer, so it will keep it's remote
  address even the remote address changes sometime in the future
  */
  snoop_uct_ep_t ep;
  char send_func_name[SNOOP_UCT_FUNC_NAME];
  struct timespec time;
  size_t comm_size;
} snoop_uct_comm_t;

void snoop_uct_iface_open(void *iface, void *md, const char *md_name,
                          const char *tl_name);
void snoop_uct_iface_add_resource(void *iface, const char *dev_name, int type,
                                  int sysdev);
void snoop_uct_ep_create_iface(void *ep, void *iface);
void snoop_uct_ep_create_cm(void *ep, const char *cm_name);
void snoop_uct_ep_connect(void *ep, const char *sender_addr,
                          const char *remote_addr, size_t addr_len,
                          const char *sender_dev_addr,
                          const char *remote_dev_addr, size_t dev_addr_len);

#define snoop_uct_send_f(ep, size) snoop_uct_send(ep, size, __func__)
void snoop_uct_send(void *ep, size_t size, const char *func_name);

#define zerostruct(p) memset(&p, 0, sizeof(p))

#ifdef __cplusplus
}
#endif
#endif
