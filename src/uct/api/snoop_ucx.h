#ifndef SNOOP_UCX_H
#define SNOOP_UCX_H
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef uintptr_t ucx_ptr;
typedef uintptr_t unpacked_rkey;
typedef uint8_t boolean;

#define SNOOP_MD_COMPONENT_NAME_SIZE 16
#define SNOOP_TL_NAME_SIZE 16
#define SNOOP_TL_DEV_NAME_SIZE 16
#define SNOOP_CM_NAME_SIZE 16
#define SNOOP_UCT_FUNC_NAME 32

#define SNOOP_LOG_ZCOPY_ADDR(rkey, is_success, remote_ptr)                     \
  do {                                                                         \
    int maxsize, i;                                                            \
    maxsize = 0;                                                               \
    for (i = 0; i < iovcnt; i++) {                                             \
      maxsize += iov[i].count * iov[i].length;                                 \
    }                                                                          \
    snoop_uct_send_f_addr(ep, maxsize, rkey, is_success, remote_ptr);          \
  } while (0)

#define SNOOP_LOG_ZCOPY_AM(rkey, is_success, id)                               \
  do {                                                                         \
    int maxsize, i;                                                            \
    maxsize = 0;                                                               \
    for (i = 0; i < iovcnt; i++) {                                             \
      maxsize += iov[i].count * iov[i].length;                                 \
    }                                                                          \
    snoop_uct_send_f_am(ep, maxsize, rkey, is_success, id);                    \
  } while (0)

#define SNOOP_LOG_ZCOPY_NONE(rkey, is_success)                                 \
  do {                                                                         \
    int maxsize, i;                                                            \
    maxsize = 0;                                                               \
    for (i = 0; i < iovcnt; i++) {                                             \
      maxsize += iov[i].count * iov[i].length;                                 \
    }                                                                          \
    snoop_uct_send_f_none(ep, maxsize, rkey, is_success);                      \
  } while (0)

#define SNOOP_STATUS(type, varname, init)                                      \
  type varname = init;                                                         \
  varname

typedef struct snoop_uct_addr {
  size_t addr_size;
  char *addr;
} snoop_uct_addr_t;

typedef struct snoop_uct_ep_ep_addr {
  snoop_uct_addr_t ep_addr;
  snoop_uct_addr_t dev_addr;
} snoop_uct_ep_ep_addr_t;

typedef struct snoop_uct_ep_iface_addr {
  snoop_uct_addr_t iface_addr;
  snoop_uct_addr_t dev_addr;
} snoop_uct_ep_iface_addr_t;

typedef struct _snoop_uct_ep_socket_addr {
  struct sockaddr *addr; /**< Pointer to socket address */
  socklen_t addrlen;     /**< Address length */
} _snoop_uct_ep_socket_addr_t;

typedef enum snoop_uct_ep_addr_type {
  SNOOP_UCT_EP_ADDR_EP = 1,
  SNOOP_UCT_EP_ADDR_IFACE = 2,
  SNOOP_UCT_EP_ADDR_SOCKET = 3,
  SNOOP_UCT_EP_ADDR_LAST = 0,
} snoop_uct_ep_addr_type_t;

typedef struct snoop_uct_ep_addr {
  snoop_uct_ep_addr_type_t address_type;
  union {
    snoop_uct_ep_ep_addr_t ep_addr;
    snoop_uct_ep_iface_addr_t iface_addr;
    snoop_uct_addr_t socket_addr;
  } address;
} snoop_uct_ep_addr_t;

#define snoop_uct_addr_equals(a1, a2)                                          \
  ((a1).addr_size == (a2).addr_size) &&                                        \
      (memcmp((a1).addr, (a2).addr, (a1).addr_size) == 0)

#define snoop_uct_ep_addr_equals(a1, a2)                                       \
  ((a1).address_type == (a2).address_type) &&                                  \
      (((a1).address_type == SNOOP_UCT_EP_ADDR_LAST) ? 1                       \
       : (a1).address_type == SNOOP_UCT_EP_ADDR_EP                             \
           ? (snoop_uct_addr_equals((a1).address.ep_addr.ep_addr,              \
                                    (a2).address.ep_addr.ep_addr) &&           \
              snoop_uct_addr_equals((a1).address.ep_addr.dev_addr,             \
                                    (a2).address.ep_addr.dev_addr))            \
       : (a1).address_type == SNOOP_UCT_EP_ADDR_IFACE                          \
           ? (snoop_uct_addr_equals((a1).address.iface_addr.iface_addr,        \
                                    (a2).address.iface_addr.iface_addr) &&     \
              snoop_uct_addr_equals((a1).address.iface_addr.dev_addr,          \
                                    (a2).address.iface_addr.dev_addr))         \
           : (snoop_uct_addr_equals((a1).address.socket_addr,                  \
                                    (a2).address.socket_addr)))

#define snoop_uct_ep_any_addr_copy(a, b, key)                                  \
  (a)->key.addr_size = (b)->key.addr_size;                                     \
  (a)->key.addr = reinterpret_cast<char *>(calloc(1, (b)->key.addr_size));     \
  memcpy((a)->key.addr, (b)->key.addr, (a)->key.addr_size);

typedef struct snoop_uct_ep {
  char cm_name[SNOOP_CM_NAME_SIZE];

  ucx_ptr ep_ptr;
  ucx_ptr iface_ptr;

  snoop_uct_ep_addr_t address;

  /*
  0x0: no name?
  0x1: name in cm_name.
  0x2: name in iface (check iface ptr)
  */
  char flags;
} snoop_uct_ep_t;

typedef struct snoop_uct_connection {
  ucx_ptr ep_ptr;
  snoop_uct_ep_addr_t address;
  snoop_uct_ep_addr_t remote_address;

  struct timespec time;
} snoop_uct_connection_t;

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
  size_t md_rkey_size;
  snoop_uct_ep_addr_t addr;
} snoop_uct_iface_t;

typedef struct snoop_uct_rkey {
  char *rkey;
  size_t size;
  char component_name[16];
} snoop_uct_rkey_t;

/*
takes in a snoop_uct_comm_extra_am* (in) and Dl_info* (out), returns int
(success)
*/
#define SNOOP_UCT_COMM_EXTRA_AM_DLINFO(aminfo, dlinfo)                         \
  ((aminfo) && (dlinfo) && dladdr((aminfo)->am_fnc_ptr, (dlinfo)) ? 0 : -1)

typedef enum {
  SNOOP_UCT_COMM_EXTRA_NONE = 0,
  SNOOP_UCT_COMM_EXTRA_ADDR = 1,
  SNOOP_UCT_COMM_EXTRA_AMINFO = 2,
} snoop_uct_comm_extra_type;

typedef struct snoop_uct_comm_extra {
  snoop_uct_comm_extra_type type;
  union {
    ucx_ptr remote_addr;
    uint8_t am_id;
  } data;
} snoop_uct_comm_extra_t;

#define SNOOP_COMM_HAS_RKEY(c) ((c)->rkey.size > 0)
#define SNOOP_COMM_HAS_CONN(c) ((c)->ep.current_addr.addr_size > 0)
typedef struct snoop_uct_comm {
  snoop_uct_comm_extra_t extra;
  /*
  Keep in mind ep is not a pointer, so it will keep it's remote
  address even the remote address changes sometime in the future
  */
  snoop_uct_ep_t ep;
  snoop_uct_rkey_t rkey;
  char send_func_name[SNOOP_UCT_FUNC_NAME];
  struct timespec time;
  size_t comm_size;
  boolean is_success;
} snoop_uct_comm_t;

void snoop_uct_iface_open(void *iface, void *md, size_t md_rkey_size,
                          const char *md_name, const char *tl_name,
                          snoop_uct_ep_addr_t address);

void snoop_uct_iface_add_resource(void *iface, const char *dev_name, int type,
                                  int sysdev);
void snoop_uct_ep_create_iface(void *ep, void *iface,
                               snoop_uct_ep_addr_t address,
                               snoop_uct_ep_addr_t remote_address);
void snoop_uct_ep_create_cm(void *ep, const char *cm_name,
                            snoop_uct_ep_addr_t address,
                            snoop_uct_ep_addr_t remote_address);
void snoop_uct_ep_connect(void *ep, const char *sender_addr,
                          const char *remote_addr, size_t addr_len,
                          const char *sender_dev_addr,
                          const char *remote_dev_addr, size_t dev_addr_len);

#define snoop_uct_send_f_none(ep, size, rkey, is_success)                      \
  do {                                                                         \
    snoop_uct_comm_extra_t extra;                                              \
    extra.type = SNOOP_UCT_COMM_EXTRA_NONE;                                    \
    snoop_uct_send_proxy(ep, size, rkey, is_success, extra, __func__);         \
  } while (0);

#define snoop_uct_send_f_addr(ep, size, rkey, is_success, remote_addr)         \
  do {                                                                         \
    snoop_uct_comm_extra_t extra;                                              \
    extra.type = SNOOP_UCT_COMM_EXTRA_ADDR;                                    \
    extra.data.remote_addr = (ucx_ptr)remote_addr;                             \
    snoop_uct_send_proxy(ep, size, rkey, is_success, extra, __func__);         \
  } while (0);

#define snoop_uct_send_f_am(ep, size, rkey, is_success, id)                    \
  do {                                                                         \
    snoop_uct_comm_extra_t extra;                                              \
    extra.type = SNOOP_UCT_COMM_EXTRA_AMINFO;                                  \
    extra.data.am_id = id;                                                     \
    snoop_uct_send_proxy(ep, size, rkey, is_success, extra, __func__);         \
  } while (0);

void snoop_uct_send(void *ep, void *iface, size_t size, unpacked_rkey rkey,
                    boolean is_success, snoop_uct_comm_extra_t extra,
                    const char *func_name);
void snoop_uct_send_proxy(void *ep, size_t size, unpacked_rkey rkey,
                          boolean is_success, snoop_uct_comm_extra_t extra,
                          const char *func_name);

// TODO change to pointer for performance
void snoop_uct_pack_rkey(snoop_uct_rkey_t rkey);
void snoop_uct_unpack_rkey(snoop_uct_rkey_t rkey, unpacked_rkey unpacked);

void printCharHex(const char *str, size_t maxLength);

#define zerostruct(p) memset(&p, 0, sizeof(p))

#ifdef __cplusplus
}
#endif
#endif
