/*
 * ax211_vfio.c — Level 07: Intel AX211 CNVi WiFi direct VFIO firmware loader
 *
 * Bypasses the entire Linux networking stack: no iwlwifi, no mac80211,
 * no cfg80211, no socket layer.  Drives the AX211 PCIe device (00:14.3,
 * 8086:51F0) directly from userspace via VFIO + IOMMU.
 *
 * What this does:
 *   1. Rebinds 0000:00:14.3 from iwlwifi → vfio-pci (via sysfs)
 *   2. Opens /dev/vfio/vfio + /dev/vfio/11, mmaps BAR0 (16 KB)
 *   3. Parses /lib/firmware/iwlwifi-cc-a0-77.ucode TLV sections
 *   4. Allocates DMA-mapped memory via VFIO IOMMU for:
 *        LMAC/UMAC/paging firmware sections, prph_scratch,
 *        prph_info, ctxt_info_gen3, RX free/used BD rings, TX MTR ring
 *   5. Performs gen2 APM init (L0s disable, HAP INTA, clock ready)
 *   6. Fills iwl_context_info_gen3 + iwl_prph_scratch (AX210 gen3 protocol)
 *   7. Kicks firmware: CSR_CTXT_INFO_ADDR → context info DMA addr,
 *      CSR_CTXT_INFO_BOOT_CTRL[AUTO_FUNC_BOOT_ENA], UREG_CPU_INIT_RUN=1
 *   8. Polls CSR_INT for ALIVE interrupt (bit 0)
 *   9. Rebinds to iwlwifi on exit
 *
 * Build:  gcc -O2 -Wall -o ax211_vfio ax211_vfio.c
 * Run:    sudo ./ax211_vfio
 *
 * Reference: drivers/net/wireless/intel/iwlwifi/ in linux-6.12
 *   pcie/trans-gen2.c   — start_fw, gen2_nic_init, gen2_apm_init
 *   pcie/ctxt-info-gen3.c — iwl_pcie_ctxt_info_gen3_init
 *   pcie/ctxt-info.c    — iwl_pcie_init_fw_sec, get_num_sections
 *   iwl-context-info-gen3.h — struct definitions
 *   cfg/ax210.c         — device config: integrated, umac_prph_offset=0x300000
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/vfio.h>

/* ── PCI device ────────────────────────────────────────────────────────── */
#define PCI_ADDR        "0000:00:14.3"
#define IOMMU_GROUP     "11"
#define FW_PATH         "/lib/firmware/iwlwifi-so-a0-gf-a0-89.ucode"
#define PNVM_PATH       "/lib/firmware/iwlwifi-so-a0-gf-a0.pnvm"

/* ── CSR register offsets (relative to BAR0) ──────────────────────────── */
#define CSR_HW_IF_CONFIG_REG    0x000
#define CSR_INT                 0x008
#define CSR_INT_MASK            0x00c
#define CSR_RESET               0x020
#define CSR_GP_CNTRL            0x024
#define CSR_HW_REV              0x028
#define CSR_GIO_REG             0x03c
#define CSR_GIO_CHICKEN_BITS    0x100
#define CSR_DBG_HPET_MEM_REG   0x240
#define CSR_LTR_LAST_MSG        0x0DC   /* polled during IML spin */
#define CSR_CTXT_INFO_BOOT_CTRL 0x000   /* same offset as HW_IF_CONFIG? no: */
/* Corrected: CSR_CTXT_INFO_BOOT_CTRL = 0x0, CSR_HW_IF_CONFIG_REG = 0x000 */
/* They ARE the same register offset -- BOOT_CTRL bits live in HW_IF_CONFIG */
#define CSR_CTXT_INFO_ADDR      0x118
#define CSR_IML_DATA_ADDR       0x120
#define CSR_IML_SIZE_ADDR       0x128
/* MSI-X HW interrupt causes: readable even in legacy INTx mode */
#define CSR_MSIX_HW_INT_CAUSES_AD   0x2808
#define MSIX_HW_INT_CAUSES_REG_IML  (1u << 1)

/* CSR bit masks */
#define CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX  (1u << 23)
#define CSR_DBG_HPET_MEM_REG_VAL                     0xFFFF0000u
#define CSR_HW_IF_CONFIG_REG_BIT_HAP_WAKE_L1A        (1u << 19)
#define CSR_GIO_REG_VAL_L0S_DISABLED                 (1u << 1)
#define CSR_RESET_REG_FLAG_SW_RESET                  (1u << 7)
#define CSR_GP_CNTRL_REG_FLAG_INIT_DONE              (1u << 2)
#define CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ         (1u << 3)
#define CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP         (1u << 4)
#define CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY        (1u << 0)
#define CSR_INT_BIT_ALIVE                            (1u << 0)
#define CSR_INT_BIT_HW_ERR                           (1u << 29)
/* CSR_CTXT_INFO_BOOT_CTRL shares offset 0 with CSR_HW_IF_CONFIG_REG */
#define CSR_AUTO_FUNC_BOOT_ENA                       (1u << 1)

/* ── HBUS (indirect peripheral register access) ───────────────────────── */
#define HBUS_BASE               0x400
#define HBUS_TARG_PRPH_WADDR   (HBUS_BASE + 0x044)
#define HBUS_TARG_PRPH_RADDR   (HBUS_BASE + 0x048)
#define HBUS_TARG_PRPH_WDAT    (HBUS_BASE + 0x04c)
#define HBUS_TARG_PRPH_RDAT    (HBUS_BASE + 0x050)

/* ── PRPH registers (accessed via HBUS indirect) ──────────────────────── */
/* For AX210: iwl_write_umac_prph adds umac_prph_offset=0x300000 */
#define UMAC_PRPH_OFFSET        0x300000u
#define UREG_CPU_INIT_RUN       0xa05c44u

/* Effective PRPH address = UREG_CPU_INIT_RUN + UMAC_PRPH_OFFSET */
#define PRPH_UREG_CPU_INIT_RUN  (UREG_CPU_INIT_RUN + UMAC_PRPH_OFFSET)

/* ── TLV types in .ucode files ────────────────────────────────────────── */
#define IWL_TLV_UCODE_MAGIC     0x0a4c5749u
#define IWL_UCODE_TLV_SEC_RT    19
#define IWL_UCODE_TLV_IML       52

/* Separator offset values in SEC_RT sections */
#define CPU1_CPU2_SEPARATOR_SECTION  0xFFFFCCCCu
#define PAGING_SEPARATOR_SECTION     0xAAAABBBBu

/* ── AX210 device parameters ──────────────────────────────────────────── */
#define NUM_RBDS        4096    /* IWL_NUM_RBDS_AX210_HE */
#define CMD_QUEUE_SIZE  128     /* min_txq_size; max(IWL_CMD_QUEUE_SIZE=32, 128) */
/* TFD_QUEUE_CB_SIZE(128) = ilog2(128)-3 = 4  (used in mtr_size field) */
#define MTR_SIZE_CB     4
/* RX_QUEUE_CB_SIZE(4096) = ilog2(4096) = 12  (used in mcr_size field) */
#define MCR_SIZE_CB     12

/* Ring element sizes for AX210 */
#define FREE_BD_SIZE    16      /* sizeof(struct iwl_rx_transfer_desc) */
#define USED_BD_SIZE    32      /* sizeof(struct iwl_rx_completion_desc) */
#define TFD_SIZE        256     /* sizeof(struct iwl_tfh_tfd) — 256-bit format */

/* prph_scratch control flags */
#define PRPH_SCRATCH_RB_SIZE_4K     (1u << 16)
#define PRPH_SCRATCH_MTR_MODE       (1u << 17)
#define PRPH_MTR_FORMAT_256B        0x000C0000u  /* BIT(18)|BIT(19) */
#define PRPH_SCRATCH_MTR_FORMAT     0x000C0000u
/* control_flags = RB_SIZE_4K | MTR_MODE | (FORMAT_256B & FORMAT_MASK) */
#define PRPH_SCRATCH_CTRL_FLAGS \
    (PRPH_SCRATCH_RB_SIZE_4K | PRPH_SCRATCH_MTR_MODE | \
     (PRPH_MTR_FORMAT_256B & PRPH_SCRATCH_MTR_FORMAT))

/* Maximum firmware sections per region (generously sized) */
#define MAX_FW_SECTIONS 64

/* ── DMA layout ───────────────────────────────────────────────────────── */
/*
 * One contiguous mmap'd anonymous region registered with VFIO IOMMU.
 * IOVA base = 0x100000000 (4 GiB) — safely above 32-bit boundary,
 * and no single allocation crosses a 4 GiB alignment boundary.
 */
#define DMA_IOVA_BASE   0x100000000ULL
#define DMA_TOTAL_SIZE  (8 * 1024 * 1024)   /* 8 MB */

/* Sub-offsets within the DMA region */
#define DMA_OFF_PRPH_SCRATCH    0x000000     /* 4 KB */
#define DMA_OFF_PRPH_INFO       0x001000     /* 4 KB (tail-pointer trick uses 2nd half) */
#define DMA_OFF_CTXT_INFO       0x002000     /* 4 KB */
#define DMA_OFF_FREE_BD         0x003000     /* 4096 * 16 = 64 KB */
#define DMA_OFF_USED_BD         0x013000     /* 4096 * 32 = 128 KB */
#define DMA_OFF_RB_STTS         0x033000     /* 4 KB  (holds __le16 status) */
#define DMA_OFF_MTR             0x034000     /* 128 * 256 = 32 KB */
#define DMA_OFF_RX_BUFS         0x03C000     /* 4096 RX buffers * 2 KB = 8 MB total */
/* Each RX buffer: 2 KB = 2048 bytes.  We pre-fill 512 to avoid running off pool. */
#define RX_BUF_SIZE             2048
#define RX_BUF_PREFILL          512          /* pre-populate 512 free BDs */
#define DMA_OFF_IML             0x43C000     /* IML (image loader) section: up to 16 KB */
#define DMA_IML_MAX_SIZE        (16 * 1024)
#define DMA_OFF_FW_SECTIONS     0x440000     /* fw LMAC/UMAC/paging sections */

/* ── struct definitions (mirror kernel headers, using standard int types) */

/* prph_scratch version sub-struct (8 bytes) */
struct prph_version {
    uint16_t mac_id;        /* hw_rev from CSR_HW_REV */
    uint16_t version;       /* = 0 */
    uint16_t size;          /* sizeof(prph_scratch) / 4 */
    uint16_t reserved;
} __attribute__((packed));

/* prph_scratch control sub-struct (8 bytes) */
struct prph_control {
    uint32_t control_flags;
    uint32_t reserved;
} __attribute__((packed));

/* prph_scratch pnvm_cfg (16 bytes) */
struct prph_pnvm_cfg {
    uint64_t pnvm_base_addr;
    uint32_t pnvm_size;
    uint32_t reserved;
} __attribute__((packed));

/* prph_scratch hwm_cfg (16 bytes) */
struct prph_hwm_cfg {
    uint64_t hwm_base_addr;
    uint32_t hwm_size;
    uint32_t debug_token_config;
} __attribute__((packed));

/* prph_scratch rbd_cfg (12 bytes) */
struct prph_rbd_cfg {
    uint64_t free_rbd_addr;
    uint32_t reserved;
} __attribute__((packed));

/* prph_scratch uefi_cfg (16 bytes) */
struct prph_uefi_cfg {
    uint64_t base_addr;
    uint32_t size;
    uint32_t reserved;
} __attribute__((packed));

/* prph_scratch step_cfg (8 bytes) */
struct prph_step_cfg {
    uint32_t mbx_addr_0;
    uint32_t mbx_addr_1;
} __attribute__((packed));

/* prph_scratch_ctrl_cfg */
struct prph_scratch_ctrl_cfg {
    struct prph_version     version;        /*   8 */
    struct prph_control     control;        /*   8 */
    struct prph_pnvm_cfg    pnvm_cfg;       /*  16 */
    struct prph_hwm_cfg     hwm_cfg;        /*  16 */
    struct prph_rbd_cfg     rbd_cfg;        /*  12 */
    struct prph_uefi_cfg    reduce_power_cfg; /* 16 */
    struct prph_step_cfg    step_cfg;       /*   8 */
} __attribute__((packed));
/* Total ctrl_cfg = 84 bytes */

/* iwl_context_info_dram (embedded in prph_scratch) */
#define IWL_MAX_DRAM_ENTRY 64
struct context_info_dram {
    uint64_t umac_img[IWL_MAX_DRAM_ENTRY];      /* 512 bytes */
    uint64_t lmac_img[IWL_MAX_DRAM_ENTRY];      /* 512 bytes */
    uint64_t virtual_img[IWL_MAX_DRAM_ENTRY];   /* 512 bytes */
} __attribute__((packed));
/* Total = 1536 bytes */

/* prph_scratch (full) */
struct prph_scratch {
    struct prph_scratch_ctrl_cfg ctrl_cfg;  /*  84 bytes */
    uint32_t fseq_override;                 /*   4 */
    uint32_t step_analog_params;            /*   4 */
    uint32_t reserved[8];                   /*  32 */
    struct context_info_dram dram;          /* 1536 */
} __attribute__((packed));
/* Total = 1660 bytes */

/* prph_info (16 bytes, but kernel allocates PAGE_SIZE) */
struct prph_info {
    uint32_t boot_stage_mirror;
    uint32_t ipc_status_mirror;
    uint32_t sleep_notif;
    uint32_t reserved;
} __attribute__((packed));

/* iwl_context_info_gen3 (108 bytes) */
struct context_info_gen3 {
    uint16_t version;
    uint16_t size;
    uint32_t config;
    uint64_t prph_info_base_addr;
    uint64_t cr_head_idx_arr_base_addr;
    uint64_t tr_tail_idx_arr_base_addr;
    uint64_t cr_tail_idx_arr_base_addr;
    uint64_t tr_head_idx_arr_base_addr;
    uint16_t cr_idx_arr_size;
    uint16_t tr_idx_arr_size;
    uint64_t mtr_base_addr;
    uint64_t mcr_base_addr;
    uint16_t mtr_size;
    uint16_t mcr_size;
    uint16_t mtr_doorbell_vec;
    uint16_t mcr_doorbell_vec;
    uint16_t mtr_msi_vec;
    uint16_t mcr_msi_vec;
    uint8_t  mtr_opt_header_size;
    uint8_t  mtr_opt_footer_size;
    uint8_t  mcr_opt_header_size;
    uint8_t  mcr_opt_footer_size;
    uint16_t msg_rings_ctrl_flags;
    uint16_t prph_info_msi_vec;
    uint64_t prph_scratch_base_addr;
    uint32_t prph_scratch_size;
    uint32_t reserved;
} __attribute__((packed));

/* ── Global state ─────────────────────────────────────────────────────── */
static int   container_fd = -1;
static int   group_fd     = -1;
static int   device_fd    = -1;
static void *bar0         = NULL;
static size_t bar0_size   = 0;

/* DMA pool */
static void    *dma_vaddr = NULL;
static uint64_t dma_iova  = DMA_IOVA_BASE;

/* Firmware section arrays */
typedef struct { const uint8_t *data; uint32_t len; uint32_t offset; } fw_sec_t;
static fw_sec_t lmac_secs[MAX_FW_SECTIONS];
static fw_sec_t umac_secs[MAX_FW_SECTIONS];
static fw_sec_t paging_secs[MAX_FW_SECTIONS];
static int lmac_cnt, umac_cnt, paging_cnt;

static uint8_t *fw_data = NULL;  /* entire .ucode file, kept in memory */
static const uint8_t *fw_iml = NULL;
static uint32_t fw_iml_size  = 0;

/* ── Utility ──────────────────────────────────────────────────────────── */
static void die(const char *msg)
{
    perror(msg);
    exit(1);
}

static void sysfs_write(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "sysfs_write open(%s): %s\n", path, strerror(errno));
        return;
    }
    ssize_t n = write(fd, value, strlen(value));
    if (n < 0)
        fprintf(stderr, "sysfs_write write(%s, %s): %s\n",
                path, value, strerror(errno));
    close(fd);
}

static uint32_t csr_read32(uint32_t offset)
{
    volatile uint32_t *p = (volatile uint32_t *)((uint8_t *)bar0 + offset);
    return *p;
}

static void csr_write32(uint32_t offset, uint32_t val)
{
    volatile uint32_t *p = (volatile uint32_t *)((uint8_t *)bar0 + offset);
    *p = val;
    __sync_synchronize();
}

static void csr_write64(uint32_t offset, uint64_t val)
{
    csr_write32(offset,     (uint32_t)(val & 0xFFFFFFFFULL));
    csr_write32(offset + 4, (uint32_t)(val >> 32));
}

static void csr_set_bits(uint32_t offset, uint32_t mask)
{
    csr_write32(offset, csr_read32(offset) | mask);
}

/* PRPH indirect write via HBUS.
 * For AX210 family the PRPH address space is 24-bit wide (0x00FFFFFF mask).
 * Older devices use 20-bit (0x000FFFFF), but AX211 needs 24-bit.
 * The upper byte of the WADDR register carries the byte-enable: 3 << 24. */
static void prph_write32(uint32_t addr, uint32_t val)
{
    csr_write32(HBUS_TARG_PRPH_WADDR, (addr & 0x00FFFFFFu) | (3u << 24));
    __sync_synchronize();
    csr_write32(HBUS_TARG_PRPH_WDAT, val);
    __sync_synchronize();
}

static void msleep(int ms)
{
    struct timespec ts = { .tv_sec = ms / 1000,
                           .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* ── VFIO setup ───────────────────────────────────────────────────────── */
static void vfio_bind_device(void)
{
    printf("[*] rebinding " PCI_ADDR " from iwlwifi → vfio-pci\n");

    /* Load vfio-pci module */
    system("modprobe vfio-pci 2>/dev/null");
    msleep(200);

    /* Set driver override so kernel won't auto-bind iwlwifi after unbind */
    sysfs_write("/sys/bus/pci/devices/" PCI_ADDR "/driver_override", "vfio-pci");

    /* Unbind from iwlwifi (tolerate failure if not bound) */
    sysfs_write("/sys/bus/pci/drivers/iwlwifi/unbind", PCI_ADDR);
    msleep(500);

    /* Bind to vfio-pci */
    sysfs_write("/sys/bus/pci/drivers/vfio-pci/bind", PCI_ADDR);
    msleep(300);

    printf("[*] vfio-pci bind complete\n");
}

static void vfio_unbind_device(void)
{
    printf("[*] rebinding " PCI_ADDR " back to iwlwifi\n");
    sysfs_write("/sys/bus/pci/drivers/vfio-pci/unbind", PCI_ADDR);
    /* Clear driver override so iwlwifi can take it back */
    sysfs_write("/sys/bus/pci/devices/" PCI_ADDR "/driver_override", "\n");
    msleep(200);
    /* Re-probe */
    sysfs_write("/sys/bus/pci/drivers_probe", PCI_ADDR);
    msleep(500);
}

static void vfio_open(void)
{
    /* Open VFIO container */
    container_fd = open("/dev/vfio/vfio", O_RDWR);
    if (container_fd < 0) die("open /dev/vfio/vfio");

    int api = ioctl(container_fd, VFIO_GET_API_VERSION);
    if (api != VFIO_API_VERSION) {
        fprintf(stderr, "unexpected VFIO API %d\n", api);
        exit(1);
    }
    if (!ioctl(container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1v2_IOMMU)) {
        fprintf(stderr, "TYPE1v2_IOMMU not supported\n");
        exit(1);
    }

    /* Open IOMMU group */
    group_fd = open("/dev/vfio/" IOMMU_GROUP, O_RDWR);
    if (group_fd < 0) die("open /dev/vfio/" IOMMU_GROUP);

    struct vfio_group_status gs = { .argsz = sizeof(gs) };
    if (ioctl(group_fd, VFIO_GROUP_GET_STATUS, &gs))
        die("VFIO_GROUP_GET_STATUS");
    if (!(gs.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        fprintf(stderr, "IOMMU group not viable — all devices must be VFIO-bound\n");
        exit(1);
    }

    /* Assign group to container, set IOMMU type */
    if (ioctl(group_fd, VFIO_GROUP_SET_CONTAINER, &container_fd))
        die("VFIO_GROUP_SET_CONTAINER");
    if (ioctl(container_fd, VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU))
        die("VFIO_SET_IOMMU");

    /* Get device fd */
    device_fd = ioctl(group_fd, VFIO_GROUP_GET_DEVICE_FD, PCI_ADDR);
    if (device_fd < 0) die("VFIO_GROUP_GET_DEVICE_FD");

    printf("[*] VFIO container/group/device opened\n");
}

static void vfio_enable_bus_master(void)
{
    /* Enable PCI bus mastering via config space command register (offset 4).
     * Required for the device to DMA into host memory.
     * Without this, CSR_RESET[8] (MASTER_DISABLED) stays set and the
     * firmware cannot write notifications or fetch firmware sections. */
    struct vfio_region_info ri = {
        .argsz = sizeof(ri),
        .index = VFIO_PCI_CONFIG_REGION_INDEX,
    };
    if (ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, &ri))
        die("VFIO_DEVICE_GET_REGION_INFO config");

    uint16_t cmd = 0;
    if (pread(device_fd, &cmd, 2, ri.offset + 4) != 2)
        die("pread PCI command register");
    printf("[*] PCI command register = 0x%04x\n", cmd);

    /* Set bit 2 (bus master), bit 1 (memory space), bit 0 (I/O space) */
    cmd |= (1u << 2) | (1u << 1);
    if (pwrite(device_fd, &cmd, 2, ri.offset + 4) != 2)
        die("pwrite PCI command register");
    printf("[*] PCI bus master enabled (cmd=0x%04x)\n", cmd);
}

static void vfio_map_bar0(void)
{
    struct vfio_device_info di = { .argsz = sizeof(di) };
    if (ioctl(device_fd, VFIO_DEVICE_GET_INFO, &di))
        die("VFIO_DEVICE_GET_INFO");
    printf("[*] device: %u regions, %u IRQs\n", di.num_regions, di.num_irqs);

    /* BAR0 = region index 0 */
    struct vfio_region_info ri = { .argsz = sizeof(ri), .index = 0 };
    if (ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, &ri))
        die("VFIO_DEVICE_GET_REGION_INFO for BAR0");

    printf("[*] BAR0: offset=0x%llx size=0x%llx flags=0x%x\n",
           (unsigned long long)ri.offset,
           (unsigned long long)ri.size,
           ri.flags);

    if (!(ri.flags & VFIO_REGION_INFO_FLAG_MMAP)) {
        fprintf(stderr, "BAR0 not mmapable\n");
        exit(1);
    }

    bar0_size = ri.size;
    bar0 = mmap(NULL, bar0_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                device_fd, ri.offset);
    if (bar0 == MAP_FAILED) die("mmap BAR0");

    printf("[*] BAR0 mapped at %p (size %zu)\n", bar0, bar0_size);
}

static void vfio_alloc_dma(void)
{
    /* Allocate anonymous memory for DMA */
    dma_vaddr = mmap(NULL, DMA_TOTAL_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED,
                     -1, 0);
    if (dma_vaddr == MAP_FAILED) die("mmap DMA");
    memset(dma_vaddr, 0, DMA_TOTAL_SIZE);

    /* Register with VFIO IOMMU */
    struct vfio_iommu_type1_dma_map dm = {
        .argsz = sizeof(dm),
        .flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
        .vaddr = (uint64_t)(uintptr_t)dma_vaddr,
        .iova  = dma_iova,
        .size  = DMA_TOTAL_SIZE,
    };
    if (ioctl(container_fd, VFIO_IOMMU_MAP_DMA, &dm))
        die("VFIO_IOMMU_MAP_DMA");

    printf("[*] DMA pool: vaddr=%p iova=0x%llx size=%d MB\n",
           dma_vaddr,
           (unsigned long long)dma_iova,
           DMA_TOTAL_SIZE >> 20);
}

/* Convert a DMA pool offset to an IOVA (device-visible physical address) */
static uint64_t iova_of(uint32_t pool_offset)
{
    return dma_iova + pool_offset;
}

/* Convert a DMA pool offset to a host virtual address */
static void *vaddr_of(uint32_t pool_offset)
{
    return (uint8_t *)dma_vaddr + pool_offset;
}

/* ── Firmware TLV parser ──────────────────────────────────────────────── */
static void parse_firmware(void)
{
    int fd = open(FW_PATH, O_RDONLY);
    if (fd < 0) die("open " FW_PATH);

    struct stat st;
    fstat(fd, &st);
    fw_data = malloc(st.st_size);
    if (!fw_data) die("malloc fw_data");
    if (read(fd, fw_data, st.st_size) != st.st_size) die("read firmware");
    close(fd);
    printf("[*] firmware: %s (%lld bytes)\n", FW_PATH, (long long)st.st_size);

    /*
     * TLV ucode header (80 bytes):
     *   u32 zero; u32 magic; u8 human_readable[64]; u32 ver; u32 build;
     * TLVs start immediately after (no 8-byte ignore field parsed here —
     * confirmed by empirical parsing of 50 SEC_RT sections).
     */
    size_t pos = 80;
    size_t total = st.st_size;

    /* Collect all SEC_RT sections in order */
    fw_sec_t all_secs[MAX_FW_SECTIONS * 4];
    int all_cnt = 0;

    while (pos + 8 <= total) {
        uint32_t tlv_type, tlv_len;
        memcpy(&tlv_type, fw_data + pos,     4);
        memcpy(&tlv_len,  fw_data + pos + 4, 4);
        uint32_t aligned_len = (tlv_len + 3) & ~3u;

        if (tlv_type == IWL_UCODE_TLV_SEC_RT && tlv_len >= 4) {
            uint32_t sec_offset;
            memcpy(&sec_offset, fw_data + pos + 8, 4);

            if (all_cnt < (int)(sizeof(all_secs)/sizeof(all_secs[0]))) {
                all_secs[all_cnt].offset = sec_offset;
                all_secs[all_cnt].data   = fw_data + pos + 8 + 4;
                all_secs[all_cnt].len    = tlv_len - 4;
                all_cnt++;
            }
        }

        if (tlv_type == IWL_UCODE_TLV_IML && tlv_len > 0) {
            fw_iml      = fw_data + pos + 8;
            fw_iml_size = tlv_len;
        }

        pos += 8 + aligned_len;
    }

    printf("[*] found %d SEC_RT sections total\n", all_cnt);

    /* Distribute into LMAC / UMAC / paging using separator detection:
     *   LMAC: all_secs[0 .. lmac_cnt-1]
     *   sep1: all_secs[lmac_cnt]              (offset == 0xFFFFCCCC)
     *   UMAC: all_secs[lmac_cnt+1 .. lmac_cnt+umac_cnt]
     *   sep2: all_secs[lmac_cnt+umac_cnt+1]   (offset == 0xAAAABBBB)
     *   paging: rest
     */
    int i;
    for (i = 0; i < all_cnt; i++) {
        if (all_secs[i].offset == CPU1_CPU2_SEPARATOR_SECTION ||
            all_secs[i].offset == PAGING_SEPARATOR_SECTION)
            break;
        lmac_secs[lmac_cnt++] = all_secs[i];
    }
    /* skip separator */
    i++;
    for (; i < all_cnt; i++) {
        if (all_secs[i].offset == CPU1_CPU2_SEPARATOR_SECTION ||
            all_secs[i].offset == PAGING_SEPARATOR_SECTION)
            break;
        umac_secs[umac_cnt++] = all_secs[i];
    }
    /* skip separator */
    i++;
    for (; i < all_cnt; i++) {
        if (all_secs[i].offset == CPU1_CPU2_SEPARATOR_SECTION ||
            all_secs[i].offset == PAGING_SEPARATOR_SECTION)
            break;
        paging_secs[paging_cnt++] = all_secs[i];
    }

    printf("[*] LMAC sections: %d\n", lmac_cnt);
    printf("[*] UMAC sections: %d\n", umac_cnt);
    printf("[*] paging sections: %d\n", paging_cnt);
    printf("[*] IML: %s (size=%u)\n",
           fw_iml ? "present" : "ABSENT", fw_iml_size);
}

/* ── DMA firmware section allocation ─────────────────────────────────── */
/*
 * Copy firmware sections into the DMA pool, starting at DMA_OFF_FW_SECTIONS.
 * Return array of IOVAs for each section.
 * Fills ctxt_dram->lmac_img[], umac_img[], virtual_img[].
 */
static void load_fw_sections(struct context_info_dram *ctxt_dram)
{
    uint32_t fw_off = DMA_OFF_FW_SECTIONS;
    int i;

    printf("[*] loading LMAC sections\n");
    for (i = 0; i < lmac_cnt; i++) {
        void *dst = vaddr_of(fw_off);
        uint32_t sz = (lmac_secs[i].len + 4095) & ~4095u;
        if (fw_off + sz > DMA_TOTAL_SIZE) {
            fprintf(stderr, "DMA pool overflow at LMAC section %d\n", i);
            exit(1);
        }
        memcpy(dst, lmac_secs[i].data, lmac_secs[i].len);
        ctxt_dram->lmac_img[i] = __builtin_bswap64(iova_of(fw_off));
        /* little-endian: no bswap needed on x86 */
        ctxt_dram->lmac_img[i] = iova_of(fw_off);
        printf("    lmac[%d] @ iova=0x%llx len=%u offset=0x%08x\n",
               i, (unsigned long long)iova_of(fw_off),
               lmac_secs[i].len, lmac_secs[i].offset);
        fw_off += sz;
    }

    printf("[*] loading UMAC sections\n");
    for (i = 0; i < umac_cnt; i++) {
        void *dst = vaddr_of(fw_off);
        uint32_t sz = (umac_secs[i].len + 4095) & ~4095u;
        if (fw_off + sz > DMA_TOTAL_SIZE) {
            fprintf(stderr, "DMA pool overflow at UMAC section %d\n", i);
            exit(1);
        }
        memcpy(dst, umac_secs[i].data, umac_secs[i].len);
        ctxt_dram->umac_img[i] = iova_of(fw_off);
        printf("    umac[%d] @ iova=0x%llx len=%u offset=0x%08x\n",
               i, (unsigned long long)iova_of(fw_off),
               umac_secs[i].len, umac_secs[i].offset);
        fw_off += sz;
    }

    printf("[*] loading paging sections\n");
    for (i = 0; i < paging_cnt; i++) {
        void *dst = vaddr_of(fw_off);
        uint32_t sz = (paging_secs[i].len + 4095) & ~4095u;
        if (fw_off + sz > DMA_TOTAL_SIZE) {
            fprintf(stderr, "DMA pool overflow at paging section %d\n", i);
            exit(1);
        }
        memcpy(dst, paging_secs[i].data, paging_secs[i].len);
        ctxt_dram->virtual_img[i] = iova_of(fw_off);
        fw_off += sz;
    }
    printf("[*] firmware sections loaded (pool used: %u KB)\n",
           (fw_off - DMA_OFF_FW_SECTIONS) >> 10);
}

/* ── APM hardware init ────────────────────────────────────────────────── */
static void apm_init(void)
{
    printf("[*] APM init\n");

    /* Disable L0s (hardware errata: L0s unstable) */
    csr_set_bits(CSR_GIO_CHICKEN_BITS,
                 CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX);

    /* Set FH wait threshold (HW stress workaround) */
    csr_set_bits(CSR_DBG_HPET_MEM_REG, CSR_DBG_HPET_MEM_REG_VAL);

    /* Enable HAP INTA — allows PCIe L1a→L0s wakeup */
    csr_set_bits(CSR_HW_IF_CONFIG_REG,
                 CSR_HW_IF_CONFIG_REG_BIT_HAP_WAKE_L1A);

    /* Disable L0S on GIO */
    csr_set_bits(CSR_GIO_REG, CSR_GIO_REG_VAL_L0S_DISABLED);

    /*
     * Set INIT_DONE → moves device from D0U* to D0A* (powered-up active).
     * For AX210 family (not BZ+), use FLAG_INIT_DONE, poll MAC_CLOCK_READY.
     */
    csr_set_bits(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_INIT_DONE);

    /* Poll for MAC clock stable (up to 25 ms) */
    int ready = 0;
    for (int i = 0; i < 250; i++) {
        if (csr_read32(CSR_GP_CNTRL) & CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY) {
            ready = 1;
            break;
        }
        usleep(100);
    }
    if (!ready)
        fprintf(stderr, "[!] WARNING: MAC clock not ready (GP_CNTRL=0x%08x)\n",
                csr_read32(CSR_GP_CNTRL));
    else
        printf("[*] MAC clock ready (GP_CNTRL=0x%08x)\n",
               csr_read32(CSR_GP_CNTRL));

    /* Enable shadow registers: lets certain CSR registers be readable
     * without requiring MAC access each time.  Required by firmware. */
    csr_set_bits(0x0A8 /*CSR_MAC_SHADOW_REG_CTRL*/, 0x800FFFFFu);
    printf("[*] shadow registers enabled\n");

    /* Set interrupt coalescing timer (2048 µs default) */
    csr_write32(0x004 /*CSR_INT_COALESCING*/, 512 /*IWL_HOST_INT_TIMEOUT_DEF*/);

    /* Read hardware revision for logging */
    uint32_t hw_rev = csr_read32(CSR_HW_REV);
    printf("[*] HW_REV=0x%08x (type=0x%03x step=0x%x)\n",
           hw_rev, (hw_rev >> 4) & 0xFFF, hw_rev & 0xF);
}

/* ── Build and kick firmware ──────────────────────────────────────────── */
static void build_and_kick_fw(void)
{
    uint32_t hw_rev = csr_read32(CSR_HW_REV);

    /* ── prph_scratch ─────────────────────────────────────────────────── */
    struct prph_scratch *ps =
        (struct prph_scratch *)vaddr_of(DMA_OFF_PRPH_SCRATCH);

    ps->ctrl_cfg.version.mac_id  = (uint16_t)hw_rev;
    ps->ctrl_cfg.version.version = 0;
    ps->ctrl_cfg.version.size    = (uint16_t)(sizeof(*ps) / 4);
    ps->ctrl_cfg.version.reserved = 0;

    ps->ctrl_cfg.control.control_flags = PRPH_SCRATCH_CTRL_FLAGS;
    ps->ctrl_cfg.control.reserved      = 0;

    /* free_rbd_addr = IOVA of the free BD ring */
    ps->ctrl_cfg.rbd_cfg.free_rbd_addr = iova_of(DMA_OFF_FREE_BD);

    /* Load firmware sections into DMA pool, fill dram arrays */
    load_fw_sections(&ps->dram);

    /* ── Pre-populate free BD ring ───────────────────────────────────────
     * Each free BD is struct iwl_rx_transfer_desc (16 bytes):
     *   le16 rbid; le16 reserved[3]; le64 addr;
     * The firmware reads these to find free RX buffers.
     * We map RX_BUF_PREFILL × RX_BUF_SIZE buffers from DMA_OFF_RX_BUFS. */
    uint8_t *free_bd = (uint8_t *)vaddr_of(DMA_OFF_FREE_BD);
    for (int i = 0; i < RX_BUF_PREFILL; i++) {
        uint64_t buf_iova = iova_of(DMA_OFF_RX_BUFS) +
                            (uint64_t)i * RX_BUF_SIZE;
        /* rbid at offset 0 (le16), addr at offset 8 (le64) */
        uint16_t rbid = (uint16_t)i;
        memcpy(free_bd + i * FREE_BD_SIZE + 0, &rbid, 2);
        memcpy(free_bd + i * FREE_BD_SIZE + 8, &buf_iova, 8);
    }
    printf("[*] pre-filled %d free BDs (RX buffers @ iova=0x%llx)\n",
           RX_BUF_PREFILL,
           (unsigned long long)iova_of(DMA_OFF_RX_BUFS));

    /* ── prph_info ────────────────────────────────────────────────────── */
    /* Zeroed by memset; tail pointer dummy lives at PAGE_SIZE/2 offset.
     * The kernel uses offsets PAGE_SIZE/2 and 3*PAGE_SIZE/4 inside this
     * page for tr_tail and cr_tail dummy arrays. */

    /* ── context_info_gen3 ────────────────────────────────────────────── */
    struct context_info_gen3 *ci =
        (struct context_info_gen3 *)vaddr_of(DMA_OFF_CTXT_INFO);

    /* version and size: kernel leaves these 0 (dma_alloc_coherent zeros) */
    ci->version               = 0;
    ci->size                  = 0;
    ci->config                = 0;
    ci->prph_info_base_addr   = iova_of(DMA_OFF_PRPH_INFO);
    ci->prph_scratch_base_addr = iova_of(DMA_OFF_PRPH_SCRATCH);
    ci->prph_scratch_size     = sizeof(*ps);

    /* cr_head: RX completion ring head index array (= rb_stts) */
    ci->cr_head_idx_arr_base_addr = iova_of(DMA_OFF_RB_STTS);

    /*
     * tr_tail and cr_tail: dummy arrays inside the prph_info page.
     * Kernel uses prph_info_dma_addr + PAGE_SIZE/2 and + 3*PAGE_SIZE/4.
     * Hardware writes there; must be valid DMA.  We use the second half
     * of the prph_info allocation (offset DMA_OFF_PRPH_INFO + 2048).
     */
    ci->tr_tail_idx_arr_base_addr =
        iova_of(DMA_OFF_PRPH_INFO) + 4096 / 2;
    ci->cr_tail_idx_arr_base_addr =
        iova_of(DMA_OFF_PRPH_INFO) + 3 * 4096 / 4;
    ci->tr_head_idx_arr_base_addr = 0;  /* not used for gen3 boot */

    ci->cr_idx_arr_size = 0;
    ci->tr_idx_arr_size = 0;

    /* mtr = TX command ring (MTR = message transfer ring) */
    ci->mtr_base_addr = iova_of(DMA_OFF_MTR);
    ci->mtr_size      = MTR_SIZE_CB;    /* TFD_QUEUE_CB_SIZE(128) = 4 */

    /* mcr = RX used/completion ring (MCR = message completion ring) */
    ci->mcr_base_addr = iova_of(DMA_OFF_USED_BD);
    ci->mcr_size      = MCR_SIZE_CB;    /* RX_QUEUE_CB_SIZE(4096) = 12 */

    /* Doorbells and MSI vectors: 0 (polled mode, no MSI/MSI-X) */
    ci->mtr_doorbell_vec = 0;
    ci->mcr_doorbell_vec = 0;
    ci->mtr_msi_vec      = 0;
    ci->mcr_msi_vec      = 0;

    ci->mtr_opt_header_size = 0;
    ci->mtr_opt_footer_size = 0;
    ci->mcr_opt_header_size = 0;
    ci->mcr_opt_footer_size = 0;
    ci->msg_rings_ctrl_flags = 0;
    ci->prph_info_msi_vec    = 0;

    printf("[*] context_info_gen3 @ iova=0x%llx\n",
           (unsigned long long)iova_of(DMA_OFF_CTXT_INFO));
    printf("[*] prph_scratch @ iova=0x%llx (size=%zu)\n",
           (unsigned long long)iova_of(DMA_OFF_PRPH_SCRATCH), sizeof(*ps));

    /* ── Load IML into DMA ────────────────────────────────────────────── */
    if (fw_iml && fw_iml_size > 0) {
        if (fw_iml_size > DMA_IML_MAX_SIZE) {
            fprintf(stderr, "IML too large (%u > %u)\n",
                    fw_iml_size, DMA_IML_MAX_SIZE);
            exit(1);
        }
        memcpy(vaddr_of(DMA_OFF_IML), fw_iml, fw_iml_size);
        printf("[*] IML loaded @ iova=0x%llx size=%u\n",
               (unsigned long long)iova_of(DMA_OFF_IML), fw_iml_size);
    } else {
        printf("[!] WARNING: no IML — AX210/AX211 needs IML to boot UMAC\n");
    }

    /* ── Clear + mask interrupts, then enable ALIVE only ─────────────── */
    csr_write32(CSR_INT,      0xFFFFFFFFu);  /* ACK all pending */
    csr_write32(CSR_INT_MASK, CSR_INT_BIT_ALIVE);  /* enable only ALIVE */

    /* Clear IML interrupt before kicking (kernel clears it in set_ltr) */
    csr_write32(CSR_MSIX_HW_INT_CAUSES_AD, MSIX_HW_INT_CAUSES_REG_IML);

    /* ── Write context info address to hardware ───────────────────────── */
    csr_write64(CSR_CTXT_INFO_ADDR, iova_of(DMA_OFF_CTXT_INFO));

    /* IML: so-a0-gf-a0 has IML (TLV type 52) — required for UMAC boot */
    if (fw_iml && fw_iml_size > 0) {
        csr_write64(CSR_IML_DATA_ADDR, iova_of(DMA_OFF_IML));
        csr_write32(CSR_IML_SIZE_ADDR, fw_iml_size);
    } else {
        csr_write64(CSR_IML_DATA_ADDR, 0);
        csr_write32(CSR_IML_SIZE_ADDR, 0);
    }

    /* Enable auto-function boot (CSR_CTXT_INFO_BOOT_CTRL = CSR offset 0x0,
     * which is the same BAR0 word as CSR_HW_IF_CONFIG_REG) */
    csr_set_bits(0x000, CSR_AUTO_FUNC_BOOT_ENA);

    printf("[*] context info addr written, AUTO_FUNC_BOOT_ENA set\n");

    /*
     * Kick firmware: for AX210 family, write UREG_CPU_INIT_RUN=1 via
     * UMAC PRPH (offset = UREG_CPU_INIT_RUN + umac_prph_offset).
     */
    /*
     * MAC access grab: required before any PRPH indirect write.
     * kernel: iwl_trans_grab_nic_access → set MAC_ACCESS_REQ, wait 2 µs,
     * poll until (GP_CNTRL & (MAC_CLOCK_READY | GOING_TO_SLEEP)) == MAC_CLOCK_READY.
     */
    csr_set_bits(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
    usleep(2);
    {
        int mac_ready = 0;
        for (int i = 0; i < 150; i++) {
            uint32_t gp = csr_read32(CSR_GP_CNTRL);
            if ((gp & (CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY |
                       CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP)) ==
                CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY) {
                mac_ready = 1;
                break;
            }
            usleep(1000);
        }
        if (!mac_ready)
            fprintf(stderr, "[!] WARNING: MAC access not ready (GP_CNTRL=0x%08x)\n",
                    csr_read32(CSR_GP_CNTRL));
        else
            printf("[*] MAC access grabbed (GP_CNTRL=0x%08x)\n",
                   csr_read32(CSR_GP_CNTRL));
    }

    printf("[*] writing UREG_CPU_INIT_RUN=1 via PRPH @ 0x%08x\n",
           PRPH_UREG_CPU_INIT_RUN);
    prph_write32(PRPH_UREG_CPU_INIT_RUN, 1);

    /* Release MAC access */
    csr_write32(CSR_GP_CNTRL,
                csr_read32(CSR_GP_CNTRL) & ~CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);

    printf("[*] firmware kick sent\n");

    /*
     * spin_for_iml: for AX210 integrated, the LMAC must load and run the
     * IML (image loader) before starting UMAC.  Poll CSR_MSIX_HW_INT_CAUSES_AD
     * bit 1 for up to 100 ms.  Simultaneously keep reading CSR_LTR_LAST_MSG
     * to work around a ROM LTR bug (same as the kernel workaround).
     * We don't fail if this times out — alive poll covers ultimate success.
     */
    if (fw_iml && fw_iml_size > 0) {
        int iml_done = 0;
        for (int i = 0; i < 1000; i++) {
            if (csr_read32(CSR_MSIX_HW_INT_CAUSES_AD) &
                    MSIX_HW_INT_CAUSES_REG_IML) {
                iml_done = 1;
                printf("[*] IML completed (at %d µs)\n", i * 100);
                break;
            }
            (void)csr_read32(CSR_LTR_LAST_MSG);  /* keep bus busy */
            usleep(100);
        }
        if (!iml_done)
            printf("[!] IML spin timed out — continuing to wait for ALIVE\n");
    }
}

/* ── Wait for ALIVE ───────────────────────────────────────────────────── */
static int wait_alive(int timeout_ms)
{
    printf("[*] waiting for ALIVE interrupt (CSR_INT bit 0) ...\n");
    for (int i = 0; i < timeout_ms; i++) {
        uint32_t intr = csr_read32(CSR_INT);
        if (intr & CSR_INT_BIT_ALIVE) {
            csr_write32(CSR_INT, CSR_INT_BIT_ALIVE);  /* ACK */
            printf("[+] ALIVE! (CSR_INT=0x%08x at %d ms)\n", intr, i);
            return 0;
        }
        if (intr & CSR_INT_BIT_HW_ERR) {
            printf("[-] HW error (CSR_INT=0x%08x at %d ms)\n", intr, i);
            return -1;
        }
        if (i % 500 == 0 && i > 0)
            printf("    ... still waiting (%d ms) CSR_INT=0x%08x GP=0x%08x\n",
                   i, intr, csr_read32(CSR_GP_CNTRL));
        usleep(1000);
    }
    printf("[-] timeout waiting for ALIVE (CSR_INT=0x%08x)\n",
           csr_read32(CSR_INT));
    return -1;
}

/* ── Cleanup ──────────────────────────────────────────────────────────── */
static void cleanup(void)
{
    if (bar0 && bar0 != MAP_FAILED)
        munmap(bar0, bar0_size);
    if (dma_vaddr && dma_vaddr != MAP_FAILED) {
        struct vfio_iommu_type1_dma_unmap du = {
            .argsz = sizeof(du),
            .iova  = dma_iova,
            .size  = DMA_TOTAL_SIZE,
        };
        ioctl(container_fd, VFIO_IOMMU_UNMAP_DMA, &du);
        munmap(dma_vaddr, DMA_TOTAL_SIZE);
    }
    if (device_fd >= 0)   close(device_fd);
    if (group_fd >= 0)    close(group_fd);
    if (container_fd >= 0) close(container_fd);
    if (fw_data)          free(fw_data);
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(void)
{
    if (getuid() != 0) {
        fprintf(stderr, "must run as root\n");
        return 1;
    }

    /* Step 1: rebind to vfio-pci */
    vfio_bind_device();

    /* Step 2: open VFIO, map BAR0, enable bus mastering, allocate DMA */
    vfio_open();
    vfio_map_bar0();
    vfio_enable_bus_master();
    vfio_alloc_dma();

    /* Step 3: parse firmware */
    parse_firmware();

    /* Step 4: SW reset to bring device to known state, then APM init */
    csr_write32(CSR_RESET, CSR_RESET_REG_FLAG_SW_RESET);
    msleep(6);
    apm_init();

    /* Step 5: build structures and kick firmware */
    build_and_kick_fw();

    /* Step 6: wait for ALIVE */
    int ret = wait_alive(5000);

    /* Dump final CSR state regardless */
    printf("[*] final state:\n");
    printf("    CSR_INT        = 0x%08x\n", csr_read32(CSR_INT));
    printf("    CSR_GP_CNTRL   = 0x%08x\n", csr_read32(CSR_GP_CNTRL));
    printf("    CSR_HW_IF_CFG  = 0x%08x\n", csr_read32(CSR_HW_IF_CONFIG_REG));
    printf("    CSR_RESET      = 0x%08x\n", csr_read32(CSR_RESET));
    /* Read prph_info to see if firmware updated it */
    struct prph_info *pi =
        (struct prph_info *)vaddr_of(DMA_OFF_PRPH_INFO);
    printf("    prph_info.boot_stage  = 0x%08x\n", pi->boot_stage_mirror);
    printf("    prph_info.ipc_status  = 0x%08x\n", pi->ipc_status_mirror);

    /* Cleanup */
    cleanup();

    /* Step 7: rebind to iwlwifi */
    vfio_unbind_device();

    return (ret == 0) ? 0 : 1;
}
