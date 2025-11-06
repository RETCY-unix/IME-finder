/*
 * Intel Management Engine (IME) Status Checker
 * 
 * This program checks if Intel ME is present and running on your system.
 * It reads PCI configuration space to detect the ME interface.
 * 
 * Compile: gcc -o ime_checker ime_checker.c -lpci
 * Run: sudo ./ime_checker
 * 
 * Note: Requires libpci-dev (Debian/Ubuntu) or pciutils-devel (RHEL/Fedora)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pci/pci.h>
#include <unistd.h>
#include <sys/io.h>

#define PCI_VENDOR_INTEL 0x8086

// ME PCI Device IDs for different chipset generations
typedef struct {
    uint16_t device_id;
    const char *name;
} me_device_t;

me_device_t me_devices[] = {
    {0x2a44, "Mobile 4 Series MEI"},
    {0x2e14, "4 Series MEI"},
    {0x1c3a, "6 Series/C200 MEI #1"},
    {0x1e3a, "7 Series/C216 MEI #1"},
    {0x8c3a, "8 Series/C220 MEI #1"},
    {0x9c3a, "8 Series MEI #0"},
    {0x9cba, "Wildcat Point-LP MEI #1"},
    {0xa13a, "100 Series/C230 MEI #1"},
    {0xa2ba, "200 Series MEI #1"},
    {0xa360, "Cannon Lake MEI"},
    {0x9de0, "Cannon Point-LP MEI"},
    {0x0, NULL}
};

// ME Status Register offsets
#define PCI_ME_HFS 0x40
#define PCI_ME_HFS2 0x48

// ME Status bit fields
#define ME_HFS_CWS_MASK 0xF
#define ME_HFS_CWS_RESET 0
#define ME_HFS_CWS_INIT 1
#define ME_HFS_CWS_REC 2
#define ME_HFS_CWS_DISABLED 4
#define ME_HFS_CWS_NORMAL 5
#define ME_HFS_CWS_WAIT 6

void print_banner() {
    printf("\n");
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║   Intel Management Engine (IME) Status Checker    ║\n");
    printf("╚════════════════════════════════════════════════════╝\n\n");
}

void print_me_status(uint32_t status) {
    printf("ME Status Register: 0x%08x\n\n", status);
    
    uint8_t cws = status & ME_HFS_CWS_MASK;
    uint8_t op_state = (status >> 4) & 0xF;
    uint8_t init_complete = (status >> 9) & 1;
    uint8_t mfg_mode = (status >> 4) & 1;
    uint8_t op_mode = (status >> 16) & 0xF;
    uint8_t error_code = (status >> 12) & 0xF;
    
    printf("Current Working State: ");
    switch(cws) {
        case ME_HFS_CWS_RESET:
            printf("RESET\n");
            break;
        case ME_HFS_CWS_INIT:
            printf("INITIALIZING\n");
            break;
        case ME_HFS_CWS_REC:
            printf("RECOVERY\n");
            break;
        case ME_HFS_CWS_DISABLED:
            printf("⚠️  PLATFORM DISABLED ⚠️\n");
            break;
        case ME_HFS_CWS_NORMAL:
            printf("🔴 NORMAL (RUNNING) 🔴\n");
            break;
        case ME_HFS_CWS_WAIT:
            printf("WAIT\n");
            break;
        default:
            printf("UNKNOWN (%d)\n", cws);
    }
    
    printf("Firmware Init Complete: %s\n", init_complete ? "YES" : "NO");
    printf("Manufacturing Mode: %s\n", mfg_mode ? "YES" : "NO");
    printf("Operation Mode: %d\n", op_mode);
    printf("Error Code: %d\n\n", error_code);
}

void check_me_device(struct pci_dev *dev) {
    const char *device_name = "Unknown ME Device";
    
    // Find device name
    for (int i = 0; me_devices[i].name != NULL; i++) {
        if (me_devices[i].device_id == dev->device_id) {
            device_name = me_devices[i].name;
            break;
        }
    }
    
    printf("Found Intel ME Device:\n");
    printf("  Device: %s\n", device_name);
    printf("  PCI Address: %04x:%02x:%02x.%d\n",
           dev->domain, dev->bus, dev->dev, dev->func);
    printf("  Device ID: 0x%04x\n\n", dev->device_id);
    
    // Read ME Status Register
    uint32_t me_status = pci_read_long(dev, PCI_ME_HFS);
    print_me_status(me_status);
    
    // Check if ME is disabled
    uint8_t cws = me_status & ME_HFS_CWS_MASK;
    if (cws == ME_HFS_CWS_DISABLED || cws == ME_HFS_CWS_WAIT) {
        printf("✓ Intel ME appears to be DISABLED or in WAIT state\n");
    } else if (cws == ME_HFS_CWS_NORMAL) {
        printf("✗ Intel ME is ACTIVE and RUNNING\n");
        printf("\n⚠️  WARNING: Intel ME has full access to:\n");
        printf("   - System memory\n");
        printf("   - Network interface\n");
        printf("   - Display\n");
        printf("   - All I/O devices\n");
        printf("   - Runs even when system is \"off\"\n");
    }
}

void check_system_info() {
    FILE *fp;
    char buffer[256];
    
    printf("\n════════════════════════════════════════════════════\n");
    printf("System Information:\n");
    printf("════════════════════════════════════════════════════\n\n");
    
    // Check CPU info
    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "model name")) {
                printf("CPU: %s", strchr(buffer, ':') + 2);
                break;
            }
        }
        fclose(fp);
    }
    
    // Check kernel version
    fp = popen("uname -r", "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            printf("Kernel: %s", buffer);
        }
        pclose(fp);
    }
    
    printf("\n");
}

int main(int argc, char **argv) {
    struct pci_access *pacc;
    struct pci_dev *dev;
    int found_me = 0;
    
    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This program must be run as root (use sudo)\n");
        return 1;
    }
    
    print_banner();
    check_system_info();
    
    printf("════════════════════════════════════════════════════\n");
    printf("Scanning for Intel Management Engine...\n");
    printf("════════════════════════════════════════════════════\n\n");
    
    // Initialize PCI library
    pacc = pci_alloc();
    if (!pacc) {
        fprintf(stderr, "Error: Cannot allocate PCI access structure\n");
        return 1;
    }
    
    pci_init(pacc);
    pci_scan_bus(pacc);
    
    // Scan for Intel ME devices
    for (dev = pacc->devices; dev; dev = dev->next) {
        pci_fill_info(dev, PCI_FILL_IDENT | PCI_FILL_BASES);
        
        // Check for Intel vendor and ME device
        if (dev->vendor_id == PCI_VENDOR_INTEL) {
            for (int i = 0; me_devices[i].name != NULL; i++) {
                if (me_devices[i].device_id == dev->device_id) {
                    pci_fill_info(dev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);
                    check_me_device(dev);
                    found_me = 1;
                    break;
                }
            }
        }
    }
    
    if (!found_me) {
        printf("✓ No Intel Management Engine device detected on PCI bus\n");
        printf("\nNote: This could mean:\n");
        printf("  1. ME is successfully disabled\n");
        printf("  2. ME is hidden from OS (still running in background)\n");
        printf("  3. System uses AMD processor (which has PSP instead)\n");
        printf("  4. Very old system (pre-2008)\n");
    }
    
    printf("\n════════════════════════════════════════════════════\n");
    printf("Additional Security Information:\n");
    printf("════════════════════════════════════════════════════\n\n");
    printf("To truly disable Intel ME:\n");
    printf("  1. Use me_cleaner tool (requires SPI flash programmer)\n");
    printf("  2. Buy systems with ME disabled (System76, Purism)\n");
    printf("  3. Use Coreboot firmware with ME disabled\n");
    printf("  4. Set HAP bit (High Assurance Platform) if supported\n\n");
    printf("For AMD systems, check for Platform Security Processor (PSP)\n");
    printf("which is AMD's equivalent to Intel ME.\n\n");
    
    pci_cleanup(pacc);
    
    return 0;
}
