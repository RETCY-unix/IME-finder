/*
 * Intel Management Engine Security Analyzer
 * Advanced detection and analysis tool for Intel ME/CSME/TXE subsystems
 * 
 * This program performs comprehensive security analysis of Intel Management
 * Engine presence and configuration on your system through PCI bus scanning
 * and register analysis.
 * 
 * Build Instructions:
 *   gcc -o ime_analyzer ime_analyzer.c -lpci -O2 -Wall
 * 
 * Usage:
 *   sudo ./ime_analyzer [options]
 *   
 * Options:
 *   -v, --verbose    Enable detailed register dumps
 *   -j, --json       Output results in JSON format
 *   -s, --silent     Minimal output mode
 * 
 * Requirements:
 *   - Root privileges for PCI configuration space access
 *   - libpci-dev (Debian/Ubuntu) or pciutils-devel (RHEL/Fedora)
 * 
 * Notes:
 *   This tool performs read-only operations and does not modify system state.
 *   Detection of ME does not necessarily indicate it is exploitable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <pci/pci.h>

#define INTEL_VENDOR_ID 0x8086
#define AMD_VENDOR_ID 0x1022

#define ME_REG_HFS1    0x40
#define ME_REG_HFS2    0x48
#define ME_REG_HFS3    0x60
#define ME_REG_HFS4    0x64
#define ME_REG_HFS5    0x68
#define ME_REG_HFS6    0x6C

#define HFS1_WORKING_STATE_MASK     0x0000000F
#define HFS1_OPERATION_MODE_MASK    0x000F0000
#define HFS1_OPERATION_MODE_SHIFT   16
#define HFS1_ERROR_CODE_MASK        0x0000F000
#define HFS1_ERROR_CODE_SHIFT       12
#define HFS1_INIT_COMPLETE_MASK     0x00000200
#define HFS1_FW_UPDATE_IN_PROGRESS  0x00000040

typedef enum {
    ME_WORKING_STATE_RESET = 0,
    ME_WORKING_STATE_INIT = 1,
    ME_WORKING_STATE_RECOVERY = 2,
    ME_WORKING_STATE_DISABLED = 4,
    ME_WORKING_STATE_NORMAL = 5,
    ME_WORKING_STATE_WAIT = 6,
    ME_WORKING_STATE_TRANSITION = 7,
    ME_WORKING_STATE_INVALID = 8
} me_working_state_t;

typedef enum {
    ME_OP_MODE_NORMAL = 0,
    ME_OP_MODE_DEBUG = 2,
    ME_OP_MODE_SOFT_TEMP_DISABLE = 3,
    ME_OP_MODE_SECOVR_JMPR = 4,
    ME_OP_MODE_SECOVR_MSG = 5,
    ME_OP_MODE_DAL = 7,
    ME_OP_MODE_ALT_DISABLE = 14,
    ME_OP_MODE_HAP_DISABLE = 15
} me_operation_mode_t;

typedef struct {
    uint16_t device_id;
    const char *name;
    const char *chipset;
    const char *generation;
    bool is_txe;
} me_device_info_t;

static me_device_info_t known_me_devices[] = {
    {0x0f18, "Atom Z36xxx/Z37xxx TXE", "Bay Trail", "TXE 2.x", true},
    {0x2298, "Atom x5-E8000/J3xxx/N3xxx TXE", "Braswell/Cherry Trail", "TXE 2.x", true},
    {0x1c3a, "6 Series/C200 MEI #1", "Cougar Point", "ME 7.x", false},
    {0x1c3b, "6 Series/C200 MEI #2", "Cougar Point", "ME 7.x", false},
    {0x1d3a, "C600/X79 MEI #1", "Patsburg", "ME 8.x", false},
    {0x1d3b, "C600/X79 MEI #2", "Patsburg", "ME 8.x", false},
    {0x1e3a, "7 Series/C216 MEI #1", "Panther Point", "ME 8.x", false},
    {0x1e3b, "7 Series/C216 MEI #2", "Panther Point", "ME 8.x", false},
    {0x8c3a, "8 Series/C220 MEI #1", "Lynx Point", "ME 9.x", false},
    {0x8c3b, "8 Series/C220 MEI #2", "Lynx Point", "ME 9.x", false},
    {0x9c3a, "8 Series MEI #1", "Lynx Point-LP", "ME 9.x", false},
    {0x9c3b, "8 Series MEI #2", "Lynx Point-LP", "ME 9.x", false},
    {0x9cba, "Wildcat Point-LP MEI", "Wildcat Point", "ME 10.x", false},
    {0x9cbb, "Wildcat Point-LP MEI #2", "Wildcat Point", "ME 10.x", false},
    {0xa13a, "100 Series/C230 MEI #1", "Sunrise Point", "ME 11.x", false},
    {0xa13b, "100 Series/C230 MEI #2", "Sunrise Point", "ME 11.x", false},
    {0xa1ba, "C620 Series MEI #1", "Lewisburg", "ME 11.x", false},
    {0xa1be, "C620 Series MEI #2", "Lewisburg", "ME 11.x", false},
    {0xa2ba, "200 Series CSME #1", "Union Point", "CSME 11.x", false},
    {0xa2bb, "200 Series CSME #2", "Union Point", "CSME 11.x", false},
    {0xa2be, "200 Series CSME #3", "Union Point", "CSME 11.x", false},
    {0xa360, "Cannon Lake MEI", "Cannon Lake", "CSME 12.x", false},
    {0x9d3a, "Sunrise Point-LP CSME #1", "Sunrise Point", "CSME 11.x", false},
    {0x9d3b, "Sunrise Point-LP CSME #2", "Sunrise Point", "CSME 11.x", false},
    {0x9de0, "Cannon Point-LP MEI", "Cannon Point", "CSME 12.x", false},
    {0x9de4, "Cannon Point-LP MEI #4", "Cannon Point", "CSME 12.x", false},
    {0x02e0, "Comet Lake CSME", "Comet Lake", "CSME 14.x", false},
    {0x06e0, "Comet Lake-H CSME", "Comet Lake", "CSME 14.x", false},
    {0x18d3, "Atom P5xxx MEI", "Elkhart Lake", "CSME 14.x", false},
    {0x19e5, "Atom E3900 MEI", "Apollo Lake", "TXE 3.x", true},
    {0x1a9a, "Atom C3000 MEI", "Denverton", "ME 11.x", false},
    {0x1be0, "Tiger Lake-LP CSME", "Tiger Lake", "CSME 14.x", false},
    {0x43e0, "Tiger Lake-H CSME", "Tiger Lake", "CSME 14.x", false},
    {0x4b70, "Elkhart Lake CSME", "Elkhart Lake", "CSME 14.x", false},
    {0x51e0, "Alder Lake-P CSME", "Alder Lake", "CSME 15.x", false},
    {0x54e0, "Alder Lake-N CSME", "Alder Lake", "CSME 15.x", false},
    {0x7a68, "Raptor Lake CSME #1", "Raptor Lake", "CSME 16.x", false},
    {0x7a74, "Raptor Lake CSME #4", "Raptor Lake", "CSME 16.x", false},
    {0x7ae8, "Raptor Lake-S CSME #1", "Raptor Lake", "CSME 16.x", false},
    {0x0000, NULL, NULL, NULL, false}
};

typedef struct {
    bool verbose;
    bool json;
    bool silent;
} options_t;

static options_t opts = {false, false, false};

void print_header(void) {
    if (opts.json || opts.silent) return;
    
    printf("\n");
    printf("================================================================================\n");
    printf("                Intel Management Engine Security Analyzer                      \n");
    printf("                        Comprehensive ME/CSME/TXE Detector                     \n");
    printf("================================================================================\n\n");
}

const char* get_working_state_string(uint8_t state) {
    switch(state) {
        case ME_WORKING_STATE_RESET:      return "RESET";
        case ME_WORKING_STATE_INIT:       return "INITIALIZING";
        case ME_WORKING_STATE_RECOVERY:   return "RECOVERY MODE";
        case ME_WORKING_STATE_DISABLED:   return "PLATFORM DISABLED";
        case ME_WORKING_STATE_NORMAL:     return "NORMAL OPERATION";
        case ME_WORKING_STATE_WAIT:       return "WAITING";
        case ME_WORKING_STATE_TRANSITION: return "TRANSITIONING";
        default:                          return "UNKNOWN";
    }
}

const char* get_operation_mode_string(uint8_t mode) {
    switch(mode) {
        case ME_OP_MODE_NORMAL:            return "Normal";
        case ME_OP_MODE_DEBUG:             return "Debug";
        case ME_OP_MODE_SOFT_TEMP_DISABLE: return "Soft Temporary Disable";
        case ME_OP_MODE_SECOVR_JMPR:       return "Security Override Jumper";
        case ME_OP_MODE_SECOVR_MSG:        return "Security Override Message";
        case ME_OP_MODE_DAL:               return "DAL";
        case ME_OP_MODE_ALT_DISABLE:       return "AltMeDisable Bit Set";
        case ME_OP_MODE_HAP_DISABLE:       return "HAP/AltMeDisable (High Assurance Platform)";
        default:                           return "Unknown";
    }
}

const char* get_risk_level(uint8_t working_state, uint8_t op_mode) {
    if (working_state == ME_WORKING_STATE_DISABLED ||
        working_state == ME_WORKING_STATE_WAIT ||
        op_mode == ME_OP_MODE_SOFT_TEMP_DISABLE ||
        op_mode == ME_OP_MODE_ALT_DISABLE ||
        op_mode == ME_OP_MODE_HAP_DISABLE) {
        return "LOW";
    }
    if (working_state == ME_WORKING_STATE_RECOVERY) {
        return "MEDIUM";
    }
    if (working_state == ME_WORKING_STATE_NORMAL && op_mode == ME_OP_MODE_NORMAL) {
        return "HIGH";
    }
    return "MEDIUM";
}

void analyze_hfs_registers(struct pci_dev *dev, const me_device_info_t *info) {
    uint32_t hfs1, hfs2, hfs3, hfs4, hfs5, hfs6;
    uint8_t working_state, operation_mode, error_code;
    bool init_complete, fw_update;
    
    hfs1 = pci_read_long(dev, ME_REG_HFS1);
    hfs2 = pci_read_long(dev, ME_REG_HFS2);
    
    working_state = hfs1 & HFS1_WORKING_STATE_MASK;
    operation_mode = (hfs1 & HFS1_OPERATION_MODE_MASK) >> HFS1_OPERATION_MODE_SHIFT;
    error_code = (hfs1 & HFS1_ERROR_CODE_MASK) >> HFS1_ERROR_CODE_SHIFT;
    init_complete = (hfs1 & HFS1_INIT_COMPLETE_MASK) != 0;
    fw_update = (hfs1 & HFS1_FW_UPDATE_IN_PROGRESS) != 0;
    
    if (!opts.silent) {
        printf("Host Firmware Status Register Analysis:\n");
        printf("----------------------------------------\n");
        printf("  HFS1 Register:         0x%08X\n", hfs1);
        printf("  Working State:         %s (%d)\n", 
               get_working_state_string(working_state), working_state);
        printf("  Operation Mode:        %s (%d)\n", 
               get_operation_mode_string(operation_mode), operation_mode);
        printf("  Error Code:            %d\n", error_code);
        printf("  Initialization:        %s\n", init_complete ? "Complete" : "In Progress");
        printf("  Firmware Update:       %s\n", fw_update ? "In Progress" : "Not Active");
        printf("\n");
        
        if (opts.verbose) {
            hfs3 = pci_read_long(dev, ME_REG_HFS3);
            hfs4 = pci_read_long(dev, ME_REG_HFS4);
            hfs5 = pci_read_long(dev, ME_REG_HFS5);
            hfs6 = pci_read_long(dev, ME_REG_HFS6);
            
            printf("  HFS2 Register:         0x%08X\n", hfs2);
            printf("  HFS3 Register:         0x%08X\n", hfs3);
            printf("  HFS4 Register:         0x%08X\n", hfs4);
            printf("  HFS5 Register:         0x%08X\n", hfs5);
            printf("  HFS6 Register:         0x%08X\n", hfs6);
            printf("\n");
        }
    }
    
    const char* risk = get_risk_level(working_state, operation_mode);
    
    printf("Security Risk Assessment: %s\n", risk);
    printf("================================================================================\n\n");
    
    if (strcmp(risk, "HIGH") == 0) {
        printf("CRITICAL: Intel ME is fully operational with normal mode enabled.\n");
        printf("This subsystem has privileged access to:\n");
        printf("  - All system memory via DMA\n");
        printf("  - Network interface for remote access\n");
        printf("  - Storage devices and encryption keys\n");
        printf("  - CPU registers and execution state\n");
        printf("  - Continues operation when system appears powered off\n\n");
        printf("Recommendations:\n");
        printf("  1. Check for firmware updates addressing known vulnerabilities\n");
        printf("  2. Disable AMT/vPro if not required for your use case\n");
        printf("  3. Consider using me_cleaner for firmware neutering\n");
        printf("  4. Enable HAP bit if available on your platform\n");
        printf("  5. Monitor network traffic for unexpected ME activity\n");
    } else if (strcmp(risk, "MEDIUM") == 0) {
        printf("WARNING: Intel ME is present but in a non-standard state.\n");
        printf("This may indicate partial disabling or recovery mode.\n");
        printf("Verify this matches your security configuration expectations.\n");
    } else {
        printf("GOOD: Intel ME appears to be disabled or in a limited state.\n");
        printf("Note: Even in disabled states, ME may still perform basic functions.\n");
        printf("Complete removal is not possible without hardware modification.\n");
    }
    printf("\n");
}

void check_me_device(struct pci_dev *dev, const me_device_info_t *info) {
    if (!opts.silent) {
        printf("\n");
        printf("================================================================================\n");
        printf("ME/CSME/TXE Device Detected\n");
        printf("================================================================================\n");
        printf("Device Information:\n");
        printf("  Name:                  %s\n", info->name);
        printf("  Chipset:               %s\n", info->chipset);
        printf("  Generation:            %s\n", info->generation);
        printf("  Type:                  %s\n", info->is_txe ? "TXE (Trusted Execution Engine)" : 
                                                             "ME/CSME (Management Engine)");
        printf("  PCI Location:          %04x:%02x:%02x.%d\n",
               dev->domain, dev->bus, dev->dev, dev->func);
        printf("  Device ID:             0x%04X\n", dev->device_id);
        printf("  Vendor ID:             0x%04X (Intel Corporation)\n", dev->vendor_id);
        printf("\n");
    }
    
    analyze_hfs_registers(dev, info);
}

void check_system_info(void) {
    if (opts.json || opts.silent) return;
    
    FILE *fp;
    char buffer[512];
    time_t now;
    struct tm *timeinfo;
    
    time(&now);
    timeinfo = localtime(&now);
    
    printf("System Analysis Report\n");
    printf("================================================================================\n");
    printf("Scan Time: %s", asctime(timeinfo));
    
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
    
    fp = popen("uname -sr 2>/dev/null", "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            printf("Kernel: %s", buffer);
        }
        pclose(fp);
    }
    
    printf("\n");
}

void check_amd_psp(struct pci_access *pacc) {
    struct pci_dev *dev;
    bool found_amd = false;
    
    for (dev = pacc->devices; dev; dev = dev->next) {
        pci_fill_info(dev, PCI_FILL_IDENT);
        if (dev->vendor_id == AMD_VENDOR_ID) {
            found_amd = true;
            break;
        }
    }
    
    if (found_amd && !opts.silent) {
        printf("\n");
        printf("================================================================================\n");
        printf("NOTE: AMD Processor Detected\n");
        printf("================================================================================\n");
        printf("AMD systems use Platform Security Processor (PSP) instead of Intel ME.\n");
        printf("PSP provides similar functionality but with different implementation:\n");
        printf("  - Runs on dedicated ARM Cortex-A5 core\n");
        printf("  - Handles secure boot and encryption\n");
        printf("  - Less documented than Intel ME\n");
        printf("  - Subject to similar security concerns\n\n");
        printf("For PSP analysis, different tools are required.\n");
        printf("This tool is specifically designed for Intel ME detection.\n\n");
    }
}

void print_mitigation_info(void) {
    if (opts.json || opts.silent) return;
    
    printf("================================================================================\n");
    printf("Security Mitigation Options\n");
    printf("================================================================================\n\n");
    
    printf("Software Methods:\n");
    printf("  1. me_cleaner (Partial Disabling)\n");
    printf("     - Open source Python tool\n");
    printf("     - Removes non-essential ME modules\n");
    printf("     - Requires SPI programmer for flash access\n");
    printf("     - GitHub: https://github.com/corna/me_cleaner\n\n");
    
    printf("  2. HAP/AltMeDisable Bit\n");
    printf("     - Hardware kill switch for ME >= 11\n");
    printf("     - Originally for US government High Assurance Platform\n");
    printf("     - Can be set via flash descriptor modification\n");
    printf("     - ME halts early in boot process\n\n");
    
    printf("  3. BIOS Settings\n");
    printf("     - Disable Intel AMT in BIOS/UEFI\n");
    printf("     - Disable ME BIOS Extension (MEBx)\n");
    printf("     - Some vendors provide \"ME disabled\" option\n\n");
    
    printf("Hardware Solutions:\n");
    printf("  1. Pre-disabled Systems\n");
    printf("     - System76 laptops (Coreboot)\n");
    printf("     - Purism Librem laptops\n");
    printf("     - Dell systems with government option\n\n");
    
    printf("  2. Coreboot Firmware\n");
    printf("     - Open source BIOS replacement\n");
    printf("     - Can minimize ME firmware\n");
    printf("     - Limited hardware support\n\n");
    
    printf("Important Warnings:\n");
    printf("  - ME cannot be completely removed on modern Intel systems\n");
    printf("  - System will shut down after 30 minutes if ME missing/corrupted\n");
    printf("  - Improper modification can brick your system\n");
    printf("  - Always backup firmware before modifications\n");
    printf("  - Consider professional assistance for hardware programming\n\n");
}

int main(int argc, char **argv) {
    struct pci_access *pacc;
    struct pci_dev *dev;
    int found_me = 0;
    int c;
    
    static struct option long_options[] = {
        {"verbose", no_argument, 0, 'v'},
        {"json", no_argument, 0, 'j'},
        {"silent", no_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((c = getopt_long(argc, argv, "vjsh", long_options, NULL)) != -1) {
        switch (c) {
            case 'v':
                opts.verbose = true;
                break;
            case 'j':
                opts.json = true;
                break;
            case 's':
                opts.silent = true;
                break;
            case 'h':
                printf("Usage: %s [OPTIONS]\n", argv[0]);
                printf("Options:\n");
                printf("  -v, --verbose    Enable detailed register dumps\n");
                printf("  -j, --json       Output results in JSON format\n");
                printf("  -s, --silent     Minimal output mode\n");
                printf("  -h, --help       Display this help message\n");
                return 0;
            default:
                return 1;
        }
    }
    
    if (geteuid() != 0) {
        fprintf(stderr, "Error: Root privileges required for PCI configuration access.\n");
        fprintf(stderr, "Please run with: sudo %s\n", argv[0]);
        return 1;
    }
    
    print_header();
    check_system_info();
    
    pacc = pci_alloc();
    if (!pacc) {
        fprintf(stderr, "Error: Failed to allocate PCI access structure\n");
        return 1;
    }
    
    pci_init(pacc);
    pci_scan_bus(pacc);
    
    if (!opts.silent) {
        printf("Scanning PCI bus for Intel ME/CSME/TXE devices...\n");
        printf("================================================================================\n");
    }
    
    for (dev = pacc->devices; dev; dev = dev->next) {
        pci_fill_info(dev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);
        
        if (dev->vendor_id == INTEL_VENDOR_ID) {
            for (int i = 0; known_me_devices[i].name != NULL; i++) {
                if (known_me_devices[i].device_id == dev->device_id) {
                    check_me_device(dev, &known_me_devices[i]);
                    found_me = 1;
                    break;
                }
            }
        }
    }
    
    if (!found_me) {
        if (!opts.silent) {
            printf("\nNo Intel ME/CSME/TXE devices detected on PCI bus.\n\n");
            printf("Possible Explanations:\n");
            printf("  1. ME successfully disabled (good)\n");
            printf("  2. ME hidden from OS but still active (concerning)\n");
            printf("  3. Non-Intel processor (AMD, ARM, etc.)\n");
            printf("  4. Very old Intel system (pre-2006, no ME)\n");
            printf("  5. PCI enumeration incomplete or restricted\n\n");
        }
        check_amd_psp(pacc);
    }
    
    print_mitigation_info();
    
    if (!opts.silent) {
        printf("================================================================================\n");
        printf("Scan Complete\n");
        printf("================================================================================\n\n");
        printf("For additional information:\n");
        printf("  - Intel ME vulnerabilities: https://security-center.intel.com\n");
        printf("  - me_cleaner project: https://github.com/corna/me_cleaner\n");
        printf("  - EFF Intel ME concerns: https://www.eff.org/deeplinks/2017/05/intels-management-engine-security-hazard-and-users-need-way-disable-it\n\n");
    }
    
    pci_cleanup(pacc);
    
    return found_me ? 0 : 2;
}
