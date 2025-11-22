#ifndef _WIN32

#include "ime_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pci/pci.h>

void analyze_registers(struct pci_dev *dev, const me_device_info_t *info) {
    uint32_t hfs1 = pci_read_long(dev, ME_REG_HFS1);
    uint8_t working_state = hfs1 & HFS1_WORKING_STATE_MASK;
    uint8_t operation_mode = (hfs1 & HFS1_OPERATION_MODE_MASK) >> HFS1_OPERATION_MODE_SHIFT;
    uint8_t error_code = (hfs1 & HFS1_ERROR_CODE_MASK) >> HFS1_ERROR_CODE_SHIFT;
    bool init_complete = (hfs1 & HFS1_INIT_COMPLETE_MASK) != 0;
    bool fw_update = (hfs1 & HFS1_FW_UPDATE_IN_PROGRESS) != 0;
    
    print_register_analysis(hfs1, working_state, operation_mode, error_code, init_complete, fw_update);
    
    const char* risk = get_risk_level(working_state, operation_mode);
    print_risk_assessment(risk, working_state, operation_mode);
}

int scan_linux_devices(void) {
    if (geteuid() != 0) {
        set_color(COLOR_RED);
        printf("\n    ╔═══════════════════════════════════════════════════════════════════════════╗\n");
        printf("    ║                         ACCESS DENIED                                     ║\n");
        printf("    ╠═══════════════════════════════════════════════════════════════════════════╣\n");
        printf("    ║ Need root to access PCI config space. Run: sudo ./ime_analyzer           ║\n");
        printf("    ╚═══════════════════════════════════════════════════════════════════════════╝\n");
        reset_color();
        return -1;
    }
    
    struct pci_access *pacc = pci_alloc();
    if (!pacc) {
        set_color(COLOR_RED);
        printf("\n    ERROR: Can't allocate PCI access\n");
        reset_color();
        return -1;
    }
    
    pci_init(pacc);
    pci_scan_bus(pacc);
    
    int found = 0;
    struct pci_dev *dev;
    
    for (dev = pacc->devices; dev; dev = dev->next) {
        pci_fill_info(dev, PCI_FILL_IDENT | PCI_FILL_BASES);
        
        if (dev->vendor_id == INTEL_VENDOR_ID) {
            for (int i = 0; me_devices[i].name != NULL; i++) {
                if (me_devices[i].device_id == dev->device_id) {
                    print_device_header(&me_devices[i], dev->vendor_id, dev->device_id);
                    analyze_registers(dev, &me_devices[i]);
                    found++;
                    break;
                }
            }
        }
    }
    
    pci_cleanup(pacc);
    return found;
}

#endif
