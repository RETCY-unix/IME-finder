#include "ime_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#else
#include <unistd.h>
#include <pci/pci.h>
#endif

static options_t opts = {false, false, false, false};

void sleep_ms(int milliseconds) {
#ifdef _WIN32
    Sleep(milliseconds);
#else
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

void set_color(int color) {
#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
#else
    switch(color) {
        case COLOR_RED: printf("\033[1;31m"); break;
        case COLOR_GREEN: printf("\033[1;32m"); break;
        case COLOR_YELLOW: printf("\033[1;33m"); break;
        case COLOR_BLUE: printf("\033[1;34m"); break;
        case COLOR_MAGENTA: printf("\033[1;35m"); break;
        case COLOR_CYAN: printf("\033[1;36m"); break;
        case COLOR_WHITE: printf("\033[1;37m"); break;
        case COLOR_RESET: printf("\033[0m"); break;
    }
#endif
}

void reset_color(void) {
#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 7);
#else
    printf("\033[0m");
#endif
}

void print_banner(void) {
    if (opts.silent) return;
    
    system("clear || cls");
    
    set_color(COLOR_RED);
    printf("\n");
    printf("    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗\n");
    printf("    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝\n");
    printf("    ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ \n");
    printf("    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  \n");
    printf("    ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   \n");
    printf("    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   \n");
    reset_color();
    
    set_color(COLOR_CYAN);
    printf("\n    ██╗███╗   ███╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ \n");
    printf("    ██║████╗ ████║██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗\n");
    printf("    ██║██╔████╔██║█████╗      ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝\n");
    printf("    ██║██║╚██╔╝██║██╔══╝      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗\n");
    printf("    ██║██║ ╚═╝ ██║███████╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║\n");
    printf("    ╚═╝╚═╝     ╚═╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n");
    reset_color();
    
    printf("\n    Intel Management Engine Security Analyzer v2.0\n");
    printf("    Analyzing system for ME/CSME/TXE firmware presence...\n\n");
}

void print_progress_bar(int percentage) {
    if (opts.silent) return;
    
    int bar_width = 50;
    int filled = (bar_width * percentage) / 100;
    
    printf("\r    [");
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) {
            printf("=");
        } else {
            printf(" ");
        }
    }
    printf("] %3d%%", percentage);
    fflush(stdout);
}

void animate_scan(void) {
    if (opts.silent) return;
    
    const char* stages[] = {
        "Initializing scan engine",
        "Loading PCI device database",
        "Probing system buses",
        "Analyzing chipset",
        "Detecting ME firmware",
        "Reading security registers"
    };
    
    for (int i = 0; i < 6; i++) {
        printf("    [*] %s...", stages[i]);
        fflush(stdout);
        sleep_ms(200);
        printf(" Done\n");
    }
    printf("\n");
}

void print_device_header(const me_device_info_t *info, uint16_t vendor_id, uint16_t device_id) {
    if (opts.silent) return;
    
    set_color(COLOR_RED);
    printf("\n=============================================================================\n");
    printf("DEVICE DETECTED\n");
    printf("=============================================================================\n");
    reset_color();
    
    printf("Name:          %s\n", info->name);
    printf("Chipset:       %s\n", info->chipset);
    printf("Generation:    %s\n", info->generation);
    printf("Type:          %s\n", info->is_txe ? "TXE - Trusted Execution Engine" : "ME/CSME - Management Engine");
    printf("Vendor ID:     0x%04X (Intel Corporation)\n", vendor_id);
    printf("Device ID:     0x%04X\n", device_id);
}

void print_register_analysis(uint32_t hfs1, uint8_t working_state, uint8_t op_mode, 
                             uint8_t error_code, bool init_complete, bool fw_update) {
    if (opts.silent) return;
    
    printf("\n");
    printf("FIRMWARE STATUS ANALYSIS\n");
    printf("-----------------------------------------------------------------------------\n");
    
    printf("HFS1 Register:     0x%08X\n", hfs1);
    printf("Working State:     %s\n", get_working_state_string(working_state));
    printf("Operation Mode:    %s\n", get_operation_mode_string(op_mode));
    printf("Error Code:        %d\n", error_code);
    printf("Initialization:    %s\n", init_complete ? "COMPLETE" : "IN PROGRESS");
    printf("Firmware Update:   %s\n", fw_update ? "IN PROGRESS" : "INACTIVE");
}

void print_capabilities_warning(void) {
    if (opts.silent) return;
    
    printf("\n");
    set_color(COLOR_RED);
    printf("SUBSYSTEM CAPABILITIES\n");
    printf("-----------------------------------------------------------------------------\n");
    reset_color();
    
    printf("- Unrestricted memory access (Ring -3 privilege)\n");
    printf("- Network interface control (Out-of-band)\n");
    printf("- Persistent storage access (Disk encryption keys)\n");
    printf("- CPU execution monitoring (System Management Mode)\n");
    printf("- Operates while system powered off\n");
    printf("- Remote management capabilities (AMT/vPro)\n");
    printf("- Firmware update mechanism\n");
    printf("- Cryptographic key storage\n");
}

void print_risk_assessment(const char* risk_level, uint8_t working_state, uint8_t op_mode) {
    if (opts.silent) return;
    
    printf("\n");
    printf("RISK ASSESSMENT\n");
    printf("-----------------------------------------------------------------------------\n");
    
    if (strcmp(risk_level, "CRITICAL") == 0) {
        set_color(COLOR_RED);
        printf("THREAT LEVEL: CRITICAL\n");
        reset_color();
        printf("Intel ME is fully operational - maximum threat condition\n");
        
        print_capabilities_warning();
        
        printf("\n");
        set_color(COLOR_YELLOW);
        printf("RECOMMENDED ACTIONS\n");
        printf("-----------------------------------------------------------------------------\n");
        reset_color();
        printf("1. Check for critical firmware vulnerabilities\n");
        printf("2. Disable AMT/vPro if not required for operations\n");
        printf("3. Consider me_cleaner for firmware neutralization\n");
        printf("4. Enable HAP bit if platform supports this feature\n");
        printf("5. Monitor all network traffic for unauthorized ME activity\n");
        printf("6. Implement network segmentation and firewall rules\n");
        printf("7. Consider hardware replacement with pre-neutered systems\n");
        
    } else if (strcmp(risk_level, "ELEVATED") == 0) {
        set_color(COLOR_YELLOW);
        printf("THREAT LEVEL: ELEVATED\n");
        reset_color();
        printf("ME detected in non-standard state - verify configuration\n");
        
    } else {
        set_color(COLOR_GREEN);
        printf("THREAT LEVEL: MITIGATED\n");
        reset_color();
        printf("ME appears disabled or limited - reduced threat level\n");
        printf("\nNote: Even in disabled states, ME may retain basic functionality.\n");
        printf("Complete removal impossible without hardware modification.\n");
    }
}

void print_scan_complete(int found) {
    if (opts.silent) return;
    
    printf("\n\n");
    printf("=============================================================================\n");
    printf("SCAN COMPLETE\n");
    printf("=============================================================================\n");
    printf("Devices Found: %d\n", found);
    printf("Status: %s\n", found ? "THREATS DETECTED" : "NO ME DEVICES FOUND");
}

int main(int argc, char **argv) {
    int found_devices = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = true;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--silent") == 0) {
            opts.silent = true;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--aggressive") == 0) {
            opts.aggressive = true;
        }
    }
    
    print_banner();
    animate_scan();
    
#ifdef _WIN32
    found_devices = scan_windows_devices();
#else
    found_devices = scan_linux_devices();
#endif
    
    print_scan_complete(found_devices);
    
    if (!opts.silent) {
        printf("\n");
        printf("Resources:\n");
        printf("  https://github.com/corna/me_cleaner\n");
        printf("  https://security-center.intel.com\n");
        printf("  https://github.com/platomav/MEAnalyzer\n");
        printf("\n");
    }
    
    return found_devices > 0 ? 0 : 1;
}
