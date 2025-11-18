#include "ime_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
// Note: setupapi.lib and cfgmgr32.lib are linked via compiler flags, not pragma
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
    
    set_color(COLOR_YELLOW);
    printf("\n    ╔═══════════════════════════════════════════════════════════════════════════╗\n");
    printf("    ║         INTEL MANAGEMENT ENGINE THREAT DETECTION SYSTEM v2.0              ║\n");
    printf("    ║              UNAUTHORIZED ACCESS MAY BE MONITORED                         ║\n");
    printf("    ╚═══════════════════════════════════════════════════════════════════════════╝\n");
    reset_color();
    printf("\n");
}

void print_progress_bar(int percentage) {
    if (opts.silent) return;
    
    int bar_width = 50;
    int filled = (bar_width * percentage) / 100;
    
    set_color(COLOR_CYAN);
    printf("\r    [");
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) {
            printf("█");
        } else {
            printf("░");
        }
    }
    printf("] %3d%%", percentage);
    reset_color();
    fflush(stdout);
}

void animate_scan(void) {
    if (opts.silent) return;
    
    const char* stages[] = {
        "INITIALIZING SCAN ENGINE",
        "LOADING PCI DEVICE DATABASE",
        "PROBING SYSTEM BUSES",
        "ANALYZING CHIPSET",
        "DETECTING ME FIRMWARE",
        "READING SECURITY REGISTERS"
    };
    
    for (int i = 0; i < 6; i++) {
        set_color(COLOR_YELLOW);
        printf("\n    ⚡ %s", stages[i]);
        reset_color();
        
        for (int j = 0; j < 4; j++) {
            printf(".");
            fflush(stdout);
            sleep_ms(150);
        }
        
        set_color(COLOR_GREEN);
        printf(" ✓\n");
        reset_color();
    }
    printf("\n");
}

void print_threat_box(const char* level, const char* message, int color) {
    if (opts.silent) return;
    
    set_color(color);
    printf("\n    ╔═══════════════════════════════════════════════════════════════════════════╗\n");
    printf("    ║ THREAT LEVEL: %-60s ║\n", level);
    printf("    ╠═══════════════════════════════════════════════════════════════════════════╣\n");
    printf("    ║ %-73s ║\n", message);
    printf("    ╚═══════════════════════════════════════════════════════════════════════════╝\n");
    reset_color();
}

void print_device_header(const me_device_info_t *info, uint16_t vendor_id, uint16_t device_id) {
    if (opts.silent) return;
    
    set_color(COLOR_RED);
    printf("\n    ╔═══════════════════════════════════════════════════════════════════════════╗\n");
    printf("    ║                    ⚠️  HOSTILE SUBSYSTEM DETECTED  ⚠️                      ║\n");
    printf("    ╚═══════════════════════════════════════════════════════════════════════════╝\n");
    reset_color();
    
    printf("\n");
    set_color(COLOR_YELLOW);
    printf("    ┌───────────────────────────────────────────────────────────────────────────┐\n");
    printf("    │ DEVICE CLASSIFICATION                                                     │\n");
    printf("    ├───────────────────────────────────────────────────────────────────────────┤\n");
    reset_color();
    
    printf("    │ Name         : ");
    set_color(COLOR_WHITE);
    printf("%-59s", info->name);
    reset_color();
    printf("│\n");
    
    printf("    │ Chipset      : ");
    set_color(COLOR_WHITE);
    printf("%-59s", info->chipset);
    reset_color();
    printf("│\n");
    
    printf("    │ Generation   : ");
    set_color(COLOR_WHITE);
    printf("%-59s", info->generation);
    reset_color();
    printf("│\n");
    
    printf("    │ Type         : ");
    set_color(info->is_txe ? COLOR_MAGENTA : COLOR_RED);
    printf("%-59s", info->is_txe ? "TXE - Trusted Execution Engine" : "ME/CSME - Management Engine");
    reset_color();
    printf("│\n");
    
    printf("    │ Vendor ID    : ");
    set_color(COLOR_WHITE);
    printf("0x%04X (Intel Corporation)                                      ", vendor_id);
    reset_color();
    printf("│\n");
    
    printf("    │ Device ID    : ");
    set_color(COLOR_WHITE);
    printf("0x%04X                                                          ", device_id);
    reset_color();
    printf("│\n");
    
    set_color(COLOR_YELLOW);
    printf("    └───────────────────────────────────────────────────────────────────────────┘\n");
    reset_color();
}

void print_register_analysis(uint32_t hfs1, uint8_t working_state, uint8_t op_mode, 
                             uint8_t error_code, bool init_complete, bool fw_update) {
    if (opts.silent) return;
    
    printf("\n");
    set_color(COLOR_CYAN);
    printf("    ┌───────────────────────────────────────────────────────────────────────────┐\n");
    printf("    │ FIRMWARE STATUS REGISTER ANALYSIS                                         │\n");
    printf("    ├───────────────────────────────────────────────────────────────────────────┤\n");
    reset_color();
    
    printf("    │ HFS1 Register    : ");
    set_color(COLOR_WHITE);
    printf("0x%08X                                                ", hfs1);
    reset_color();
    printf("│\n");
    
    printf("    │ Working State    : ");
    int state_color = (working_state == ME_WORKING_STATE_NORMAL) ? COLOR_RED : COLOR_GREEN;
    set_color(state_color);
    printf("%-59s", get_working_state_string(working_state));
    reset_color();
    printf("│\n");
    
    printf("    │ Operation Mode   : ");
    int mode_color = (op_mode == ME_OP_MODE_NORMAL) ? COLOR_RED : COLOR_GREEN;
    set_color(mode_color);
    printf("%-59s", get_operation_mode_string(op_mode));
    reset_color();
    printf("│\n");
    
    printf("    │ Error Code       : ");
    set_color(error_code ? COLOR_YELLOW : COLOR_WHITE);
    printf("%-59d", error_code);
    reset_color();
    printf("│\n");
    
    printf("    │ Initialization   : ");
    set_color(init_complete ? COLOR_RED : COLOR_YELLOW);
    printf("%-59s", init_complete ? "COMPLETE - SYSTEM COMPROMISED" : "IN PROGRESS");
    reset_color();
    printf("│\n");
    
    printf("    │ Firmware Update  : ");
    set_color(fw_update ? COLOR_YELLOW : COLOR_WHITE);
    printf("%-59s", fw_update ? "IN PROGRESS" : "INACTIVE");
    reset_color();
    printf("│\n");
    
    set_color(COLOR_CYAN);
    printf("    └───────────────────────────────────────────────────────────────────────────┘\n");
    reset_color();
}

void print_capabilities_warning(void) {
    if (opts.silent) return;
    
    printf("\n");
    set_color(COLOR_RED);
    printf("    ╔═══════════════════════════════════════════════════════════════════════════╗\n");
    printf("    ║                      SUBSYSTEM CAPABILITIES DETECTED                      ║\n");
    printf("    ╠═══════════════════════════════════════════════════════════════════════════╣\n");
    reset_color();
    
    const char* capabilities[] = {
        "► UNRESTRICTED MEMORY ACCESS (Ring -3 Privilege)",
        "► NETWORK INTERFACE CONTROL (Out-of-Band)",
        "► PERSISTENT STORAGE ACCESS (Disk Encryption Keys)",
        "► CPU EXECUTION MONITORING (System Management Mode)",
        "► OPERATES WHILE SYSTEM POWERED OFF (Deep Sleep Active)",
        "► REMOTE MANAGEMENT CAPABILITIES (AMT/vPro)",
        "► FIRMWARE UPDATE MECHANISM (Autonomous)",
        "► CRYPTOGRAPHIC KEY STORAGE (Hardware Root of Trust)"
    };
    
    for (int i = 0; i < 8; i++) {
        set_color(COLOR_RED);
        printf("    ║ %-73s ║\n", capabilities[i]);
    }
    
    set_color(COLOR_RED);
    printf("    ╚═══════════════════════════════════════════════════════════════════════════╝\n");
    reset_color();
}

void print_risk_assessment(const char* risk_level, uint8_t working_state, uint8_t op_mode) {
    if (opts.silent) return;
    
    printf("\n");
    
    if (strcmp(risk_level, "CRITICAL") == 0) {
        set_color(COLOR_RED);
        printf("    ╔═══════════════════════════════════════════════════════════════════════════╗\n");
        printf("    ║  ██████╗██████╗ ██╗████████╗██╗ ██████╗ █████╗ ██╗                       ║\n");
        printf("    ║ ██╔════╝██╔══██╗██║╚══██╔══╝██║██╔════╝██╔══██╗██║                       ║\n");
        printf("    ║ ██║     ██████╔╝██║   ██║   ██║██║     ███████║██║                       ║\n");
        printf("    ║ ██║     ██╔══██╗██║   ██║   ██║██║     ██╔══██║██║                       ║\n");
        printf("    ║ ╚██████╗██║  ██║██║   ██║   ██║╚██████╗██║  ██║███████╗                  ║\n");
        printf("    ║  ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝                  ║\n");
        printf("    ╠═══════════════════════════════════════════════════════════════════════════╣\n");
        printf("    ║ INTEL ME IS FULLY OPERATIONAL - MAXIMUM THREAT CONDITION                 ║\n");
        printf("    ╚═══════════════════════════════════════════════════════════════════════════╝\n");
        reset_color();
        
        print_capabilities_warning();
        
        printf("\n");
        set_color(COLOR_YELLOW);
        printf("    ╔═══════════════════════════════════════════════════════════════════════════╗\n");
        printf("    ║                         IMMEDIATE ACTIONS REQUIRED                        ║\n");
        printf("    ╠═══════════════════════════════════════════════════════════════════════════╣\n");
        printf("    ║ 1. CHECK FOR CRITICAL FIRMWARE VULNERABILITIES                           ║\n");
        printf("    ║ 2. DISABLE AMT/vPro IF NOT REQUIRED FOR OPERATIONS                       ║\n");
        printf("    ║ 3. CONSIDER me_cleaner FOR FIRMWARE NEUTRALIZATION                       ║\n");
        printf("    ║ 4. ENABLE HAP BIT IF PLATFORM SUPPORTS THIS FEATURE                      ║\n");
        printf("    ║ 5. MONITOR ALL NETWORK TRAFFIC FOR UNAUTHORIZED ME ACTIVITY              ║\n");
        printf("    ║ 6. IMPLEMENT NETWORK SEGMENTATION AND FIREWALL RULES                     ║\n");
        printf("    ║ 7. CONSIDER HARDWARE REPLACEMENT WITH PRE-NEUTERED SYSTEMS               ║\n");
        printf("    ╚═══════════════════════════════════════════════════════════════════════════╝\n");
        reset_color();
        
    } else if (strcmp(risk_level, "ELEVATED") == 0) {
        set_color(COLOR_YELLOW);
        printf("    ╔═══════════════════════════════════════════════════════════════════════════╗\n");
        printf("    ║ ███████╗██╗     ███████╗██╗   ██╗ █████╗ ████████╗███████╗██████╗        ║\n");
        printf("    ║ ██╔════╝██║     ██╔════╝██║   ██║██╔══██╗╚══██╔══╝██╔════╝██╔══██╗       ║\n");
        printf("    ║ █████╗  ██║     █████╗  ██║   ██║███████║   ██║   █████╗  ██║  ██║       ║\n");
        printf("    ║ ██╔══╝  ██║     ██╔══╝  ╚██╗ ██╔╝██╔══██║   ██║   ██╔══╝  ██║  ██║       ║\n");
        printf("    ║ ███████╗███████╗███████╗ ╚████╔╝ ██║  ██║   ██║   ███████╗██████╔╝       ║\n");
        printf("    ║ ╚══════╝╚══════╝╚══════╝  ╚═══╝  ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═════╝        ║\n");
        printf("    ╠═══════════════════════════════════════════════════════════════════════════╣\n");
        printf("    ║ ME DETECTED IN NON-STANDARD STATE - VERIFY CONFIGURATION                 ║\n");
        printf("    ╚═══════════════════════════════════════════════════════════════════════════╝\n");
        reset_color();
        
    } else {
        set_color(COLOR_GREEN);
        printf("    ╔═══════════════════════════════════════════════════════════════════════════╗\n");
        printf("    ║ ███╗   ███╗██╗████████╗██╗ ██████╗  █████╗ ████████╗███████╗██████╗      ║\n");
        printf("    ║ ████╗ ████║██║╚══██╔══╝██║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝██╔══██╗     ║\n");
        printf("    ║ ██╔████╔██║██║   ██║   ██║██║  ███╗███████║   ██║   █████╗  ██║  ██║     ║\n");
        printf("    ║ ██║╚██╔╝██║██║   ██║   ██║██║   ██║██╔══██║   ██║   ██╔══╝  ██║  ██║     ║\n");
        printf("    ║ ██║ ╚═╝ ██║██║   ██║   ██║╚██████╔╝██║  ██║   ██║   ███████╗██████╔╝     ║\n");
        printf("    ║ ╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═════╝      ║\n");
        printf("    ╠═══════════════════════════════════════════════════════════════════════════╣\n");
        printf("    ║ ME APPEARS DISABLED OR LIMITED - REDUCED THREAT LEVEL                    ║\n");
        printf("    ╚═══════════════════════════════════════════════════════════════════════════╝\n");
        reset_color();
        
        printf("\n");
        set_color(COLOR_CYAN);
        printf("    NOTE: Even in disabled states, ME may retain basic functionality.\n");
        printf("    Complete removal impossible without hardware modification.\n");
        reset_color();
    }
}

void print_scan_complete(int found) {
    if (opts.silent) return;
    
    printf("\n\n");
    set_color(COLOR_CYAN);
    printf("    ╔═══════════════════════════════════════════════════════════════════════════╗\n");
    printf("    ║                          SCAN COMPLETE                                    ║\n");
    printf("    ╠═══════════════════════════════════════════════════════════════════════════╣\n");
    printf("    ║ Devices Found: %-58d ║\n", found);
    printf("    ║ Status: %-66s ║\n", found ? "THREATS DETECTED" : "NO ME DEVICES FOUND");
    printf("    ╚═══════════════════════════════════════════════════════════════════════════╝\n");
    reset_color();
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
    
    if (!opts.silent) {
        set_color(COLOR_YELLOW);
        printf("    Initializing security analysis engine...\n");
        reset_color();
        sleep_ms(500);
    }
    
    animate_scan();
    
#ifdef _WIN32
    found_devices = scan_windows_devices();
#else
    found_devices = scan_linux_devices();
#endif
    
    print_scan_complete(found_devices);
    
    if (!opts.silent) {
        printf("\n");
        set_color(COLOR_MAGENTA);
        printf("    Intel ME Security Resources:\n");
        printf("    ► https://github.com/corna/me_cleaner\n");
        printf("    ► https://security-center.intel.com\n");
        printf("    ► https://github.com/platomav/MEAnalyzer\n");
        reset_color();
        printf("\n");
    }
    
    return found_devices > 0 ? 0 : 1;
}
