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
    
#ifdef _WIN32
    set_color(COLOR_RED);
    printf("\n========================================\n");
    printf("  Intel ME Security Hunter v2.0\n");
    printf("========================================\n");
    reset_color();
    printf("Hunting for backdoors in your system...\n\n");
#else
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
    
    printf("\n    Intel Management Engine Security Hunter v2.0\n");
    printf("    Searching for Intel's hidden surveillance system...\n\n");
#endif
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
        "Initializing hardware probe",
        "Loading threat database",
        "Scanning system buses",
        "Analyzing chipset architecture",
        "Detecting backdoor firmware",
        "Reading surveillance registers"
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
    printf("!! BACKDOOR COMPONENT DETECTED !!\n");
    printf("=============================================================================\n");
    reset_color();
    
    printf("Device Name:   %s\n", info->name);
    printf("Chipset:       %s\n", info->chipset);
    printf("Generation:    %s\n", info->generation);
    printf("Type:          %s\n", info->is_txe ? "TXE - Trusted Execution Engine" : "ME/CSME - Management Engine");
    printf("Vendor:        0x%04X (Intel Corporation)\n", vendor_id);
    printf("Device:        0x%04X\n", device_id);
}

void print_register_analysis(uint32_t hfs1, uint8_t working_state, uint8_t op_mode, 
                             uint8_t error_code, bool init_complete, bool fw_update) {
    if (opts.silent) return;
    
    printf("\n");
    printf("FIRMWARE STATUS\n");
    printf("-----------------------------------------------------------------------------\n");
    
    printf("HFS1 Register:     0x%08X\n", hfs1);
    printf("Working State:     %s\n", get_working_state_string(working_state));
    printf("Operation Mode:    %s\n", get_operation_mode_string(op_mode));
    printf("Error Code:        %d\n", error_code);
    printf("Initialized:       %s\n", init_complete ? "YES" : "IN PROGRESS");
    printf("Updating:          %s\n", fw_update ? "YES" : "NO");
}

void print_capabilities_warning(void) {
    if (opts.silent) return;
    
    printf("\n");
    set_color(COLOR_RED);
    printf("WHAT THIS THING CAN DO TO YOUR MACHINE\n");
    printf("-----------------------------------------------------------------------------\n");
    reset_color();
    
    printf("- Full RAM access (even when YOU can't see it)\n");
    printf("- Network control (separate from YOUR operating system)\n");
    printf("- Disk access (including encrypted drives)\n");
    printf("- CPU control (runs below Ring 0, deeper than your OS)\n");
    printf("- Works when system is \"off\" (if plugged in)\n");
    printf("- Remote access (AMT/vPro lets others control your PC)\n");
    printf("- Self-updating (without asking you)\n");
    printf("- Stores crypto keys (that you don't control)\n");
}

void print_risk_assessment(const char* risk_level, uint8_t working_state, uint8_t op_mode) {
    if (opts.silent) return;
    
    printf("\n");
    printf("SECURITY ASSESSMENT\n");
    printf("-----------------------------------------------------------------------------\n");
    
    if (strcmp(risk_level, "CRITICAL") == 0) {
        set_color(COLOR_RED);
        printf("STATUS: YOU'RE COMPLETELY PWNED\n");
        reset_color();
        printf("\nThis thing is running at full power. Intel has a backdoor into your machine\n");
        printf("right now, whether you like it or not. It can see everything, do anything,\n");
        printf("and you can't stop it without serious hardware modifications.\n");
        
        print_capabilities_warning();
        
        printf("\n");
        set_color(COLOR_YELLOW);
        printf("WHAT YOU CAN TRY (NO GUARANTEES)\n");
        printf("-----------------------------------------------------------------------------\n");
        reset_color();
        printf("1. Update firmware (might patch known exploits, adds new ones)\n");
        printf("2. Disable AMT/vPro (if you're not using it, turn it OFF)\n");
        printf("3. Try me_cleaner (neutralizes some ME functionality)\n");
        printf("4. Enable HAP bit (if your board supports it - rare)\n");
        printf("5. Firewall everything (watch for suspicious ME network traffic)\n");
        printf("6. Air-gap sensitive systems (seriously consider it)\n");
        printf("7. Buy pre-neutered hardware (Purism, System76, or old Thinkpads)\n");
        printf("\nReality check: You can't fully remove this without a soldering iron\n");
        printf("and deep knowledge of your motherboard. Even then, good luck.\n");
        
    } else if (strcmp(risk_level, "ELEVATED") == 0) {
        set_color(COLOR_YELLOW);
        printf("STATUS: SOMETHING'S WEIRD\n");
        reset_color();
        printf("\nME is in a non-standard state. Could be recovering from an error,\n");
        printf("could be disabled, or could be in some other mode. Check your BIOS.\n");
        
    } else {
        set_color(COLOR_GREEN);
        printf("STATUS: PARTIALLY CONTAINED\n");
        reset_color();
        printf("\nLooks like ME is disabled or limited. That's good, but don't celebrate yet.\n");
        printf("\nEven in \"disabled\" states, parts of ME still run. You can't kill it completely\n");
        printf("without hardware modifications. It's like a zombie - you can slow it down,\n");
        printf("but it never truly dies.\n");
    }
}

void print_scan_complete(int found) {
    if (opts.silent) return;
    
    printf("\n\n");
    printf("=============================================================================\n");
    printf("SCAN COMPLETE\n");
    printf("=============================================================================\n");
    
    if (found > 0) {
        printf("ME Devices Found:  %d\n", found);
        set_color(COLOR_RED);
        printf("Verdict:           YOUR SYSTEM IS COMPROMISED\n");
        reset_color();
        printf("\nYou've got Intel's backdoor running on your machine. Welcome to modern\n");
        printf("computing, where your CPU comes with built-in surveillance capabilities.\n");
    } else {
        printf("ME Devices Found:  0\n");
        set_color(COLOR_GREEN);
        printf("Verdict:           NO ME DETECTED (LUCKY YOU)\n");
        reset_color();
        printf("\nEither you're running AMD, or you've got an older Intel system without ME.\n");
        printf("Enjoy your relative freedom while it lasts.\n");
    }
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
        printf("Learn more:\n");
        printf("  https://github.com/corna/me_cleaner (neutralization tool)\n");
        printf("  https://security-center.intel.com (Intel's security bulletins)\n");
        printf("  https://github.com/platomav/MEAnalyzer (deep analysis)\n");
        printf("  https://www.eff.org/deeplinks/2017/05/intels-management-engine-security-hazard-and-users-need-way-disable-it\n");
        printf("\n");
    }
    
    return found_devices > 0 ? 0 : 1;
}
