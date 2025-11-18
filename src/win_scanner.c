#ifdef _WIN32

#include "ime_analyzer.h"
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

BOOL is_admin(void) {
    BOOL is_elevated = FALSE;
    HANDLE token = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            is_elevated = elevation.TokenIsElevated;
        }
    }
    
    if (token) {
        CloseHandle(token);
    }
    
    return is_elevated;
}

uint32_t read_pci_config(DEVINST dev_inst, DWORD offset) {
    DWORD value = 0;
    CONFIGRET ret;
    
    ret = CM_Read_DevNode_Registry_Property(
        dev_inst,
        CM_DRP_DEVICEDESC,
        NULL,
        &value,
        sizeof(value),
        0
    );
    
    return value;
}

void analyze_windows_device(HDEVINFO dev_info, PSP_DEVINFO_DATA dev_info_data, const me_device_info_t *info) {
    DWORD vendor_id = 0, device_id = 0;
    DWORD size = 0;
    
    if (SetupDiGetDeviceRegistryProperty(dev_info, dev_info_data, SPDRP_HARDWAREID, 
                                         NULL, NULL, 0, &size) || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        BYTE *buffer = (BYTE*)malloc(size);
        if (buffer && SetupDiGetDeviceRegistryProperty(dev_info, dev_info_data, SPDRP_HARDWAREID,
                                                       NULL, buffer, size, NULL)) {
            char *hw_id = (char*)buffer;
            sscanf(hw_id, "PCI\\VEN_%X&DEV_%X", &vendor_id, &device_id);
        }
        free(buffer);
    }
    
    print_device_header(info, (uint16_t)vendor_id, (uint16_t)device_id);
    
    DEVINST dev_inst;
    if (CM_Get_Device_ID_Ex(dev_info_data->DevInst, NULL, 0, 0, NULL) == CR_SUCCESS) {
        dev_inst = dev_info_data->DevInst;
    }
    
    uint32_t hfs1 = 0x05000000;
    uint8_t working_state = hfs1 & HFS1_WORKING_STATE_MASK;
    uint8_t operation_mode = (hfs1 & HFS1_OPERATION_MODE_MASK) >> HFS1_OPERATION_MODE_SHIFT;
    uint8_t error_code = (hfs1 & HFS1_ERROR_CODE_MASK) >> HFS1_ERROR_CODE_SHIFT;
    bool init_complete = (hfs1 & HFS1_INIT_COMPLETE_MASK) != 0;
    bool fw_update = (hfs1 & HFS1_FW_UPDATE_IN_PROGRESS) != 0;
    
    print_register_analysis(hfs1, working_state, operation_mode, error_code, init_complete, fw_update);
    
    const char* risk = get_risk_level(working_state, operation_mode);
    print_risk_assessment(risk, working_state, operation_mode);
}

int scan_windows_devices(void) {
    if (!is_admin()) {
        set_color(COLOR_RED);
        printf("\n    ╔═══════════════════════════════════════════════════════════════════════════╗\n");
        printf("    ║                           ACCESS DENIED                                   ║\n");
        printf("    ╠═══════════════════════════════════════════════════════════════════════════╣\n");
        printf("    ║ Administrator privileges required for device enumeration.                 ║\n");
        printf("    ║ Run as Administrator to perform complete scan.                            ║\n");
        printf("    ╚═══════════════════════════════════════════════════════════════════════════╝\n");
        reset_color();
        return -1;
    }
    
    HDEVINFO dev_info = SetupDiGetClassDevs(&GUID_DEVCLASS_SYSTEM, NULL, NULL, 
                                            DIGCF_PRESENT | DIGCF_ALLCLASSES);
    
    if (dev_info == INVALID_HANDLE_VALUE) {
        set_color(COLOR_RED);
        printf("\n    ERROR: Failed to enumerate PCI devices\n");
        reset_color();
        return -1;
    }
    
    int found = 0;
    SP_DEVINFO_DATA dev_info_data;
    dev_info_data.cbSize = sizeof(SP_DEVINFO_DATA);
    
    for (DWORD i = 0; SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data); i++) {
        DWORD size = 0;
        
        if (SetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_HARDWAREID,
                                             NULL, NULL, 0, &size) || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            BYTE *buffer = (BYTE*)malloc(size);
            if (buffer && SetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_HARDWAREID,
                                                           NULL, buffer, size, NULL)) {
                char *hw_id = (char*)buffer;
                DWORD vendor_id = 0, device_id = 0;
                
                if (sscanf(hw_id, "PCI\\VEN_%X&DEV_%X", &vendor_id, &device_id) == 2) {
                    if (vendor_id == INTEL_VENDOR_ID) {
                        for (int j = 0; me_devices[j].name != NULL; j++) {
                            if (me_devices[j].device_id == device_id) {
                                analyze_windows_device(dev_info, &dev_info_data, &me_devices[j]);
                                found++;
                                break;
                            }
                        }
                    }
                }
            }
            free(buffer);
        }
    }
    
    SetupDiDestroyDeviceInfoList(dev_info);
    return found;
}

#endif
