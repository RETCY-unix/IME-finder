#include "ime_analyzer.h"
#include <stddef.h>

me_device_info_t me_devices[] = {
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
    {0xa75d, "Meteor Lake CSME", "Meteor Lake", "CSME 18.x", false},
    {0x0000, NULL, NULL, NULL, false}
};

const char* get_working_state_string(uint8_t state) {
    switch(state) {
        case ME_WORKING_STATE_RESET: return "RESET";
        case ME_WORKING_STATE_INIT: return "INITIALIZING";
        case ME_WORKING_STATE_RECOVERY: return "RECOVERY MODE";
        case ME_WORKING_STATE_DISABLED: return "PLATFORM DISABLED";
        case ME_WORKING_STATE_NORMAL: return "NORMAL OPERATION";
        case ME_WORKING_STATE_WAIT: return "WAITING";
        case ME_WORKING_STATE_TRANSITION: return "TRANSITIONING";
        default: return "UNKNOWN";
    }
}

const char* get_operation_mode_string(uint8_t mode) {
    switch(mode) {
        case ME_OP_MODE_NORMAL: return "Normal";
        case ME_OP_MODE_DEBUG: return "Debug";
        case ME_OP_MODE_SOFT_TEMP_DISABLE: return "Soft Temporary Disable";
        case ME_OP_MODE_SECOVR_JMPR: return "Security Override Jumper";
        case ME_OP_MODE_SECOVR_MSG: return "Security Override Message";
        case ME_OP_MODE_DAL: return "DAL";
        case ME_OP_MODE_ALT_DISABLE: return "AltMeDisable Bit Set";
        case ME_OP_MODE_HAP_DISABLE: return "HAP/AltMeDisable (High Assurance Platform)";
        default: return "Unknown";
    }
}

const char* get_risk_level(uint8_t working_state, uint8_t op_mode) {
    if (working_state == ME_WORKING_STATE_DISABLED ||
        working_state == ME_WORKING_STATE_WAIT ||
        op_mode == ME_OP_MODE_SOFT_TEMP_DISABLE ||
        op_mode == ME_OP_MODE_ALT_DISABLE ||
        op_mode == ME_OP_MODE_HAP_DISABLE) {
        return "MITIGATED";
    }
    if (working_state == ME_WORKING_STATE_RECOVERY) {
        return "ELEVATED";
    }
    if (working_state == ME_WORKING_STATE_NORMAL && op_mode == ME_OP_MODE_NORMAL) {
        return "CRITICAL";
    }
    return "ELEVATED";
}
