#ifndef IME_ANALYZER_H
#define IME_ANALYZER_H

#include <stdint.h>
#include <stdbool.h>

#define INTEL_VENDOR_ID 0x8086
#define AMD_VENDOR_ID 0x1022

#define ME_REG_HFS1 0x40
#define ME_REG_HFS2 0x48
#define ME_REG_HFS3 0x60
#define ME_REG_HFS4 0x64
#define ME_REG_HFS5 0x68
#define ME_REG_HFS6 0x6C

#define HFS1_WORKING_STATE_MASK 0x0000000F
#define HFS1_OPERATION_MODE_MASK 0x000F0000
#define HFS1_OPERATION_MODE_SHIFT 16
#define HFS1_ERROR_CODE_MASK 0x0000F000
#define HFS1_ERROR_CODE_SHIFT 12
#define HFS1_INIT_COMPLETE_MASK 0x00000200
#define HFS1_FW_UPDATE_IN_PROGRESS 0x00000040

#ifdef _WIN32
#define COLOR_RED 12
#define COLOR_GREEN 10
#define COLOR_YELLOW 14
#define COLOR_BLUE 9
#define COLOR_MAGENTA 13
#define COLOR_CYAN 11
#define COLOR_WHITE 15
#define COLOR_RESET 7
#else
#define COLOR_RED 1
#define COLOR_GREEN 2
#define COLOR_YELLOW 3
#define COLOR_BLUE 4
#define COLOR_MAGENTA 5
#define COLOR_CYAN 6
#define COLOR_WHITE 7
#define COLOR_RESET 0
#endif

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

typedef struct {
    bool verbose;
    bool json;
    bool silent;
    bool aggressive;
} options_t;

extern me_device_info_t me_devices[];

void set_color(int color);
void reset_color(void);
void print_banner(void);
void print_progress_bar(int percentage);
void animate_scan(void);
void print_device_header(const me_device_info_t *info, uint16_t vendor_id, uint16_t device_id);
void print_register_analysis(uint32_t hfs1, uint8_t working_state, uint8_t op_mode, 
                             uint8_t error_code, bool init_complete, bool fw_update);
void print_risk_assessment(const char* risk_level, uint8_t working_state, uint8_t op_mode);
const char* get_working_state_string(uint8_t state);
const char* get_operation_mode_string(uint8_t mode);
const char* get_risk_level(uint8_t working_state, uint8_t op_mode);

#ifdef _WIN32
int scan_windows_devices(void);
#else
int scan_linux_devices(void);
#endif

#endif
