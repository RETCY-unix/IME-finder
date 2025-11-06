# **Intel Management Engine Security Analyzer**

ime\_analyzer is a read-only security auditing tool for **Linux**. It performs a security analysis of the Intel Management Engine (ME), Converged Security Management Engine (CSME), and Trusted Execution Engine (TXE) subsystems.

This tool scans the PCI bus directly to read the hardware's internal status registers. This provides an assessment of your ME's configuration to help determine if it is active, disabled, or in another state.

## **Detection Method**

Many tools check if an OS-level driver (like /dev/mei0) is loaded. This check may be insufficient, as the Intel ME can be operational without an OS driver.

This tool reads the ME\_REG\_HFS1 (0x40) hardware register directly. This allows it to check the hardware's reported status, including:

* Its current working state (e.g., NORMAL OPERATION).  
* If it is disabled via a hardware kill switch (the HAP\_DISABLE bit).  
* If it is in a recovery or error state.

## **Features**

* **Direct Hardware Analysis:** Reads the Host Firmware Status (HFS) registers directly from the PCI bus using libpci.  
* **State Detection:** Differentiates between the ME's "Working State" (e.g., NORMAL OPERATION) and its "Operation Mode" (e.g., HAP\_DISABLE).  
* **Risk Assessment:** Provides a **HIGH**, **MEDIUM**, or **LOW** risk assessment based on the hardware's state.  
* **HAP Bit Detection:** Correctly identifies if the ME is in a disabled state via the High Assurance Platform (ME\_OP\_MODE\_HAP\_DISABLE) bit.  
* **Device Database:** Includes a built-in database of known ME/CSME/TXE device IDs, from older chipsets (ME 7.x) to newer ones (CSME 16.x).  
* **AMD PSP Detection:** Will detect AMD CPUs and inform the user that they have a Platform Security Processor (PSP) instead.  
* **Mitigation Guide:** Prints a list of known mitigation strategies.  
* **Flexible Output:** Includes verbose (-v), JSON (-j), and silent (-s) output modes.

## **Requirements (Linux Only)**

This tool is for **Linux only**. It is not designed to work inside a virtual machine (like WSL), as it requires direct, bare-metal hardware access.

* gcc and build-essential (or equivalent)  
* libpci-dev (on Debian/Ubuntu) or pciutils-devel (on RHEL/Fedora)

## **Installation & Compilation**

1. **Install Dependencies:**  
   \# On Debian/Ubuntu/Mint  
   sudo apt-get install build-essential libpci-dev

   \# On Fedora/RHEL/CentOS  
   sudo dnf install gcc pciutils-devel

2. Save the Code:  
   Save the source code as ime\_analyzer.c.  
3. Compile:  
   Use the build command from the source file's comments:  
   gcc \-o ime\_analyzer ime\_analyzer.c \-lpci \-O2 \-Wall

## **Usage**

The tool **must** be run with root privileges (sudo) to read the PCI configuration space.

sudo ./ime\_analyzer

### **Options**

| Flag | Long Flag | Description |
| :---- | :---- | :---- |
| \-v | \--verbose | Enable detailed register dumps for all 6 HFS registers. |
| \-j | \--json | Output results in JSON format (useful for scripting). |
| \-s | \--silent | Minimal output mode. |
| \-h | \--help | Show this help message. |

## **Interpreting the Output**

The tool provides a security risk assessment based on the detected hardware state:

### **Security Risk Assessment: HIGH**

This state indicates the Intel ME is **fully operational** in NORMAL OPERATION mode. This is the default configuration, where the subsystem has privileged access to system memory, network, and storage, independent of the OS.

### **Security Risk Assessment: MEDIUM**

This indicates a non-standard state, such as RECOVERY MODE. This may be a sign of firmware corruption or a failed update. The ME is not in a fully operational state.

### **Security Risk Assessment: LOW**

This indicates the ME is **disabled or in a limited state**. This state can be the result of the HAP\_DISABLE bit being set or other mitigations (like me\_cleaner) being applied.

### **No Intel ME... devices detected**

This result means the tool could not find a known Intel ME device on the PCI bus. This could mean:

1. The ME is disabled or neutered.  
2. The ME is hidden from OS enumeration.  
3. You have a **Non-Intel processor** (e.g., AMD).  
4. You are running this inside a **Virtual Machine**.

## **Disclaimer**

This tool performs **read-only operations** and will not modify your system.

However, the mitigation options it suggests (like using me\_cleaner or flashing firmware) are advanced procedures. These actions **carry a risk of permanently damaging ("bricking") your system** if performed incorrectly. Always back up your firmware and proceed with extreme caution.