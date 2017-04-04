/*
 * Opcodes of instructions in ALU_WORD1_OP3 (taken from the Evergreen Family
 * Instruction Set Architecture Instructions and Microcode PDF).
 */
#define OP3_INST_BFE_UINT	4UL
#define OP3_INST_BFE_INT	5UL
#define OP3_INST_BFI_INT	6UL
#define OP3_INST_BIT_ALIGN_INT	12UL
#define OP3_INST_BYTE_ALIGN_INT	13UL

void fatal(const char *func_name);
void show_ver(void);
const char *target_name(CALtarget target, CALuint revision);
void display_attribs(CALdeviceattribs *a);
void patch_bfi_int_instructions(int verbose, CALobject *obj,
        unsigned bytes_to_scan, int expected_min, int expected_max);
