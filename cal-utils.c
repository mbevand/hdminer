#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <cal.h>
#include <calcl.h>

#include "cal-utils.h"

void fatal(const char *func_name)
{
    const char *cal_msg = calGetErrorString();
    const char *comp_msg = calclGetErrorString();
    fprintf(stderr, "%s failed\ncal error: %s\ncalcl error: %s\n",
            func_name, cal_msg, comp_msg);
    // calGetErrorString error messages are prematurely truncated because of
    // stray NUL chars. print the message until 3 consecutive NUL chars are
    // encountered
    fprintf(stderr, "Full CAL error: ");
    for (int i = 0; i < 128; i++) {
        if (i > 1 && !cal_msg[i - 2] && !cal_msg[i - 1] && !cal_msg[i])
            break;
        if (cal_msg[i])
            fprintf(stderr, "%c", cal_msg[i]);
    }
    fprintf(stderr, "\n");
    exit(1);
}

void show_ver(void)
{
    CALuint major, minor, imp;
    if (CAL_RESULT_OK != calGetVersion(&major, &minor, &imp))
        fatal("calGetVersion");
    printf("CAL version %u.%u.%u\n", major, minor, imp);
}

const char *target_name(CALtarget target, CALuint revision)
{
    static char _out[128];
    char *name;
    switch (target) {
        case CAL_TARGET_600: name = "R600 GPU"; break;
        case CAL_TARGET_610: name = "RV610 GPU"; break;
        case CAL_TARGET_630: name = "RV630 GPU"; break;
        case CAL_TARGET_670: name = "RV670 GPU"; break;
        case CAL_TARGET_7XX: name = "R700 class GPU"; break;
        case CAL_TARGET_770: name = "RV770 GPU"; break;
        case CAL_TARGET_710: name = "RV710 GPU"; break;
        case CAL_TARGET_730: name = "RV730 GPU"; break;
        case CAL_TARGET_CYPRESS: name = "Cypress GPU"; break;
        case CAL_TARGET_JUNIPER: name = "Juniper GPU"; break;
        case CAL_TARGET_REDWOOD: name = "Redwood GPU"; break;
        case CAL_TARGET_CEDAR: name = "Cedar GPU"; break;
        default: name = "unknown"; break;
    }
    sprintf(_out, "%s (target %u rev %u)", name, target, revision);
    return _out;
}

void display_attribs(CALdeviceattribs *a)
{
    printf(
            "target                %u\n"
            "localRAM              %u MB\n"
            "uncachedRemoteRAM     %u MB\n"
            "cachedRemoteRAM       %u MB\n"
            "engineClock           %u MHz\n"
            "memoryClock           %u MHz\n"
            "wavefrontSize         %u\n"
            "numberOfSIMD          %u\n"
            "doublePrecision       %u\n"
            "localDataShare        %u\n"
            "globalDataShare       %u\n"
            "globalGPR             %u\n"
            "computeShader         %u\n"
            "memExport             %u\n"
            "pitch_alignment       %u\n"
            "surface_alignment     %u\n"
            "numberOfUAVs          %u\n"
            "bUAVMemExport         %u\n"
            "b3dProgramGrid        %u\n"
            "numberOfShaderEngines %u\n"
            "targetRevision        %u\n"
            , a->target, a->localRAM, a->uncachedRemoteRAM, a->cachedRemoteRAM,
        a->engineClock, a->memoryClock, a->wavefrontSize, a->numberOfSIMD,
        a->doublePrecision, a->localDataShare, a->globalDataShare,
        a->globalGPR, a->computeShader, a->memExport, a->pitch_alignment,
        a->surface_alignment, a->numberOfUAVs, a->bUAVMemExport,
        a->b3dProgramGrid, a->numberOfShaderEngines, a->targetRevision);
}

static void advance(char **area, unsigned *remaining, const char *marker)
{
    char *find = memmem(*area, *remaining, marker, strlen(marker));
    if (!find)
        fprintf(stderr, "Marker \"%s\" not found\n", marker), exit(1);
    *remaining -= find - *area;
    *area = find;
}

static void patch_opcodes(int verbose, char *w, unsigned remaining,
        int expected_min, int expected_max)
{
    uint64_t *opcode = (uint64_t *)w;
    int patched = 0;
    int count_bfe_int = 0;
    int count_bfe_uint = 0;
    int count_byte_align = 0;
    while (42)
      {
        int clamp = (*opcode >> (32 + 31)) & 0x1;
        //int dest_chan = (*opcode >> (32 + 29)) & 0x3;
        int dest_rel = (*opcode >> (32 + 28)) & 0x1;
        //int bank_swizzle = (*opcode >> (32 + 18)) & 0x7;
        int alu_inst = (*opcode >> (32 + 13)) & 0x1f;
        int s2_neg = (*opcode >> (32 + 12)) & 0x1;
        //int s2_chan = (*opcode >> (32 + 10)) & 0x3;
        int s2_rel = (*opcode >> (32 + 9)) & 0x1;
        //int s2_sel = (*opcode >> (32 + 0)) & 0x1ff;
        //int last = (*opcode >> 31) & 0x1;
        int pred_sel = (*opcode >> 29) & 0x3;
        int index_mode = (*opcode >> 26) & 0x7;
        int s1_neg = (*opcode >> 25) & 0x1;
        //int s1_chan = (*opcode >> 23) & 0x3;
        int s1_rel = (*opcode >> 22) & 0x1;
        //int s1_sel = (*opcode >> 13) & 0x1ff;
        int s0_neg = (*opcode >> 12) & 0x1;
        //int s0_chan = (*opcode >> 10) & 0x3;
        int s0_rel = (*opcode >> 9) & 0x1;
        //int s0_sel = (*opcode >> 0) & 0x1ff;
        if (!clamp && !dest_rel && !s2_neg && !s2_rel && !pred_sel &&
                !index_mode && !s1_neg && !s1_rel && !s0_neg && !s0_rel) {
            if (alu_inst == OP3_INST_BFE_INT) {
                count_bfe_int++;
                // patch this instruction to BFI_INT
                *opcode &= 0xfffc1fffffffffffUL;
                *opcode |= OP3_INST_BFI_INT << (32 + 13);
                patched++;
            } else if (alu_inst == OP3_INST_BFE_UINT) {
                count_bfe_uint++;
            } else if (alu_inst == OP3_INST_BYTE_ALIGN_INT) {
                count_byte_align++;
            }
        }
        if (remaining <= 8) {
            break;
        }
        opcode++;
        remaining -= 8;
      }
    if (verbose > 1)
        printf("Potential OP3 instructions identified: "
                "%i BFE_INT, %i BFE_UINT, %i BYTE_ALIGN\n",
                count_bfe_int, count_bfe_uint, count_byte_align);
    if (verbose)
        printf("Patched a total of %i BFI_INT instructions\n", patched);
    if (patched < expected_min || patched > expected_max)
        fprintf(stderr, "Error: patched %i instructions, was expecting %i-%i\n",
                patched, expected_min, expected_max), exit(1);
}

/*
 * Patches ibit_extract/BFE_INT opcodes to BFI_INT.
 *
 * Note: BEWARE of IL compiler optimizations. Only use a fake ibit_extract
 * when the register values cannot be known by the compiler.
 *
 * Requires the IL code to have a comment near the end of "_the_end_".
 *
 * BFI_INT src0=mask  src1=data_if_mask_1 src2=data_of_mask_0
 * BFE_INT src0=input src1=offset         src2=width
 * ibit_extract dst, width, offset, input
 * <virtualbfi> dst, data_if_mask_0, data_if_mask_1, mask
 *
 * verbose       Non-zero increases verbosity
 * obj           ELF CALobject to patch
 * bytes_to_scan Number of bytes to assume the ELF CALobject contains
 * expected_min  Min number of BFE_INT instr. that were expected to be patched
 * expected_max  Max number of BFE_INT instr. that were expected to be patched
 */
void patch_bfi_int_instructions(int verbose, CALobject *obj,
        unsigned bytes_to_scan, int expected_min, int expected_max)
{
    if (verbose > 1)
        printf("Patching BFI_INT instructions into the binary CAL object...\n");
    if (0) {
        int fd = open("obj.elf", O_CREAT|O_WRONLY|O_TRUNC, 0666);
        if (fd == -1)
            perror("obj.elf"), exit(1);
        if (-1 == write(fd, *obj, bytes_to_scan))
	    perror("write"), exit(1);
        close(fd);
    }
    unsigned remaining = bytes_to_scan;
    char *w = (void *)*obj;
    if (verbose > 1)
        printf("At %p (%u rem. bytes), searching end marker\n", w, remaining);
    advance(&w, &remaining, "_the_end_");
    // advance until the 17th "ATI CAL" marker is encountered
    const int ati_cal_markers = 17;
    for (int i = 0; i < ati_cal_markers; i++) {
        if (verbose > 1)
            printf("At %p (%u rem. bytes), searching ATI CAL marker %i\n",
                    w, remaining, i);
        advance(&w, &remaining, "ATI CAL");
        if (remaining < 1)
            fprintf(stderr, "Only %u rem. bytes\n", remaining), exit(1);
        w++; remaining--;
    }
    if (remaining < 11)
        fprintf(stderr, "Only %u rem. bytes\n", remaining), exit(1);
    w += 11; remaining -= 11;
    // now we are pointing to the first opcode
    patch_opcodes(verbose, w, remaining, expected_min, expected_max);
}
