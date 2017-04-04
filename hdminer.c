#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <cal.h>
#include <calcl.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include <pthread.h>
#include <jansson.h>

#include "cal-utils.h"
#include "miner-utils.h"
#include "kernel-sha256.h"

// hardcoded limit of 64*128 = 8192 GPUs.
// Moore's law: this won't be sufficient after around 2025.
uint64_t gpuset[128];

const char *auth = "bitcoin:password";
int disassemble_target = -1;
unsigned max_gpus = 0;
const char *server = "localhost";
unsigned iterations = 0x1000;
unsigned port = 8332;
int threads_per_grp = 320;
int verbose = 0;
const unsigned show_stats_every_x_ms = 1000;
uint32_t k_constants[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
int pipefd[2];
uint8_t target[32];
// Kernel is about 140kB, but scan for more bytes due to incertitude of
// the exact ELF layout.
const unsigned bytes_to_patch = 220000;
// Number of instruction patched should be at most 8 (elements) * 64 (rounds) *
// 2 (SHA-256 hash) but it is less because the CAL compiler optimizes out some
// computations.
const int expected_patched_instr_min = 950;
const int expected_patched_instr_max = 1024;
char *rpc_url = NULL;

const uint8_t s_searching = 0; // still searching this data block
const uint8_t s_found = 1;     // found a target hash
const uint8_t s_finished = 2;  // finished searching this data block

typedef struct
{
    uint8_t	status;
    uint8_t	_unused0[3];
    uint32_t	cur_nonce;
    uint32_t	end_nonce;
    uint32_t	_unused1;
} __attribute__((packed))	elm_state_t;

typedef struct
{
    // each thread works on 4 IL elements (1 set of x,y,z,w)
#define ELM_PER_THREAD	4 // keep in sync with elm_per_threads in Perl code
    elm_state_t	elm[ELM_PER_THREAD];
} __attribute__((packed))	thread_state_t;

typedef struct
{
    unsigned		nr_simds;
    bool		used;
    int			nr_threads;
    CALtarget		target;
    CALimage		img;
    CALdevice		device;
    CALcontext		ctx;
    CALmodule		module;
    CALresource		globalRes;
    CALmem		globalMem;
    CALresource		constRes;
    CALmem		constMem;
    CALprogramGrid	pg;
    CALevent		e;
    bool		have_run;
    struct timeval	tv_start;
    struct timeval	tv_end;
    int			last_mhashpsec;
    uint32_t		datawords[32];
    uint32_t		midstate[8];
    CALimage		next_img;
    uint32_t		next_datawords[32];
    uint32_t		next_midstate[8];
}		gpu_state_t;

enum iid
{
    CREATE_NEXT_WORK_ITEM,
    VERIFY_POTENTIAL_FIND,
};

typedef struct
{
    enum iid    id;
    CALuint     devi;
    // used by CREATE_NEXT_WORK_ITEM
    gpu_state_t *gs;
    // used by VERIFY_POTENTIAL_FIND
    uint32_t	datawords[32];
    uint32_t	nonce;
}               instr_t;

/**
** Returns true iff the user selected running on this GPU device.
*/
static bool run_on_gpu(CALuint n)
{
    const size_t elmbits = 8 * sizeof (*gpuset);
    return gpuset[n / elmbits] & (1L << (n % elmbits));
}

/**
** Initializes the global gpuset. Enable all GPUs if the param is not specified.
*/
static void init_gpuset(const char *gpuset_str)
{
    if (!gpuset_str)
      {
	memset(gpuset, 0xff, sizeof (gpuset));
	return;
      }
    const char *cur = gpuset_str;
    char *end;
    const size_t elmbits = 8 * sizeof (*gpuset);
    errno = 0;
    while (*cur)
      {
	long n = strtol(cur, &end, 0);
	if (errno)
	    fprintf(stderr, "Error parsing GPU set starting from: %s\n", cur), exit(1);
	gpuset[n / elmbits] |= 1L << (n % elmbits);
	if (!*end)
	    break;
	if (*end != ',')
	    fprintf(stderr, "GPU set does not seem to be a comma-separated list of integers: %s\n",
		    cur), exit(1);
	cur = end + 1;
      }
}

static bool jobj_binary(const json_t *obj, const char *key,
        void *buf, size_t buflen)
{
    const char *hexstr;
    json_t *tmp;
    tmp = json_object_get(obj, key);
    if (!tmp) {
        fprintf(stderr, "JSON key '%s' not found\n", key);
        return false;
    }
    hexstr = json_string_value(tmp);
    if (!hexstr) {
        fprintf(stderr, "JSON key '%s' is not a string\n", key);
        return false;
    }
    if (!hex2bin(buf, hexstr, buflen))
        return false;
    return true;
}

static bool work_decode(uint32_t datw[], uint32_t mids[], const json_t *val)
{
    if (!jobj_binary(val, "midstate", mids, 32)) {
        fprintf(stderr, "JSON inval midstate\n");
        goto err_out;
    }
    if (!jobj_binary(val, "data", datw, 128)) {
        fprintf(stderr, "JSON inval data\n");
        goto err_out;
    }
    // technically one should handle potentially different target values per
    // GPU, but it changes so rarely (once every 2 weeks) that it is not worth
    // the complexity. in these cases a GPU will simply have wasted a few
    // seconds of work on a data block...
    if (!jobj_binary(val, "target", target, sizeof(target))) {
        fprintf(stderr, "JSON inval target\n");
        goto err_out;
    }
    return true;
err_out:
    return false;
}

/*
 * Acquire new work and save it in the arguments:
 *   uint32_t	datw[32]
 *   uint32_t	mids[8]
 * as well as in the 'target' global variable.
 */
void rpc_get_work(uint32_t datw[], uint32_t mids[])
{
    json_t *val;
    static const char *rpc_req =
        "{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";
    // obtain new work
    val = json_rpc_call(rpc_url, auth, rpc_req);
    if (!val)
      {
        fprintf(stderr, "json_rpc_call failed\n");
        exit(1);
      }
    // decode result
    bool rc = work_decode(datw, mids, json_object_get(val, "result"));
    if (!rc)
      {
        fprintf(stderr, "work decode failed\n");
        exit(1);
      }
    json_decref(val);
    if (verbose > 1)
        printf("data: %08x...\n"
                "midstate: %08x...\n"
                "target: %02x%02x%02x%02x...\n",
                datw[0],
                mids[0],
                target[0], target[1], target[2], target[3]);
}

static bool rpc_submit_work(CALuint devi, uint32_t datw[], uint32_t nonce)
{
    char *hexstr = NULL;
    json_t *val, *res;
    char s[345];
    // patching the nonce into word 3 of the second 64-byte data block
    memcpy(datw + 16 + 3, &nonce, sizeof (nonce));
    /* build hex string */
    hexstr = bin2hex((unsigned char *)datw, 128);
    if (!hexstr)
        goto out;
    /* build JSON-RPC request */
    sprintf(s,
            "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}\r\n",
            hexstr);
    /* issue JSON-RPC request */
    val = json_rpc_call(rpc_url, auth, s);
    if (!val) {
        fprintf(stderr, "submit_work json_rpc_call failed\n");
        goto out;
    }
    res = json_object_get(val, "result");
    if (json_is_true(res))
        // print the nonce bytes as if they were a big endian value
        printf("Device %u solved block with nonce %u.\n",
                devi, htonl(nonce));
    else if (verbose)
        printf("Device %u found false positive with nonce %u.\n",
                devi, htonl(nonce));
    json_decref(val);
    return json_is_true(res);
out:
    free(hexstr);
    return false;
}

void generate_il(char **src, uint32_t datw[], uint32_t mids[])
{
    // dummy second data block (last 64 bytes)
    uint32_t *dat = (uint32_t *)
        "\x20\x87\x4c\x04\x4d\x0c\x82\x5c\x1c\x45\x12\x08\x29\xfb\xd3\x00"
        "\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x02\x00\x00";
    // dummy mid-state
    uint32_t *sta = (uint32_t *)
        "\x5a\xcb\x58\x60\x4e\x38\x72\xde\x3c\x8d\xe3\xfa\x39\x2e\x21\xf6"
        "\x2f\x5a\xfb\x0c\x29\xe6\xeb\x20\x77\xce\xe9\x9c\x3f\x5a\xfb\xc2";
    if (datw || mids)
      {
        assert(datw);
        assert(mids);
        dat = datw + 16;
        sta = mids;
      }
    if (-1 == asprintf(src, KERNEL_SHA256,
                threads_per_grp, iterations,
                sizeof (thread_state_t) / 16 /* size of x,y,z,w IL elements */,
                s_found, s_finished,
                // give the kernel only the non-zero data words
                dat[0], dat[1], dat[2],
                sta[0], sta[1], sta[2], sta[3],
                sta[4], sta[5], sta[6], sta[7]))
        perror("asprintf"), exit(1);
}

/*
 * Acquire next work item, compile, and save it in the next_* member variables.
 */
void create_next_work_item(CALuint devi, gpu_state_t *gs)
{
        char *src;
        CALobject obj;
        if (verbose)
            printf("Getting new work for GPU %u\n", devi);
        rpc_get_work(gs->next_datawords, gs->next_midstate);
        // compile and link
        generate_il(&src, gs->next_datawords, gs->next_midstate);
        if (CAL_RESULT_OK != calclCompile(&obj, CAL_LANGUAGE_IL, src,
                    gs->target))
            fatal("calclCompile");
        free(src);
        if (1)
            patch_bfi_int_instructions(verbose, &obj, bytes_to_patch,
                    expected_patched_instr_min, expected_patched_instr_max);
        if (CAL_RESULT_OK != calclLink(&gs->next_img, &obj, 1))
            fatal("calclLink");
        if (CAL_RESULT_OK != calclFreeObject(obj))
            fatal("calclFreeObject");
}

void verify_potential_find(CALuint devi, uint32_t datawords[], uint32_t nonce)
{
    // TODO: only send it if the SHA-256 hash is under the target
    rpc_submit_work(devi, datawords, nonce);
}

void prepare_run(CALuint devi, gpu_state_t *gs)
{
    // open device
    if (CAL_RESULT_OK != calDeviceOpen(&gs->device, devi))
        fatal("calDeviceOpen");
    if (CAL_RESULT_OK != calCtxCreate(&gs->ctx, gs->device))
        fatal("calCtxCreate");
    gs->have_run = false;
    gs->last_mhashpsec = 0;
    create_next_work_item(devi, gs);
}

/*
 * Shift the next_* variable representing the next work item to the current
 * variables, and notify the controller thread so it can acquire and prepare
 * the next work item.
 */
void shift_to_next_work(CALuint devi, gpu_state_t *gs)
{
    if (!gs->next_img)
      {
	printf("Device %d: getwork was not quick enough - waiting a bit...\n",
		devi);
	// wait for the controller thread to prepare work
	while (!gs->next_img)
	  {
	    struct timespec req = { .tv_sec = 0, .tv_nsec = 1e6 };
	    nanosleep(&req, NULL);
	  }
	printf("Device %d: getwork returned - resuming\n", devi);
      }
    gs->img = gs->next_img;
    gs->next_img = NULL;
    memcpy(gs->datawords, gs->next_datawords, sizeof (gs->datawords));
    memcpy(gs->midstate, gs->next_midstate, sizeof (gs->midstate));
    // tell the controller thread to prepare the next work item
    instr_t *i = malloc(sizeof (*i));
    if (!i)
        perror("malloc instruction"), exit(1);
    i->id = CREATE_NEXT_WORK_ITEM;
    i->devi = devi;
    i->gs = gs;
    if (-1 == write(pipefd[1], &i, sizeof (i)))
	perror("shift_to_next_work: write"), exit(1);
}

void set_local_res_mem(CALdevice device, CALcontext ctx, CALmodule module,
        CALresource *res, CALuint flags,
        CALmem *mem, const void *data, unsigned length, const char *param_name)
{
    /* About calResAllocLocal2D: There are some performance implications when
     * width is not a multiple of 64 for R6xx GPUs. Neither the width nor the
     * height can be too large (with 1.4 SDK on R700 the limit is 8192).
     * Similar limitations may exist for calResAllocLocal1D.
     */

    // allocate resource (length is in bytes)
    if (length % 64)
        fprintf(stderr, "length not multiple of 64: %u\n", length), exit(1);
    if (CAL_RESULT_OK != calResAllocLocal1D(res, device,
                length / 4, CAL_FORMAT_UNORM_INT32_1, flags))
        fatal("calResAllocLocal1D");
    if (CAL_RESULT_OK != calCtxGetMem(mem, ctx, *res))
        fatal("calCtxGetMem");
    // map, initialize, unmap
    if (data)
      {
        void *mapped;
        CALuint pitch;
        if (CAL_RESULT_OK != calResMap((CALvoid**)&mapped, &pitch, *res, 0))
            fatal("calResMap");
        memcpy(mapped, data, length);
        if (CAL_RESULT_OK != calResUnmap(*res))
            fatal("calResUnmap");
      }
    // bind to appropriate parameter
    CALname n;
    if (CAL_RESULT_OK != calModuleGetName(&n, ctx, module, param_name))
        fatal("calModuleGetName");
    if (CAL_RESULT_OK != calCtxSetMem(ctx, n, *mem))
        fatal("calCtxSetMem");
}

void load_module_data(gpu_state_t *gs)
{
    CALfunc entry;

    // load module, get entry point
    if (CAL_RESULT_OK != calModuleLoad(&gs->module, gs->ctx, gs->img))
        fatal("calModuleLoad");
    if (CAL_RESULT_OK != calModuleGetEntry(&entry, gs->ctx, gs->module,
                "main"))
        fatal("calModuleGetEntry");

    // global buffer "g[]" (gs->nr_threads * size of thread state)
    if (verbose)
        printf("Initializing global buffer\n");
    set_local_res_mem(gs->device, gs->ctx, gs->module,
            &gs->globalRes, CAL_RESALLOC_GLOBAL_BUFFER,
            &gs->globalMem, NULL,
            gs->nr_threads * sizeof (thread_state_t), "g[]");

    // SHA-256 cube roots of the first 64 primes "cb0" (64 4-byte values)
    if (verbose)
        printf("Initializing cube root constants\n");
    set_local_res_mem(gs->device, gs->ctx, gs->module,
            &gs->constRes, 0,
            &gs->constMem, k_constants, 64 * 4, "cb0");

    // init program grid
    CALprogramGrid pg = {
        .func = entry,
        .gridBlock = { .width = threads_per_grp, .height = 1, .depth = 1 },
        .gridSize = { .width = gs->nr_simds, .height = 1, .depth = 1 },
        .flags = 0
    };
    gs->pg = pg;
    gs->e = 0;
}

void free_local_res_mem(CALcontext ctx, CALmem mem, CALresource res)
{
    if (CAL_RESULT_OK != calCtxReleaseMem(ctx, mem))
        fatal("calCtxReleaseMem");
    if (CAL_RESULT_OK != calResFree(res))
        fatal("calResFree");
}

void unload_module_data(gpu_state_t *gs)
{
    free_local_res_mem(gs->ctx, gs->constMem, gs->constRes);
    free_local_res_mem(gs->ctx, gs->globalMem, gs->globalRes);
    // unload module
    if (CAL_RESULT_OK != calModuleUnload(gs->ctx, gs->module))
        fatal("calModuleUnload");
    // free the image
    if (CAL_RESULT_OK != calclFreeImage(gs->img))
        fatal("calclFreeImage");
}

/**
 * Returns true iff the threads are currently running. Returns false
 * if they have never been started of if they completed work.
 */
bool threads_running(gpu_state_t *gs)
{
    if (!gs->have_run)
        // threads have never been started
        return false;
    CALresult res;
    res = calCtxIsEventDone(gs->ctx, gs->e);
    if (res == CAL_RESULT_OK)
      {
        gettimeofday(&gs->tv_end, NULL);
        return false;
      }
    else if (res != CAL_RESULT_PENDING)
        fatal("calCtxIsEventDone");
    return true;
}

void show_global_stats(gpu_state_t *gs_base, CALuint nr_devs)
{
    CALuint devi;
    int global_mhashpsec = 0;
    for (devi = 0; devi < nr_devs; devi++)
      {
	if (!gs_base[devi].used)
	    continue;
        global_mhashpsec += gs_base[devi].last_mhashpsec;
      }
    printf("Overall rate: %u Mhash/sec...", global_mhashpsec);
    if (verbose)
        printf("\n");
    else {
        printf("\r");
        fflush(stdout);
    }
}

void show_stats(CALuint devi, gpu_state_t *gs)
{
    long long ms0 = gs->tv_start.tv_sec * 1000 + gs->tv_start.tv_usec / 1000;
    long long ms1 = gs->tv_end.tv_sec * 1000 + gs->tv_end.tv_usec / 1000;
    int mhashpsec = (int)
        ((float)ELM_PER_THREAD // nr of hashes verified per thread per iteration
         * iterations // nr of iterations of the main loop for each thread
         * gs->nr_threads // nr of threads
         * 1000 / (ms1 - ms0) // hash/period_of_time converted to hash/sec
         / 1e6); // converted to Mhash/sec
    if (verbose)
        printf("Device %d: execution time %lld ms (%u Mhash/sec)\n",
                devi, ms1 - ms0, mhashpsec);
    gs->last_mhashpsec = mhashpsec;
}

/*
 * Verify if the candidate nonce actually solves the block.
 *
 * Returns true iff it does.
 */
void validate_candidate(gpu_state_t *gs, CALuint devi, int t, int e,
        uint32_t nonce)
{
    if (verbose)
      {
        printf("GPU %d thread %d elm %d found candidate nonce\n",
                devi, t, e);
        // print the nonce bytes as if they were a big endian value
        printf("Candidate nonce value: %d             \n", htonl(nonce));
      }
    // send the candidate to the controller thread
    instr_t *i = malloc(sizeof (*i));
    if (!i)
        perror("malloc instruction"), exit(1);
    i->id = VERIFY_POTENTIAL_FIND;
    i->devi = devi;
    memcpy(i->datawords, gs->datawords, 128);
    i->nonce = nonce;
    if (-1 == write(pipefd[1], &i, sizeof (i)))
	perror("validate_candidate: write"), exit(1);
}

/**
 * Analyze current results from the global buffer (if threads have
 * run at least once). And prepare next batch of work.
 */
void threads_analyze_and_prepare(CALuint devi, gpu_state_t *gs)
{
    uint8_t *ptr = NULL;
    // a single variable is used to determine if new work should be fetched,
    // which means when 1 elm of 1 thread finds a potential nonce solving the
    // block, all threads will start on new work on the next run
    bool ready_for_new_work = false;
    if (!gs->have_run)
      {
        ready_for_new_work = true;
        goto new_work;
      }
    // map
    CALuint pitch = 0;
    if (CAL_RESULT_OK != calResMap((CALvoid**)&ptr, &pitch, gs->globalRes, 0))
        fatal("calResMap");
    // analyze results if we have some, ie. if the threads have been started
    show_stats(devi, gs);
    if (verbose > 1)
        printf(" Global buffer for first and last threads:\n");
    for (int t = 0; t < gs->nr_threads; t++)
      {
        thread_state_t *ts = (thread_state_t *)ptr + t;
        if (verbose > 1 && (t <= 0 || t == gs->nr_threads - 1))
            printf("  thread %d:\n", t);
        for (int e = 0; e < ELM_PER_THREAD; e++)
          {
            elm_state_t *elm = (elm_state_t *)ts + e;
            if (verbose > 1 && (t <= 0 || t == gs->nr_threads - 1))
                printf("    elm %d: %02x(%02x%02x%02x) %08x %08x %08x\n",
                        e, elm->status,
                        elm->_unused0[0], elm->_unused0[1], elm->_unused0[2],
                        elm->cur_nonce, elm->end_nonce, elm->_unused1);
            if (elm->status == s_searching)
                (void)0; // still searching this work unit
            else if (elm->status == s_found)
              {
                // Potentially found a nonce solving the block. Note that
                // the thread has already incremented the nonce, so
                // validate it "minus 1".
                if (verbose > 1)
                    printf("Candidate found by GPU %d thread %d elm %d\n",
                            devi, t, e);
                validate_candidate(gs, devi, t, e, elm->cur_nonce - 1);
                // Regardless of whether it is valid or not, continue
                // processing were we left at. Note that we need special
                // handling if the nonce was the last one to be verified.
                if (elm->cur_nonce == elm->end_nonce)
                    ready_for_new_work = true;
              }
            else if (elm->status == s_finished)
              {
                // finished searching all nonce, try next one
                ready_for_new_work = true;
              }
            else
                fprintf(stderr, "*bug*: invalid status for GPU %d thread %d "
                        "elm %d: %02x\n", devi, t, e, elm->status), exit(1);
          }
      }
new_work:
    if (ptr)
        if (CAL_RESULT_OK != calResUnmap(gs->globalRes))
            fatal("calResUnmap 1");
    if (ready_for_new_work)
      {
        if (gs->have_run)
            unload_module_data(gs);
        shift_to_next_work(devi, gs);
        load_module_data(gs);
        if (CAL_RESULT_OK !=
                calResMap((CALvoid**)&ptr, &pitch, gs->globalRes, 0))
            fatal("calResMap");
        uint32_t nonces_per_elm =
            (uint32_t)-1 / (gs->nr_threads * ELM_PER_THREAD);
        uint32_t n = 0;
        //n = 0xd3fb29;
        if (verbose > 1)
            printf("Nonces per elm: 0x%x\n", nonces_per_elm);
        for (int t = 0; t < gs->nr_threads; t++)
          {
            thread_state_t *ts = (thread_state_t *)ptr + t;
            for (int e = 0; e < ELM_PER_THREAD; e++)
              {
                elm_state_t *elm = (elm_state_t *)ts + e;
                elm->status = s_searching;
                elm->cur_nonce = n;
                elm->end_nonce = (n += nonces_per_elm);
                elm->_unused1 = 0;
              }
          }
        if (CAL_RESULT_OK != calResUnmap(gs->globalRes))
            fatal("calResUnmap 2");
      }
}

void threads_start(gpu_state_t *gs)
{
    gettimeofday(&gs->tv_start, NULL);
    if (CAL_RESULT_OK != calCtxRunProgramGrid(&gs->e, gs->ctx, &gs->pg))
        fatal("calCtxRunProgram");
    if (CAL_RESULT_OK != calCtxFlush(gs->ctx))
        fatal("calCtxFlush");
    gs->have_run = true;
}

void do_run(gpu_state_t *gs_base, CALuint nr_devs)
{
    const int forever = 42;
    CALuint devi;
    int i = 0;
    printf("Running on GPUs\n");
    while (forever)
      {
        for (devi = 0; devi < nr_devs; devi++)
          {
            gpu_state_t *gs = gs_base + devi;
	    if (!gs->used)
		continue;
            if (!threads_running(gs))
              {
                threads_analyze_and_prepare(devi, gs);
                threads_start(gs);
              }
          }
        if (!(i % show_stats_every_x_ms))
            show_global_stats(gs_base, nr_devs);
        struct timespec req = { .tv_sec = 0, .tv_nsec = 1e6 };
        nanosleep(&req, NULL);
        i++;
      }
}

void finish_run(gpu_state_t *gs)
{
    // close device
    if (CAL_RESULT_OK != calCtxDestroy(gs->ctx))
        fatal("calCtxDestroy");
    if (CAL_RESULT_OK != calDeviceClose(gs->device))
        fatal("calDeviceClose");
}

void handle(instr_t *i)
{
    switch (i->id)
      {
        case CREATE_NEXT_WORK_ITEM:
            create_next_work_item(i->devi, i->gs);
            break;
        case VERIFY_POTENTIAL_FIND:
            verify_potential_find(i->devi, i->datawords, i->nonce);
            break;
        default:
            fprintf(stderr, "Unknown instruction id %u", i->id);
            exit(1);
      }
}

void *controller_thread(void *_unused)
{
    instr_t *i;
    ssize_t n;
    while (-1 != (n = read(pipefd[0], &i, sizeof (i))))
      {
        if (n != sizeof (i))
            fprintf(stderr, "read only %li bytes out of %lu\n", n, sizeof (i)),
                exit(1);
        if (verbose)
            printf("Controller processing instruction at %p\n", (void *)i);
        handle(i);
        if (verbose)
            printf("Controller processing done\n");
        free(i);
      }
    perror("read");
    exit(1);
    (void)_unused;
    return NULL;
}

void prepare_and_run(CALuint nr_devs)
{
    CALuint nr_devs_used = 0;
    CALuint devi;
    CALdeviceattribs attribs;
    pthread_t t;
    gpu_state_t *gs_base = malloc(nr_devs * sizeof (*gs_base));
    if (!gs_base)
        perror("malloc"), exit(1);
    // get attributes of the target devices
    for (devi = 0; devi < nr_devs; devi++)
      {
        gpu_state_t *gs = gs_base + devi;
        attribs.struct_size = sizeof(CALdeviceattribs);
        if (CAL_RESULT_OK != calDeviceGetAttribs(&attribs, devi))
            fatal("calDeviceGetAttribs");
        gs->nr_simds = attribs.numberOfSIMD;
        printf("Device %u: %s, %u SIMDs, ",
                devi, target_name(attribs.target, attribs.targetRevision),
                gs->nr_simds);
	if (!run_on_gpu(devi))
	  {
	    printf("excluded from GPU set\n");
	    gs->used = false;
	    continue;
	  }
	if (attribs.target < CAL_TARGET_CYPRESS)
	  {
	    printf("skipped (not HD 5000+ series)\n");
	    gs->used = false;
	    continue;
	  }
        gs->nr_threads = gs->nr_simds * threads_per_grp;
        printf("launching %i threads\n", gs->nr_threads);
	gs->used = true;
	nr_devs_used++;
        gs->target = attribs.target;
      }
    printf("Found %u usable device%s\n", nr_devs_used,
	    nr_devs_used != 1 ? "s" : "");
    if (!nr_devs_used)
	exit(1);
    if (pipe(pipefd))
        perror("pipe"), exit(1);
    for (devi = 0; devi < nr_devs; devi++)
      {
	if (!gs_base[devi].used)
	    continue;
        prepare_run(devi, gs_base + devi);
      }
    if (pthread_create(&t, NULL, controller_thread, NULL))
        perror("pthread_create"), exit(1);
    do_run(gs_base, nr_devs);
    for (devi = 0; devi < nr_devs; devi++)
      {
	if (!gs_base[devi].used)
	    continue;
        finish_run(gs_base + devi);
      }
}

void cal_puts(const CALchar *msg)
{
    fputs(msg, stdout);
}

void disassemble(const char *src)
{
    CALobject obj;
    if (CAL_RESULT_OK != calclCompile(&obj, CAL_LANGUAGE_IL, src,
                disassemble_target))
        fatal("calclCompile");
    if (1)
        patch_bfi_int_instructions(verbose, &obj, bytes_to_patch,
                expected_patched_instr_min, expected_patched_instr_max);
    calclDisassembleObject(&obj, cal_puts);
}

void usage(const char *name)
{
    fprintf(stdout, "Usage: %s [OPTION]...\n"
            "\n"
            "Arguments:\n"
            "  -a <user:pwd>   Bitcoin JSON-RPC user and password (default bitcoin:password)\n"
            "  -d <target>     Disassemble kernel for this target device\n"
            "  -G <n,n...>     Limit execution to this set of GPU devices (default all)\n"
            "  -g <nr-gpus>    Limit execution to the first <nr-gpus> GPUs (default all)\n"
            "  -h              Display this help\n"
            "  -i <iterations> Number of iterations of the main compute loop (default 4096)\n"
            "  -p <port>       Bitcoin JSON-RPC server TCP port (default 8332)\n"
            "  -s <server>     Bitcoin JSON-RPC server (default localhost)\n"
            "  -t <threads>    Number of threads per SIMD (default 320)\n"
            "  -v              Verbose mode\n"
            , name);
}

int main(int argc, char** argv)
{
    // the CAL IL kernel makes these assumptions
    //assert(sizeof (elm_state_t) == 12);
    //assert(sizeof (thread_state_t) == 192);
    const char *gpuset_str = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "a:d:G:g:hi:p:s:t:v")) != -1) {
        switch (opt) {
            case 'a':
                auth = optarg;
                break;
            case 'd':
                disassemble_target = strtoul(optarg, NULL, 0);
                break;
            case 'G':
                gpuset_str = optarg;
                break;
            case 'g':
                max_gpus = strtoul(optarg, NULL, 0);
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
            case 'i':
                iterations = strtoul(optarg, NULL, 0);
                break;
            case 'p':
                port = strtoul(optarg, NULL, 0);
                break;
            case 's':
                server = optarg;
                break;
            case 't':
                threads_per_grp = strtoul(optarg, NULL, 0);
                break;
            case 'v':
                verbose++;
                break;
            default:
                usage(argv[0]);
                exit(1);
        }
    }
    if (optind < argc)
      {
        if (optind != argc)
          {
            fprintf(stderr, "Expected no extra argument\n");
            usage(argv[0]);
            exit(1);
          }
      }
    if (gpuset_str && max_gpus)
      {
	fprintf(stderr, "Cannot specify GPU set (-G) and maximum number of GPUs (-g) concurrently\n");
	exit(1);
      }
    init_gpuset(gpuset_str);
    if (-1 == asprintf(&rpc_url, "http://%s:%d/", server, port))
	perror("asprintf"), exit(1);
    printf("Initializing CAL... ");
    fflush(stdout);
    if (CAL_RESULT_OK != calInit())
        fatal("calInit");
    show_ver();
    if (disassemble_target != -1)
      {
        char *src;
        generate_il(&src, NULL, NULL);
        disassemble(src);
        free(src);
        exit(0);
      }
    if (verbose)
        printf("Will do %i iterations per loop\n", iterations);
    CALuint nr_devs;
    if (CAL_RESULT_OK != calDeviceGetCount(&nr_devs))
        fatal("calDeviceGetCount");
    printf("Found %u device%s, launching %u threads per SIMD\n",
            nr_devs, nr_devs != 1 ? "s" : "", threads_per_grp);
    if (max_gpus && nr_devs > max_gpus)
      {
        nr_devs = max_gpus;
        printf("Use only first %u device%s\n", nr_devs,
                nr_devs != 1 ? "s" : "");
      }
    if (nr_devs >= 1)
        prepare_and_run(nr_devs);
    calShutdown();
    free(rpc_url);
    return 0;
}
