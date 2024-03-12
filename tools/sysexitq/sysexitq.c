#define _GNU_SOURCE

#include <argp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "misc.h"
#include "ldat.h"
#include "patch.h"

#include "ucode_macro.h"

u8 verbose = 0;

const char *argp_program_version = "custom-cpu v0.1";
static char doc[] = "Tool for patching ucode";
static char args_doc[] = "";

// cli argument availble options.
static struct argp_option options[] = {
    {.name="verbose", .key='v', .arg=NULL, .flags=0, .doc="Produce verbose output"},
    {.name="reset", .key='r', .arg=NULL, .flags=0, .doc="reset match & patch"},
    {.name="patch", .key='p', .arg=NULL, .flags=0, .doc="patch sysexitq"},
    {.name="core", .key='c', .arg="core", .flags=0, .doc="core to patch [0-3]"},
    {0}
};


// define a struct to hold the arguments.
struct arguments{
    u8 verbose;
    u8 reset;
    u8 patch;
    s8 core;
};


// define a function which will parse the args.
static error_t parse_opt(int key, char *arg, struct argp_state *state){
    char *token;
    int i;
    struct arguments *arguments = state->input;
    switch(key){

        case 'v':
            arguments->verbose = 1;
            break;
        case 'r':
            arguments->reset = 1;
            break;
        case 'p':
            arguments->patch = 1;
            break;
        case 'c':
            arguments->core = strtol(arg, NULL, 0);
            if (arguments->core < 0 || arguments->core > 3){
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            break;

        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

void do_sysexitq_patch() {
    u64 patch_addr = 0x7da0;
    u64 hook_addr  = 0x0740;
    ucode_t ucode_patch[] = {
        /*
        Read uram
        > RDI: uram_address
        < RAX: output
        */
        #if 0
        {
            READURAM_DR(RAX, RDI),
            NOP,
            NOP,
            END_SEQWORD
        }
        #endif

        /*
        Write uram
        > RDI: uram_address
        > RAX: data
        */
        #if 0
        {
            WRITEURAM_RR(RAX, RDI),
            NOP,
            NOP,
            END_SEQWORD
        }
        #endif

        /*
        Read staging buffer
        > RDI: address
        < RAX: output
        */
        #if 0
        {
            LDSTGBUF_DSZ64_ASZ16_SC1_DR(RAX, RDI),
            NOP,
            NOP,
            END_SEQWORD
        }
        #endif

        /*
        Write staging buffer
        > RDI: address
        > RAX: data
        */
        #if 0
        {
            STADSTGBUF_DSZ64_ASZ16_SC1_RR(RAX, RDI),
            NOP,
            NOP,
            END_SEQWORD
        }
        #endif

        /*
        Read crbus (weird behaviour)
        > RDI: address
        < RAX: output
        */
        #if 0
        {
            MOVEFROMCREG_DSZ64_DR(RAX, RDI),
            NOP,
            NOP,
            END_SEQWORD
        }
        #endif

        /*
        Write crbus (weird behaviour)
        > RDI: address
        > RAX: data
        */
        #if 0
        {
            MOVETOCREG_DSZ64_RR(RAX, RDI),
            NOP,
            NOP,
            END_SEQWORD
        }
        #endif

        /*
        Watchpoint
        */
        #if 1
        {
            LDZX_DSZ64_ASZ32_SC1_DR(TMP5, RDI, 0x18),
            SUB_DSZ64_DRR(TMP5, RBX, TMP5),
            UJMPCC_DIRECT_NOTTAKEN_CONDZ_RI(TMP5, patch_addr + 0x08),
            NOP_SEQWORD
        },
        {
            NOP,
            NOP,
            MOVE_DSZ64_DI(RBX, 0x1234),
            END_SEQWORD
        },
        {
            NOP,
            MOVE_DSZ64_DI(RBX, 0x5678),
            DIVSD(XMM0, XMM0, XMM1),
            END_SEQWORD
        }
        #endif
    };

    patch_ucode(patch_addr, ucode_patch, ARRAY_SZ(ucode_patch));
    hook_match_and_patch(0, hook_addr, patch_addr);
}

// initialize the argp struct. Which will be used to parse and use the args.
static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};

int main(int argc, char* argv[]) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    struct arguments arguments;
    memset(&arguments, 0, sizeof(struct arguments));
    arguments.core = -1;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);
    verbose = arguments.verbose;

    u8 core = (arguments.core < 0)? 0 : arguments.core;
    if (0 <= core && core <= 3) 
        assign_to_core(core);
    else {
        printf("core out of bound");
        exit(EXIT_FAILURE);
    }

    if (arguments.reset) { // Reset match and patch
        init_match_and_patch();
        usleep(20000);
    }

    crbus_write(0x51b, 0x1);
    if (arguments.patch) { // Patch sysexitq
        do_fix_IN_patch();
        do_sysexitq_patch();

        register u64 rax asm("rax");
        register u64 rbx asm("rbx");
        register u64 rdi asm("rdi");
        volatile u64 test = 0x1122334455667788;

        //for (int i = 0; i < 10; i++) {
            rbx = 0x1122334455667788;
            rdi = (u64) &main;
            asm volatile("sysexitq");
            printf("rax: 0x%016lx\nrbx: 0x%016lx\nrsi: 0x%016lx\n\n", rax, rbx, rdi);
        //}

        rbx = 0x1122334455667788;
        rdi = (u64) &test;
        asm volatile("sysexitq");
        printf("rax: 0x%016lx\nrbx: 0x%016lx\nrsi: 0x%016lx\n\n", rax, rbx, rdi);
        return 0;
    }

    return 0;
}
