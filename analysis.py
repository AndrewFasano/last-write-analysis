#!/usr/bin/env python3

import os
from ipdb import set_trace as d

from panda import Panda, blocking, ffi
from panda.x86.helper import *

panda = Panda(generic="x86_64")
panda.load_plugin("syscalls2", {"load-info": True})
panda.load_plugin("osi")
panda.load_plugin("osi_linux")

# First we need to hack around a not-yet-supported feature in pypanda:  the structs for on_all_sys_enter2
# aren't automatically defined for python. These are just copied from some header files

ffi.cdef("""
struct syscall_ctx {
    int no;               /**< number */
    target_ptr_t asid;    /**< calling process asid */
    target_ptr_t retaddr; /**< return address */
    uint8_t args[64]
                [64]; /**< arguments */
};

// syscalls2_info.h
typedef struct {
    uint32_t max;
    uint32_t max_generic;
    uint32_t max_args;
} syscall_meta_t;

typedef enum {
    SYSCALL_ARG_U64 = 0x00, /**< unsigned 64bit value */
    SYSCALL_ARG_U32,        /**< unsigned 32bit value */
    SYSCALL_ARG_U16,        /**< unsigned 16bit value */
    SYSCALL_ARG_S64 = 0x10, /**< signed 64bit value */
    SYSCALL_ARG_S32,        /**< signed 32bit value */
    SYSCALL_ARG_S16,        /**< signed 16bit value */
    SYSCALL_ARG_PTR = 0x20, /**< pointer to buffer/struct */
    SYSCALL_ARG_STR         /**< C string */
} syscall_argtype_t;

typedef struct {
    int no;
    const char *name;
    int nargs;
    syscall_argtype_t *argt;
    uint8_t *argsz;
    bool noreturn;
} syscall_info_t;


// Hand-crafted modeling python/include/syscalls_ext_typedefs_x86_64.h
typedef struct syscall_ctx syscall_ctx_t;
typedef void (*on_all_sys_enter2_t)(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *ctx);
void ppp_add_cb_on_all_sys_enter2(on_all_sys_enter2_t);
""")


recording_name="test"

# 1) Generate recording we want to analyze
if not os.path.isfile("test-rr-snp"):
    print("Taking recording")
    @blocking
    def start():
        panda.record_cmd("cat /etc/passwd > foo", recording_name=recording_name)
        panda.end_analysis()

    panda.queue_async(start)
    panda.run()

# 2) Analyze the recording to find all the buffer addresses that go into syscalls

procnames_of_interest = ["cat"]
asid_to_procname = {} # asid: procname

# Might have issues if the same process uses the same address multiple times
identified_buffers = {} # address: [(asid, proc_name, icount_use)]

argtypes = ffi.typeof("syscall_argtype_t").relements
@panda.ppp("syscalls2", "on_all_sys_enter2")
def syscall_enter(cpu, pc, call, ctx):
    for arg_idx in range(call.nargs):
        # Debug prints
        #type_str = ffi.string(ffi.cast("syscall_argtype_t", call.argt[arg_idx]))
        #print(f"\tArg{arg_idx}: size {call.argsz[arg_idx]}, type {type_str}")

        # Log all pointers passed to syscalls
        if call.argt[arg_idx] == argtypes['SYSCALL_ARG_PTR']:
            arg_ptr = int(ffi.cast('uint64_t*', ctx.args)[1]) # Cast to uint64_t's _BEFORE_ we access (weird)
            asid = panda.current_asid(cpu)
            proc = panda.plugins['osi'].get_current_process(cpu) 
            syscall_name = ffi.string(call.name).decode('utf8') if call.name != ffi.NULL else "unknown"
            if asid not in asid_to_procname:
                proc_name    = ffi.string(proc.name).decode('utf8') if (proc.name != ffi.NULL) else "unknown"
                asid_to_procname[asid] = proc_name
            proc_name = asid_to_procname[asid]
            if proc_name in procnames_of_interest:
                print(f"Process: {proc_name} ({ctx.asid}) syscall {syscall_name} with buffer at 0x{arg_ptr:x}")
                if arg_ptr not in identified_buffers.keys():
                    identified_buffers[arg_ptr] = []
                identified_buffers[arg_ptr].append((asid, proc_name, panda.rr_get_guest_instr_count()))

panda.run_replay(recording_name)
#panda.disable_ppp("syscall_enter") # XXX TODO

print(f"Identified {len(identified_buffers.keys())} buffers")

# 3) Now we know where the buffers are. Analyze the recording again to identify the last write to each

panda.unload_plugin("syscalls2")
panda.enable_memcb()

last_write_before = {} # (asid, address, icount_at_use): (write_addr, icount_at_write)

@panda.cb_virt_mem_before_write
def before_write(cpu, pc, start_addr, size, buf):
    for addr in range(start_addr, start_addr+size):
        if addr not in identified_buffers:
            continue

        # Find the last instruction (highest icount) that wrote to the buffer,
        # but before the syscall's icount
        write_icount = panda.rr_get_guest_instr_count()

        asid = panda.current_asid(cpu)
        for (old_asid, proc_name, icount_use) in identified_buffers[addr]:
            if old_asid != asid:
                continue
            if icount_use < write_icount:
                continue
            if (asid, addr, icount_use) not in last_write_before.keys():
                last_write_before[(asid, addr, icount_use)] = (pc, write_icount)
            else:
                _, last_write_icount = last_write_before[(asid, addr, icount_use)]
                if write_icount > last_write_icount: # Replace with new write
                    last_write_before[(asid, addr, icount_use)] = (pc, write_icount)

panda.run_replay(recording_name)

# 4) Now we have the last writes to each buffer, print each

for ((asid, addr, _), (write_pc, _)) in last_write_before.items():
    proc_name = asid_to_procname[asid]
    print(f"Last write to 0x{addr:x} at 0x{write_pc:x} by {proc_name}")
