#!/usr/bin/env python3

import os

from panda import Panda, blocking, ffi
from panda.x86.helper import *

panda = Panda(generic="x86_64")

# Use syscalls2 to get callbacks whenever we enter any syscall
panda.load_plugin("syscalls2", {"load-info": True})

# Use OSI to figure out what process is running
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

# 1) Generate recording we want to analyze - Copy the `target/` directory from host into guest
if not os.path.isfile(f"{recording_name}-rr-snp"):
    print("Taking recording")
    @blocking
    def start():
        panda.record_cmd("sleep 1s; target/testprog", copy_directory="target", recording_name=recording_name)
        panda.end_analysis()

    panda.queue_async(start)
    panda.run()
else:
    print(f"Using cached recording {recording_name}-rr-snp and {recording_name}-rr-nondet.log")

# 2) Analyze the recording to find all the buffer addresses that go into syscalls

procnames_of_interest = ["testprog"]
asid_to_procname = {} # asid: procname

# Might have issues if the same process uses the same address multiple times
identified_buffers = {} # address: [(asid, proc_name, icount_use, syscall_name)]

argtypes = ffi.typeof("syscall_argtype_t").relements
@panda.ppp("syscalls2", "on_all_sys_enter2")
def syscall_enter(cpu, pc, call, ctx):
    for arg_idx in range(call.nargs):
        # Debug prints
        #type_str = ffi.string(ffi.cast("syscall_argtype_t", call.argt[arg_idx]))
        #print(f"\tArg{arg_idx}: size {call.argsz[arg_idx]}, type {type_str}")

        # Log all pointers passed to syscalls - strings or poitners to buffers
        if call.argt[arg_idx] in [argtypes['SYSCALL_ARG_PTR'], argtypes['SYSCALL_ARG_STR']]:
            arg_ptr = int(ffi.cast('uint64_t*', ctx.args)[arg_idx]) # Cast to uint64_t's _BEFORE_ we access (weird) TODO

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
                identified_buffers[arg_ptr].append((asid, proc_name, panda.rr_get_guest_instr_count(), syscall_name))

panda.run_replay(recording_name)

print(f"Identified {len(identified_buffers.keys())} buffers")
if len(identified_buffers.keys()) == 0:
    raise RuntimeError(f"Failed to identify any buffers passed to syscalls for process(es): {', '.join(procnames_of_interest)}")

# 3) Now we know where the buffers are. Analyze the recording again to identify the last write to each

# No longer need syscalls2 callbacks
panda.unload_plugin("syscalls2")

instr_counts = [hex(truple[0][2]) for truple in identified_buffers.values()]
panda.load_plugin("memorymap", {"instr_counts": "-".join(instr_counts)}) # Get base address of target

# Turn on memory callbacks so virtual_mem_before_write works
panda.enable_memcb()

# update the program counter within basic blocks
panda.enable_precise_pc()

# XXX: PRI only supports 32-bit linux :( Leaving this disabled
# Use PRI to map program counters back to line numbers. Note these arguments correspond to the target
#panda.load_plugin("pri")
#panda.load_plugin("pri_dwarf", {"proc":"test", "h_debugpath": "./target/", "g_debugpath": "/root/target/" })
# PRI isn't well supported by the python interface, tell cffi all it needs to know
#header = """
#typedef struct { const char *filename; const char *funct_name; unsigned long line_number; } SrcInfo;
#int pri_get_pc_source_info (CPUState *env, target_ulong pc, SrcInfo *info);
#"""
#ffi.cdef(header)


last_write_before = {} # (asid, address, icount_at_use): (icount_at_write, write_addr, mod_name, mod_base, in_kernel)

base_addresses = {} # name (from procnames_of_interest): lowest address loaded at

@panda.cb_virt_mem_before_write
def before_write(cpu, pc, start_addr, size, buf):
    for addr in range(start_addr, start_addr+size):
        if addr not in identified_buffers:
            continue

        buf_base = buf+(addr-start_addr)
        data = ffi.string(ffi.cast('char*', buf_base))

        # Find the last instruction (highest icount) that wrote to the buffer,
        # but before the syscall's icount
        write_icount = panda.rr_get_guest_instr_count()

        asid = panda.current_asid(cpu)
        for (old_asid, proc_name, icount_use, _) in identified_buffers[addr]:
            if old_asid != asid:
                continue
            if icount_use < write_icount:
                continue

            in_kernel = panda.in_kernel(cpu)

            # Identify what module we're currently in so we can get a relative offset
            for module in panda.get_mappings(cpu):
                mod_base = None
                mod_name = ffi.string(module.name).decode("utf8") if module.name != ffi.NULL else '(null)'

                if mod_name in procnames_of_interest:
                    if mod_name not in base_addresses or module.base < base_addresses[mod_name]:
                        base_addresses[mod_name] = module.base


                # Debug: print memory map at each write we care about
                #print(f"0x{module.base:012x} - 0x{module.base+module.size:012x}: {mod_name}")

                if addr >= module.base and addr < module.base+module.size: # Then it's in this module
                    mod_name = ffi.string(module.name).decode("utf8") if module.name != ffi.NULL else '(null)'
                    mod_base = module.base
                    break
            else:
                print(f"Warning: No loaded module owns address 0x{addr:x}. Skipping")
                continue

            # Identify where PC is at time of write
            '''
            for module in panda.get_mappings(cpu):
                if pc >= module.base and pc < module.base+module.size: # Then it's in this module
                    name = ffi.string(module.name).decode("utf8") if module.name != ffi.NULL else '(null)'
                    print(f"PC 0x{pc:x} is in {name} offset: 0x{pc-module.base:x}")
            '''

            if (asid, addr, icount_use) not in last_write_before.keys():
                last_write_before[(asid, addr, icount_use)] = (write_icount, pc, mod_name, mod_base, in_kernel)
            else:
                last_write_icount = last_write_before[(asid, addr, icount_use)][0]
                if write_icount > last_write_icount: # Replace with new write
                    last_write_before[(asid, addr, icount_use)] = (write_icount, pc, mod_name, mod_base, in_kernel)

                    # Get source location
                    #info = ffi.new("SrcInfo*")
                    #panda.libpanda.pri_get_pc_source_info(cpu, pc, info)
                    #print(ffi.string(info.filename), ffi.string(info.func_name), info.line_number)

panda.run_replay(recording_name)

# 4) Now we have the last writes to each buffer, print each
# XXX: some of these relative addresses look crazy
print()
for ((asid, addr, _), (_, write_pc, mod_name, mod_base, in_kernel)) in last_write_before.items():
    proc_name, syscall_name = [(buf[1], buf[3]) for buf in identified_buffers[addr] if buf[0] == asid][0]
    print(f"{syscall_name} got data from 0x{addr:x} => {mod_name}+0x{addr-mod_base:x}")
    if in_kernel:
        print("\tData was written by the kernel")
    elif proc_name in base_addresses:
        #print(f"\tWritten by {proc_name} (base 0x{base_addresses[proc_name]:x}). Relative PC: 0x{write_pc - base_addresses[proc_name]:x}")
        print(f"\tWritten by {proc_name} (base 0x{base_addresses[proc_name]:x}). PC at write 0x{write_pc:x}")
    else:
        print(f"\tWritten by {proc_name}")
