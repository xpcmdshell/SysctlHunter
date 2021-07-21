#!/usr/bin/env python3
from binaryninja import *
import argparse
import os
import sys
import plistlib

QUIET_MODE = False

OID_FLAGS = {
    0x80000000: "CTLFLAG_RD",
    0x40000000: "CTLFLAG_WR",
    0x20000000: "CTLFLAG_NOLOCK",
    0x10000000: "CTLFLAG_ANYBODY",
    0x08000000: "CTLFLAG_SECURE",
    0x04000000: "CTLFLAG_MASKED",
    0x02000000: "CTLFLAG_NOAUTO",
    0x01000000: "CTLFLAG_KERN",
    0x00800000: "CTLFLAG_LOCKED",
    0x00400000: "CTLFLAG_OID2",
}

OID_TYPES = {
    0x00000001: "CTLTYPE_NODE",
    0x00000002: "CTLTYPE_INT",
    0x00000003: "CTLTYPE_STRING",
    0x00000004: "CTLTYPE_QUAD",
    0x00000005: "CTLTYPE_OPAQUE",
}

OID_DEFS = """
typedef uint64_t user_addr_t;

struct sysctl_req
{
    void* p;
    int32_t lock;
    user_addr_t oldptr;
    uint64_t oldlen;
    uint64_t oldidx;
    int32_t (* oldfunc)(struct sysctl_req*, void const*, uint64_t);
    user_addr_t newptr;
    uint64_t newlen;
    uint64_t newidx;
    int32_t (* newfunc)(struct sysctl_req*, void*, uint64_t);
};

struct sysctl_oid
{
    struct sysctl_oid* oid_parent;
    struct sysctl_oid* oid_link;
    int   oid_number;
    int   oid_kind;
    void* oid_arg1;
    int   oid_arg2;
    char const* oid_name;
    int   (* oid_handler)(struct sysctl_oid* oidp, void* arg1, int arg2, struct sysctl_req* req);
    char const* oid_fmt;
    char const* oid_descr;
    int  oid_version;
    int   oid_refcnt;
};
"""


class SysctlHunter:
    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.oid_handler_funcs = []
        self.oid_structs = []
        self.oid_struct_addrs = []

    def is_valid(self):
        return "_sysctl_register_oid" in self.bv.symbols

    def run(self):
        qprint("[*] Creating necessary type definitions")
        self.define_types()

        # Using the types we defined, instantiate structs at the right addresses
        qprint("[*] Creating OID structs")
        self.oid_struct_addrs = self.create_structs()
        if len(self.oid_struct_addrs) == 0:
            qprint("[-] No oid structs found")
            return

        qprint(f"[+] Identified {len(self.oid_struct_addrs)} sysctl OIDs")

        qprint("[*] Tagging OIDs")
        # Create nice struct views of all the sysctl oids
        for addr in self.oid_struct_addrs:
            # Mark the location with a tag for easy access later
            self.mark_with_tag(addr)

            # Create a programmatic view of the struct that we can peek into later
            s = StructuredDataView(self.bv, "sysctl_oid", addr)
            self.oid_structs.append(s)

        # Get the handler function for each oid
        for s in self.oid_structs:
            handler = self.get_handler(s)
            if handler is not None:
                self.oid_handler_funcs.append(handler)

        # Fix up the function prototype for sysctl handlers
        qprint(
            f"[*] Correcting prototype for {len(self.oid_handler_funcs)} OID handlers"
        )
        for f in self.oid_handler_funcs:
            self.set_fn_type(f)

        # Dump all the OIDs that we've collected so far
        qprint("[*] Dumping OIDs")
        for s in self.oid_structs:
            self.summarize_oid(s)

    # Save the current BinaryView into a database at the specified location
    def save(self, path):
        self.bv.create_database(path)

    # Take a list of Function references, and modify their prototype to match that of oid_handler
    def set_fn_type(self, f: Function):
        params = [
            types.FunctionParameter(
                Type.pointer(self.bv.arch, self.bv.types["sysctl_oid"]), "oidp"
            ),
            types.FunctionParameter(Type.pointer(self.bv.arch, Type.void()), "arg1"),
            types.FunctionParameter(Type.int(4), "arg2"),
            types.FunctionParameter(
                Type.pointer(self.bv.arch, self.bv.types["sysctl_req"]), "req"
            ),
        ]
        fn_type = Type.function(Type.int(4), params)
        f.function_type = fn_type

    # Create the struct types required
    def define_types(self):
        # Register the types
        oid_types = self.bv.parse_types_from_string(OID_DEFS)
        for name in oid_types.types:
            self.bv.define_user_type(name, oid_types.types[name])
        self.bv.create_tag_type("Sysctl OID", "💡")

    # For each call of sysctl_register_oid, get the referenced parameter address and create a struct there
    def create_structs(self):
        # We'll store the struct addrs here
        struct_addrs = []

        # Find all of the calls to sysctl_register_oid()
        reg_oid = self.bv.symbols["_sysctl_register_oid"][0]
        callers = self.bv.get_callers(reg_oid.address)
        for c in callers:
            # For each call site, the first parameter will be a pointer to a sysctl_oid struct. We need
            # to set the type for this parameter.
            inst: MediumLevelILInstruction = c.function.get_llil_at(c.address).mlil

            # We only care about function calls of sysctl_register_oid
            if inst.operation != MediumLevelILOperation.MLIL_CALL:
                continue

            # Get the address of the first parameter
            if inst.params[0].operation != MediumLevelILOperation.MLIL_CONST_PTR:
                continue
            param_addr = inst.params[0].constant
            struct_addrs.append(param_addr)

            # Create a user data var at the address (set the type of the data at address to a user-defined type)
            self.bv.define_user_data_var(param_addr, self.bv.types["sysctl_oid"])
        return struct_addrs

    def get_handler(self, sd: StructuredDataView):
        handler_addr = int.from_bytes(sd.oid_handler.value, "little")
        # Handle this more gracefully later, represents an oid container (no handler func)
        if handler_addr == 0:
            return None
        handler_func: Function = self.bv.get_function_at(handler_addr)
        return handler_func

    # Take an integer and create a list of OID flags from it
    def flag_strings(self, flags: int):
        flagset = []
        for k in OID_FLAGS:
            if flags & k:
                flagset.append(OID_FLAGS[k])
        for k in OID_TYPES:
            if (flags & 0xF) == k:
                flagset.append(OID_TYPES[k])
        return flagset

    # Mark the specified address with a tag denoting an OID
    def mark_with_tag(self, addr: int):
        self.bv.create_user_data_tag(
            addr, self.bv.tag_types["Sysctl OID"], "Sysctl OID", False
        )

    # Try to infer the full OID path from debug symbols
    def get_oid_path(self, oid: StructuredDataView):
        sym = self.bv.get_symbol_at(oid._address)
        # No symbol to work from, bye!
        if not sym:
            return "<Unknown>"
        sym = sym.short_name

        name_addr = int.from_bytes(oid.oid_name.value, "little")
        name = self.bv.get_ascii_string_at(name_addr)
        if not name_addr:
            return "<Unknown>"
        name = name.value

        sym = sym.lstrip("_")
        sym = sym.replace("sysctl__", "", 1)
        p = sym.split(name)[0]
        p = p.replace("_", ".", -1) + name
        return p

    # Take the view of the OID and dump the interesting information as json
    def summarize_oid(self, oid: StructuredDataView):
        handler_addr = int.from_bytes(oid.oid_handler.value, "little")
        name_addr = int.from_bytes(oid.oid_name.value, "little")
        desc_addr = int.from_bytes(oid.oid_descr.value, "little")
        flags = int.from_bytes(oid.oid_kind.value, "little")
        fmt_addr = int.from_bytes(oid.oid_fmt.value, "little")

        summary = {}

        # Extract a nice representation of the flags
        flags = self.flag_strings(flags)
        summary["flags"] = flags

        # is it a container or a leaf?
        if "CTLTYPE_NODE" in summary["flags"]:
            summary["type"] = "container"
        else:
            summary["type"] = "leaf"

        if handler_addr != 0:
            handler_func: Function = self.bv.get_function_at(handler_addr)
            if handler_func:
                _, demangled_name = demangle.demangle_gnu3(
                    self.bv.arch, handler_func.name
                )
                summary["handler"] = demangled_name[0]

        if name_addr != 0:
            name: StringReference = self.bv.get_ascii_string_at(name_addr, min_length=0)
            if name:
                summary["name"] = name.value

        if desc_addr != 0:
            desc = self.bv.get_ascii_string_at(name_addr, min_length=0)
            if desc:
                summary["description"] = desc.value

        if fmt_addr != 0:
            fmt = self.bv.get_ascii_string_at(fmt_addr, min_length=0)
            if fmt:
                summary["fmt"] = fmt.value

        summary["path"] = self.get_oid_path(oid)

        print(json.dumps(summary))


# Given a kext directory path, get the path to the bundle executable
def resolve_kext_path(path: str):
    macho_name = get_macho_name(path)
    if not macho_name:
        return None
    return get_macho_path(path, macho_name)


# Identify the Plist in the bundle, and read out the CFBundleExecutable tag
def get_macho_name(path: str):
    f = None
    for i in ["/Contents/Info.plist", "/Info.plist"]:
        try:
            f = open(path + i, "rb")
            kext_info = plistlib.load(f)
            if "CFBundleExecutable" in kext_info:
                return kext_info["CFBundleExecutable"]
        except Exception as e:
            continue
    return None


# Given a kext dir path and CFBundleExecutable name, identify the location of the executable within the bundle
def get_macho_path(path: str, macho_name: str):
    for i in ["/", "/Contents/MacOS/"]:
        pth = f"{path}{i}{macho_name}"
        p = Path(pth)
        if p.is_file():
            return pth
    return None


# Don't print if in quiet mode
def qprint(str):
    if not QUIET_MODE:
        print(str)


# Headless wrapper
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="XNU Sysctl Hunter will identify and dump Sysctl OIDs in the target Kext(s). Can optionally specify an output directory to save resulting BNDBs in."
    )
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-o", "--outdir", dest="bndb_outdir")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()

    QUIET_MODE = args.quiet

    # Create the output directory if it doesn't already exist
    if args.bndb_outdir:
        if not os.path.exists(args.bndb_outdir):
            os.makedirs(args.bndb_outdir)

    for path in args.files:
        filename = Path(path).name
        name, ext = os.path.splitext(filename)

        # Handle kernel extension directories
        if ext == ".kext" and os.path.isdir(path):
            path = resolve_kext_path(path)

        bv = BinaryViewType.get_view_of_file(path, update_analysis=True)
        if bv == None:
            qprint("[-] Failed to load binaryview")
            continue

        hunter = SysctlHunter(bv)
        if not hunter.is_valid():
            qprint("[-] Target doesn't reference sysctl_register_oid")
            continue

        hunter.run()
        if args.bndb_outdir:
            hunter.save(f"{args.bndb_outdir}/{filename}.bndb")
