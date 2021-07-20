from .hunter import SysctlHunter
from binaryninja import *


def find_sysctls(bv: BinaryView):
    hunter = SysctlHunter(bv)
    hunter.run()


PluginCommand.register(
    "Sysctl Hunter\\Identify OIDs",
    "Find Sysctl OIDs",
    find_sysctls,
    is_valid=lambda v: "_sysctl_register_oid" in v.symbols,
)
