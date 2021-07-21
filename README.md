XNU Sysctl Hunter
====================
XNU Sysctl Hunter is a tool for analyzing Kexts that will automatically identify, type, and tag sysctl OIDs, as well as correct the prototypes of their OID handler functions. It contains a Binary Ninja plugin action, as well as a headless script for batch processing.

# Screenshots
OID structures are created, and their location is tagged for review later:
![Tagged OIDs](screenshots/tagged_oids.png?raw=true "OIDs get tagged")

OID handler function prototypes are corrected:
![Prototypes Corrected](screenshots/prototype.png?raw=true "OID Handler Prototypes Corrected")

## Headless Usage
Call it from the command line targeting a single kext:
```
$ ./hunter.py /System/Library/Extensions/L2TP.kext
[*] Creating necessary type definitions
[*] Creating OID structs
[+] Identified 3 sysctl OIDs
[*] Tagging OIDs
[*] Correcting prototype for 1 OID handlers
[*] Dumping OIDs
{"flags": ["CTLFLAG_RD", "CTLFLAG_WR", "CTLFLAG_NOAUTO", "CTLFLAG_KERN", "CTLFLAG_OID2", "CTLTYPE_INT"], "type": "leaf", "handler": "_", "name
": "nb_threads", "description": "nb_threads", "path": "net.ppp.l2tp.nb_threads"}
{"flags": ["CTLFLAG_RD", "CTLFLAG_WR", "CTLFLAG_NOAUTO", "CTLFLAG_KERN", "CTLFLAG_OID2", "CTLTYPE_INT"], "type": "leaf", "name": "thread_outq_
size", "description": "thread_outq_size", "path": "net.ppp.l2tp.thread_outq_size"}
{"flags": ["CTLFLAG_RD", "CTLFLAG_WR", "CTLFLAG_OID2", "CTLTYPE_NODE"], "type": "container", "name": "l2tp", "description": "l2tp", "path": "n
et.ppp.l2tp"}```

Suppress status lines with the `quiet` option:
```
$ ./hunter.py -q /System/Library/Extensions/L2TP.kext

{"flags": ["CTLFLAG_RD", "CTLFLAG_WR", "CTLFLAG_NOAUTO", "CTLFLAG_KERN", "CTLFLAG_OID2", "CTLTYPE_INT"], "type": "leaf", "handler": "_", "name
": "nb_threads", "description": "nb_threads", "path": "net.ppp.l2tp.nb_threads"}
{"flags": ["CTLFLAG_RD", "CTLFLAG_WR", "CTLFLAG_NOAUTO", "CTLFLAG_KERN", "CTLFLAG_OID2", "CTLTYPE_INT"], "type": "leaf", "name": "thread_outq_
size", "description": "thread_outq_size", "path": "net.ppp.l2tp.thread_outq_size"}
{"flags": ["CTLFLAG_RD", "CTLFLAG_WR", "CTLFLAG_OID2", "CTLTYPE_NODE"], "type": "container", "name": "l2tp", "description": "l2tp", "path": "n
et.ppp.l2tp"}```

Save the BNDB for more reversing later (OIDs are marked in the Tags section):
```
$ ./hunter.py -q -o /tmp/ /System/Library/Extensions/L2TP.kext

{"flags": ["CTLFLAG_RD", "CTLFLAG_WR", "CTLFLAG_NOAUTO", "CTLFLAG_KERN", "CTLFLAG_OID2", "CTLTYPE_INT"], "type": "leaf", "handler": "_", "name
": "nb_threads", "description": "nb_threads", "path": "net.ppp.l2tp.nb_threads"}
{"flags": ["CTLFLAG_RD", "CTLFLAG_WR", "CTLFLAG_NOAUTO", "CTLFLAG_KERN", "CTLFLAG_OID2", "CTLTYPE_INT"], "type": "leaf", "name": "thread_outq_
size", "description": "thread_outq_size", "path": "net.ppp.l2tp.thread_outq_size"}
{"flags": ["CTLFLAG_RD", "CTLFLAG_WR", "CTLFLAG_OID2", "CTLTYPE_NODE"], "type": "container", "name": "l2tp", "description": "l2tp", "path": "n
et.ppp.l2tp"}

$ ls /tmp/
L2TP.kext.bndb
```

Batch process a whole directory of Kexts and save the results
```
$ ./hunter.py -q -o ./bndbs /System/Library/Extensions/*
```

Filter JSON output to analyze attributes in bulk
```
$ ./hunter.py -q /System/Library/Extensions/L2TP.kext | jq -r '.path'
net.ppp.l2tp.nb_threads
net.ppp.l2tp.thread_outq_size
net.ppp.l2tp
```
