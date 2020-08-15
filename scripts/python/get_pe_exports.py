#!/usr/bin/env python3
import sys
import pefile
import glob
import json

for arg in sys.argv[1:]:
    for file_name in glob.glob(arg, recursive=True):
        try:
            pe = pefile.PE(name=file_name)
        except pefile.PEFormatError:
            continue
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            continue
        export = pe.DIRECTORY_ENTRY_EXPORT
        dll_name = pe.get_string_at_rva(export.struct.Name)
        if not dll_name:
            continue
        if not export.symbols:
            continue
        for pe_export in export.symbols:
            if not pe_export.name:
                continue
            function_name = pe_export.name.decode('utf8')
            if not function_name.isidentifier():
                continue
            print(json.dumps(dict(dll=dll_name.decode('utf8'), name=function_name)))