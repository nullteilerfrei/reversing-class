#!/usr/bin/env python3
import json
import sys
import argparse as ap

def calc_hash_5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93(function_name):
    ret = 0x2b
    for c in function_name:
        ret = ret * 0x10f + ord(c)
    return (ret ^ 0xafb9) & 0x1fffff


def calc_hash(function_name):
    ret = 0x2b
    for c in function_name:
        ret = ret * 0x10f + ord(c)
    return (ret ^ 0x12e9) & 0x1fffff

if __name__ == '__main__':
    argp = ap.ArgumentParser()
    argp.add_argument('input', type=ap.FileType('r'))
    argp.add_argument('output', nargs='?', default=sys.stdout, type=ap.FileType('w'))
    args = argp.parse_args()
    for line in args.input:
        export = json.loads(line)
        export['hash'] = calc_hash(export['name'])
        print(json.dumps(export), file=args.output)
