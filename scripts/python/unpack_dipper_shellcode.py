import pefile
import struct
import sys


def main(offset, size):
    pe = pefile.PE(sys.argv[1])
    offset = pe.get_offset_from_rva(offset - pe.OPTIONAL_HEADER.ImageBase)

    with open(sys.argv[1], 'rb') as stream:
        stream.seek(offset, 0)
        payload = stream.read(size * 4)
        fmt = '<{}I'.format(size)
        payload = list(struct.unpack(fmt, payload))
        for k, b in enumerate(payload):
            t = b ^ 0x10A1
            t = (t << 4 | t >> 0x1C) + 0x77777778
            payload[k] = t & 0xFFFFFFFF

    with open(sys.argv[1] + '.shellcode', 'wb') as stream:
        stream.write(struct.pack(fmt, *payload))

if __name__ == '__main__':
    main(0x01010648, 765)