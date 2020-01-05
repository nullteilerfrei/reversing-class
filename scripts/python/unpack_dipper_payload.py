import pefile
import struct
import sys
import io

from aplib import Decompress


def main(offset, size):
    pe = pefile.PE(sys.argv[1])
    offset = pe.get_offset_from_rva(offset - pe.OPTIONAL_HEADER.ImageBase)

    with open(sys.argv[1], 'rb') as stream:
        chunk_count = size // 4
        stream.seek(offset, 0)
        payload = stream.read(size)
        payload = struct.pack('bb' * chunk_count, *struct.unpack('xxbb' * chunk_count, payload))
        fmt = '<{}I'.format(chunk_count // 2)
        payload = list(struct.unpack(fmt, payload))
        for k, b in enumerate(payload):
            t = b ^ 0x26FE
            t = (t << 4 | t >> 0x1C) + 0x77777778
            payload[k] = t & 0xFFFFFFFF

    payload_wrapper = io.BytesIO(struct.pack(fmt, *payload))
    payload = Decompress(payload_wrapper, verbose=False).do()

    with open(sys.argv[1] + '.payload', 'wb') as stream:
        stream.write(payload)

if __name__ == '__main__':
    main(0x01011240, 0x1e348)