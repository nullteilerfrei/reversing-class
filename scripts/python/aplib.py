#Kabopan - Readable Algorithms. Public Domain, 2007-2009
"""
aPLib, LZSS based lossless compression algorithm
Jorgen Ibsen U{http://www.ibsensoftware.com}
Original: http://code.google.com/p/kabopan/source/browse/trunk/kbp/comp/aplib.py
"""

import sys
import io


class BitsDecompress:
    """bit machine for variable-sized auto-reloading tag decompression"""
    def __init__(self, data, tag_size, verbose=True):
        self.__current_bit = 0  # The count of bits available to use in the tag
        self.__tag = None  # The tag is a bitstream dispersed through the file and read in chunks.
                           # This is the current chunk, shifted so the MSB is the next bit.
        self.__tag_size = tag_size  # Number of bytes per bitstream chunk, 1 by default
        self.__in = data  # The stream
        self.out = bytearray()
        self.max_offset = 0
        self.max_match_length = 0
        self.bits_count = 0
        self.bytes_count = 0
        self.verbose = verbose

    def read_bit(self):
        """read next bit from the stream, reloads the tag if necessary"""
        
        if self.__current_bit != 0:
            # Move to the next bit
            self.__current_bit -= 1
        else:
            # Select the MSB
            self.__current_bit = (self.__tag_size * 8) - 1
            # Read new data
            self.__tag = self.read_byte()
            self.bytes_count -= 1
            for i in range(self.__tag_size - 1):
                self.__tag += self.read_byte() << (8 * (i + 1))

        # Then extract the bit in question
        bit = (self.__tag >> ((self.__tag_size * 8) - 1)) & 0x01
        # And shift it out of the tag
        self.__tag <<= 1
        self.bits_count += 1
        return bit

    def read_byte(self):
        """read next byte from the stream"""
        result = self.__in.read(1)[0]
        self.bytes_count += 1
        return result

    def read_fixed_number(self, num_bits, init=0):
        """reads a fixed bit-length number"""
        result = init
        for i in range(num_bits):
            result = (result << 1) + self.read_bit()
        return result

    def read_variable_number(self):
        """return a variable bit-length number x, x >= 2
        reads a bit until the next bit in the pair is not set"""
        result = 1
        result = (result << 1) + self.read_bit()
        while self.read_bit():
            result = (result << 1) + self.read_bit()
        return result

    def read_set_bits(self, max_bits, set_value=1):
        """read bits as long as their set or a maximum is reached"""
        # Reads consecutive set bits from the bitstream, up to max_bits or until a zero is encountered.
        # Returns the number of set bits read.
        result = 0
        while result < max_bits and self.read_bit() == set_value:
            result += 1
        return result

    def back_copy(self, offset, length=1):
        s = "offset %d, length %d:" % (offset, length)
        for i in range(length):
            b = self.out[-offset]
            s += " %02x" % b
            self.out.append(b)
        self.print(s)
        self.max_offset = max(self.max_offset, offset)
        self.max_match_length = max(self.max_match_length, length)
        return

    def read_literal(self, value=None):
        if value is None:
            b = self.read_byte()
            self.print("%02x" % b)
            self.out.append(b)
        else:
            self.print("%02x" % value)
            self.out.append(value)
        return False

    def print(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)


class Decompress(BitsDecompress):
    def __init__(self, data, verbose=True):
        BitsDecompress.__init__(self, data, tag_size=1, verbose=verbose)
        self.__pair = True    # paired sequence
        self.__last_offset = 0
        self.__functions = [
            self.__literal,      # 0 = literal
            self.__block,        # 1 = block
            self.__short_block,  # 2 = short block
            self.__single_byte]  # 3 = single byte
        return

    def __literal(self):
        self.print("Literal: ", end="")
        self.read_literal()
        self.__pair = True
        return False

    def __block(self):
        b = self.read_variable_number() - 2
        if b == 0 and self.__pair:    # reuse the same offset
            offset = self.__last_offset
            length = self.read_variable_number()    # 2-
            self.print("Block with reused ", end="")
        else:
            if self.__pair:
                b -= 1
            offset = b * 256 + self.read_byte()
            length = self.read_variable_number()    # 2-
            length += self.__length_delta(offset)
            self.print("Block with encoded ", end="")
        self.__last_offset = offset
        self.back_copy(offset, length)
        self.__pair = False
        return False

    @staticmethod
    def __length_delta(offset):
        if offset < 0x80 or 0x7D00 <= offset:
            return 2
        elif 0x500 <= offset:
            return 1
        return 0

    def __short_block(self):
        b = self.read_byte()
        if b <= 1:    # likely 0
            self.print("Short block offset %d: EOF" % b)
            return True
        length = 2 + (b & 0x01)    # 2-3
        offset = b >> 1    # 1-127
        self.print("Short block ", end="")
        self.back_copy(offset, length)
        self.__last_offset = offset
        self.__pair = False
        return False

    def __single_byte(self):
        offset = self.read_fixed_number(4)  # 0-15
        if offset:
            self.print("Single byte ", end="")
            self.back_copy(offset)
        else:
            self.print("Single byte zero: ", end="")
            self.read_literal(0)
        self.__pair = True
        return False

    def do(self):
        """returns decompressed buffer and consumed bytes counter"""
        # First byte is a literal
        self.print("Initial literal: ", end="")
        self.read_literal()
        while True:
            # Read the gamma-coded (?) bitstream and then execute the relevant decoder based on what's found
            if self.__functions[self.read_set_bits(3)]():
                break
        return self.out

if __name__ == "__main__":
    input_file = open(sys.argv[1], "rb")
    decompressor = Decompress(input_file)
    decompressed = decompressor.do()
    output_file = open(sys.argv[1] + ".out", "wb")
    output_file.write(decompressed)
    output_file.close()
    input_file.close()
    print("Max backref distance %d, max backref length %d" % (decompressor.max_offset, decompressor.max_match_length))
    print("%d bits (= %d bytes) + %d bytes data" % (
        decompressor.bits_count,
        decompressor.bits_count / 8,
        decompressor.bytes_count))
    compressed_size = decompressor.bits_count / 8 + decompressor.bytes_count
    decompressed_size = len(decompressed)
    ratio = (decompressed_size - compressed_size) / decompressed_size
    print("Total: %d bytes decompressed to %d bytes (%.2f%% compression)" % (compressed_size, decompressed_size, ratio * 100))

"""

The format is:

1st byte: literal

Remaining bytes: a bitstream interleaved with byte-sized data where appropriate.

The bitstream is read left to right. It encodes four different types of data, plus parameters where appropriate. As
soon as a byte of extra data is needed, it is stored in the following byte in the file (byte-aligned). The bitstream
then skips past the data as it continues.

The four different types of data are encoded as:

literal     -> 0
block       -> 10
short block -> 110
single byte -> 111

0: literal
==========

One byte of data is emitted.

1: block
========

An LZ block, referencing some data previously emitted. Offset and length are unlimited.

First parameter: encoded_offset, variable-length number (in bitstream)
Second parameter: length, variable-length number (in bitstream)

If encoded_offset == 2 and the last block was a literal or a single byte then
    Emit length bytes from (last_offset) bytes ago
Else
    last_offset = (encoded_offset - 3) << 8 + next_byte()
    if (0 <= length <= 127) length += 2
    else if (1280 <= length < 32000) length += 1
    else if (length >= 32000) length += 2;
    Emit length bytes from (last_offset) bytes ago

Note that you can have encoded_offset = 2 and last block is not the right type; this results in the decoded offset
being somewhat screwy - I'm not sure this ever happens. The Z80 decoder will have on offset of $ffnn at this point.

2: short block
==============

An LZ block, encoded in a single byte. The offset is in the range 1..127 (7 bits)
and the length in the range 2..3 (1 bit).

Next byte is (offset << 1) | (length - 2)
If offset = 0 then
    This is the end of the file - terminate
Else
    Emit length bytes from (offset) bytes ago
    last_offset = offset

3: single byte
==============

An LZ block with a length of 1, encoded in four bits.

Parameter: offset, 4-bit number (in bitstream)

If offset = 0
    Emit 0
Else
    Emit 1 byte from (offset) bytes ago

Variable length numbers
=======================

These are numbers with value at least 2. They are encoded as:

1. The highest bit is implicit
2. The next bit is emitted
3. If there are more bits, a 1 is emitted and go to 2, else a zero is emitted

Decoding is the reverse. Here's some examples:

Example     Binary      Encoding
2           10          00
3           11          10
4           100         0100
7           111         1110
14          1110        111100
170         10101010    01110111011100

This results in a more compact representation for smaller numbers, plus (in theory) no limit to the size of the number
encoded.

Analysis
========

Literals (after the first byte) cost 10 bits per byte to encode.
LZ runs where there are occasional bytes which have changed are able to avoid encoding the offset more than once.
These occasional differences then have two different ways to encode the non-matching byte (a literal, or a 4-bit
encoded reference to a recent value (or zero).

"""