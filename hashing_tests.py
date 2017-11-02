#! /usr/bin/env python

import sys
import struct
import textwrap


class GenerateHash(object):

    def __init__(self, password):
        self.password = password
        self.key_length = 1024
        self.key = ''
        self.digest_variables = [
            0x92849382,
            0x38493843,
            0x73829211,
            0x48902384,
            0x83703979,
            0x56382990,
            0x47384039,
            0x09300021
        ]


    def _convert_password_to_int(self):
        converted_password = ''

        for character in self.password:
            converted_password = converted_password + str(ord(character))

        self.password = converted_password
        self._pad_password()


    def _pad_password(self):
        padded_password = ''
        password = textwrap.wrap(self.password, 8)

        while len(padded_password) < (self.key_length * 2):
            for chunk in password:
                padded_password = padded_password + str(int(chunk) & 0xffffffff)

        self.password = padded_password[:(self.key_length * 2)]
        self._gen_key()


    def _shift_rows(self, chunk, bits):
        return ((chunk << bits) | (chunk >> (64 - bits))) & 0xffffffff


    def _process_chunk(self, chunk):
        assert len(chunk) == 64
        chunk = self._shift_rows(int(chunk), self.shift_bits)

        chunks = struct.pack('>Q', chunk)
        chunks = [ord(chunk) for chunk in chunks]

        matrix = [None] * 128

        for i in range(8):
            matrix[i] = chunks[i]

        for i in range(8, 128):
            matrix[i] = int(str(self._shift_rows((matrix[i-8] | matrix[i-1]) ^ (matrix[i-3] & matrix[i-5]), 1))[:2])

        d_1 = self.digest_variables[0]
        d_2 = self.digest_variables[1]
        d_3 = self.digest_variables[2]
        d_4 = self.digest_variables[3]
        d_5 = self.digest_variables[4]
        d_6 = self.digest_variables[5]
        d_7 = self.digest_variables[6]
        d_8 = self.digest_variables[7]

        for i in range(128):
            # mod stuff



    def _gen_key(self):
        for chunk in range(0, self.key_length, 64):
            self.shift_bits = 1
            chunk = self.password[chunk:chunk + 64]

            self.key = self.key + self._process_chunk(chunk)


    def hexdigest(self):
        self._convert_password_to_int()


def main(password):
    '''
    if len(password) > KEY_LENGTH:
        print "Key is longer than can be processed."
        sys.exit(1)
    '''

    password = str(password)

    test_hash = GenerateHash(password)
    print test_hash.hexdigest()


if __name__ == "__main__":
    main(sys.argv[1])
