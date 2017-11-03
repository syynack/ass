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
            0x83703979
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
        return ((chunk << bits) | (chunk >> (16 - bits))) & 0xffffffff


    def _process_chunk(self, chunk):
        assert len(chunk) == 64
        chunks = []

        for i in range(0, 64, 8):
            chunks.append(self._shift_rows(int(chunk[i:i + 8]), 3))

        matrix = [None] * 64

        for i in range(8):
            matrix[i] = self._shift_rows(chunks[i], 1)

        for i in range(8, 64):
            matrix[i] = self._shift_rows(matrix[i - 8] + matrix[i - 2] + matrix[i - 5], 1)

        candidate = ''

        for item in matrix:
            if 0 <= int(str(item)[:2]) <= 19:
                candidate_chunk = (item ^ self.digest_variables[0]) & 0xff
            elif 20 <= int(str(item)[:2]) <= 39:
                candidate_chunk = (item ^ self.digest_variables[1]) & 0xff
            elif 40 <= int(str(item)[:2]) <= 59:
                candidate_chunk = (item ^ self.digest_variables[2]) & 0xff
            elif 60 <= int(str(item)[:2]) <= 79:
                candidate_chunk = (item ^ self.digest_variables[3]) & 0xff
            elif 80 <= int(str(item)[:2]) <= 99:
                candidate_chunk = (item ^ self.digest_variables[4]) & 0xff

            candidate = candidate + str(candidate_chunk)

        return format(int(candidate[:64]), 'x')


    def _gen_key(self):
        for chunk in range(0, self.key_length, 64):
            self.shift_bits = 1
            chunk = self.password[chunk:chunk + 64]

            self.key = self.key + self._process_chunk(chunk)

        print self.key


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
    test_hash.hexdigest()


if __name__ == "__main__":
    main(sys.argv[1])
