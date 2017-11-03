#! /usr/bin/env python

import sys
import struct
import textwrap


class GenerateHash(object):

    def __init__(self, password):
        self.password = password
        self.key_length = 512
        self.key = ''
        self.digest_variables = [
            0x92849382,
            0x38493843,
            0x73829211,
            0x48902384,
            0x83703979
        ]


    def _shift_rows(self, chunk, bits):
        return ((chunk << bits) | (chunk >> (16 - bits))) & 0xffffffff


    def _convert_password_to_int(self):
        converted_password = ''

        for character in self.password:
            converted_password = converted_password + str(ord(character))

        self.password = int(converted_password)
        self._pad_password()
        return self


    def _pad_password(self):
        password = str(self.password)

        while len(password) < (self.key_length * 2):
            first_half, second_half = int(password[:len(password)/2]), int(password[len(password)/2:])
            new_value = str((first_half & second_half) ^ int(password))
            password = password + new_value

            if (str(self.password) in password) and (len(password) < self.key_length / 4):
                password = password.replace(str(self.password), '')

        self.password = password[:(self.key_length * 2)]
        return self


    def _process_chunk(self, chunk):
        assert len(chunk) == 64

        #print chunk

        chunks = []

        for i in range(0, 64, 8):
            chunks.append(self._shift_rows(int(chunk[i:i + 8]), 3))

        matrix = [None] * 64

        for i in range(8):
            matrix[i] = self._shift_rows(chunks[i], 1)

        for i in range(8, 64):
            matrix[i] = self._shift_rows(matrix[i - 8] + matrix[i - 2] + matrix[i - 5], 8)

        candidate = ''

        #print matrix

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

        #print format(int(candidate[-64:]), 'x')

        return format(int(candidate[:64]), 'x')


    def _gen_key(self):
        self._convert_password_to_int()

        for chunk in range(0, self.key_length, 64):
            chunk = self.password[chunk:chunk + 64]

            #print chunk

            self.key = self.key + self._process_chunk(chunk)

        return self.key


    def hexdigest(self):
        return self._gen_key()


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
