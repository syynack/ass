#! /usr/bin/env python

import click
import sys
import struct
import textwrap


class GenerateHash(object):
    ''' Class for generating a hash based off a user entered password. '''

    def __init__(self, password, key_length = 1024):
        self.password = password
        self.key_length = key_length
        self.key = ''
        self.digest_variables = [
            0x92849382,
            0x38493843,
            0x73829211,
            0x48902384,
            0x83703979
        ]


    def _shift_rows(self, chunk, bits):
        ''' Shift a row by using bitwise shift and AND operators. '''

        return ((chunk << bits) | (chunk >> (16 - bits))) & 0xffffffff


    def _convert_password_to_int(self):
        ''' Converts the password plaintext string to integer for processing. '''

        converted_password = ''

        for character in self.password:
            converted_password = converted_password + str(ord(character))

        self.password = int(converted_password)
        self._pad_password()
        return self


    def _pad_password(self):
        '''
        User input password is probably less that the key length, so this
        function adds extra padding to the password so that it can be processed in
        chunks.
        '''
        password = str(self.password)

        while len(password) < (self.key_length * 2):
            first_half, second_half = int(password[:len(password)/2]), int(password[len(password)/2:])
            new_value = str((first_half | second_half) & int(password))
            password = password + new_value

            if (str(self.password) in password) and (len(password) < self.key_length / 4):
                password = password.replace(str(self.password), '')

        self.password = password[:(self.key_length * 2)]
        return self


    def _process_chunk(self, chunk):
        ''' Processes 64 bit chunk of the converted password to a ciphertext value. '''

        assert len(chunk) == 64
        chunks = []

        for i in range(0, 64, 8):
            chunks.append(self._shift_rows(int(chunk[i:i + 8]), 3))

        matrix = [None] * 64

        for i in range(8):
            matrix[i] = self._shift_rows(chunks[i], 1)

        for i in range(8, 64):
            matrix[i] = self._shift_rows(matrix[i - 8] + matrix[i - 2] + matrix[i - 5], 8)

        candidate = ''

        for item in matrix:
            if 0 <= int(str(item)[:2]) <= 19:
                candidate_chunk = (item ^ self.digest_variables[0]) & 0xffff
            elif 20 <= int(str(item)[:2]) <= 39:
                candidate_chunk = (item ^ self.digest_variables[1]) & 0xffff
            elif 40 <= int(str(item)[:2]) <= 59:
                candidate_chunk = (item ^ self.digest_variables[2]) & 0xffff
            elif 60 <= int(str(item)[:2]) <= 79:
                candidate_chunk = (item ^ self.digest_variables[3]) & 0xffff
            elif 80 <= int(str(item)[:2]) <= 99:
                candidate_chunk = (item ^ self.digest_variables[4]) & 0xffff

            candidate_chunk = candidate_chunk & 0x3E
            candidate = candidate + str(candidate_chunk)

        return format(int(candidate[:64]), 'x')


    def _gen_key(self):
        ''' Manages the chunks of password bieng processed into cipher text. '''
        self._convert_password_to_int()

        for chunk in range(0, self.key_length, 64):
            chunk = self.password[chunk:chunk + 64]

            self.key = self.key + self._process_chunk(chunk)

        return self.key


    def hexdigest(self):
        ''' Returns the actual hex digest. '''
        return self._gen_key()


@click.command(help = 'Generate a hash key based on a password.')
@click.option('-k', '--key-length', type=click.Choice(['256', '512', '1024', '2048', '4096']))
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
def main(key_length, password):
    if not password:
        print 'ERROR: No password entered!'
        sys.exit(1)

    test_hash = GenerateHash(
        key_length = int(key_length),
        password = password
    )

    print "\nKEY: {}\n".format(test_hash.hexdigest())


if __name__ == "__main__":
    main()
