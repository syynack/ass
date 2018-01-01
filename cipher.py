#! /usr/bin/env python
# Written by Matthew Lovatt for Advanced Software Security at Staffordshire Univeristy.

import binascii
import click
import os
import textwrap
import sys

BINARY_TEMPLATE = '{0:0{1}b}'
SBOX_0 = [
    ['\x00', ' ', '\x04', '\x87', '\x08', 'K', '\x0c', '\x8f', '\x10', 'Q', '\x14', '\x97', '\x18', '}', 'x', '\x9f'],
    ['\x83', '\xa3', '$', '\xa7', '(', '\xab', ',', '\xaf', '0', '\xb3', '4', '\xb7', '8', '\xbb', '<', '\xbf'],
    ['@', '\xc3', 'D', '\xc7', 'H', '\xcb', 'L', '\xcf', 'P', '\xd3', 'T', '\xd7', 'X', '\xdb', '\\', '\xdf'],
    ['`', '\xe3', '\xf3', '\xe7', 'h', '\xeb', 'l', '\xef', 'p', 'd', 't', '\xf7', '\x1c', '\xfb', '|', '\xff'],
    ['I', '\x03', '\x84', 'U', 'E', '\x0b', '3', '\x0f', '\x90', '\x13', '\x94', '~', '\x98', 'N', '2', '\x1f'],
    ['#', '\xa0', '\xa4', "'", '\xa8', '+', '\xac', '/', '\xb0', '\x8c', '\xb4', '7', '\xb8', ';', '\xbc', '?'],
    ['\xc0', '\xc1', '\xc4', 'G', 'V', 'n', '\xcc', 'O', '\xd0', 'S', '\xd4', 'W', '\xd8', '[', '\xdc', '_'],
    ['\xe0', 'c', '\xe4', 'g', '\xe8', 'k', '\xec', '\xee', '\xf0', 's', '\xf4', 'w', '\xf8', '{', '\xfc', '\x7f'],
    ['\x81', '\x02', '\x85', 'M', 'i', '\n', '\x8d', '\x0e', 'R', '\x12', '\x95', '9', 'y', '\x1a', '\x9d', 'q'],
    ['\xa1', '"', '\xa5', '&', '\xa9', '*', '\xad', '.', '\xb1', '\x9c', '\xb5', '6', '\xb9', ':', '\xbd', '>'],
    ['B', 'C', '\xc5', 'F', '\xc9', 'J', '\xcd', '\x1b', '\xd1', '\x91', '\xd5', '\xc8', '\xd9', 'Z', '\xdd', '^'],
    ['\xe1', 'A', '\xe5', 'f', '\xe9', 'j', '\xed', '\x8b', '\xf1', 'r', '\xf5', 'v', '\xf9', 'z', '\xfd', '\x17'],
    ['\x01', '\x82', '\x05', '\x86', '\t', '\x8a', '\r', '\x8e', '\x11', '\x92', '\x15', '\x96', '\x19', '\x9a', '\x1d', '\x9e'],
    ['!', '\xa2', '%', '\xa6', ')', '\xaa', '-', '\xae', '1', '\xb2', '5', '\xb6', '\x16', '\xba', '=', '\xbe'],
    ['b', '\xc2', '\x88', '\xc6', '\x80', '\xca', '\x06', '\xce', '\x93', '\xd2', '\x07', '\xd6', 'Y', '\xda', ']', '\xde'],
    ['a', '\xe2', 'e', '\xe6', '\x89', '\xea', 'm', 'o', '\x1e', '\xf2', 'u', '\xf6', '\x99', '\xfa', '\x9b', '\xfe']
]

class Public():
    def calculate_round_keys(self, key, encryption_rounds, round_keys):
        '''
        Format plaintext key provided by user into binary and split into a list of bytes. Reduce key
        to a list of 32 bit length (4 * 4 bytes) by XORing each key segment with the next. Initiate
        round key list with the first two elements and resume key expansion by XORing the key four positions
        away with the key one position away from the current position in the list.
        '''

        key = ''.join(format(ord(i), 'b') for i in key)
        split_key = textwrap.wrap(key, 8)

        while len(split_key) != 4:
            for i in range(0, len(split_key), 2):
                k1 = split_key[i-1]
                k2 = split_key[i]
                split_key[i-1] = BINARY_TEMPLATE.format(int(k1, 2) ^ int(k2, 2), 8)

            del split_key[0]

            '''
            Was using this in a previous iteration, found out it wasn't needed. Keeping in anyway.

            while len(split_key) % 4 != 0:
                split_key[0] = BINARY_TEMPLATE.format(int(split_key[0], 2) ^ int(split_key[1], 2), 8)
                del split_key[1]

            split_key = split_key[1::2]
            '''

        round_keys = round_keys + (split_key + ([None] * (encryption_rounds - 4)))

        for i in range(4, len(round_keys)):
            round_keys[i] = BINARY_TEMPLATE.format(int(round_keys[i - 4], 2) ^ int(round_keys[i - 1], 2), 8)

        return round_keys


class Encrypt():
    ''' Class to encrypt plaintext contents of a file into encrypted ciphertext. '''

    def __init__(self, plaintext_file, key, key_length):
        self.plaintext_file = plaintext_file
        self.key = key
        self.key_length = 128
        self.encryption_rounds = 0
        self.round_keys = []
        self.xored_plaintext_chunks = []
        self.plaintext_contents = ""
        self.ciphertext_contents = ""
        self.ciphertext_file = self.plaintext_file + '.encrypted'

        ''' Calculate number of encryption rounds based off entered key length. '''
        if self.key_length == 128:
            self.encryption_rounds = 16
        elif self.key_length == 256:
            self.encryption_rounds = 24
        elif self.key_length == 512:
            self.encryption_rounds = 32

    def _read_plaintext_file_contents(self):
        ''' Read plaintext data from the target file in a binary format. '''

        with open(self.plaintext_file, 'rb') as ptf:
            self.plaintext_contents = ptf.read()


    def _xor_binary_plaintext_chunks(self, chunk):
        '''
        Takes a 64 bit binary chunk of plaintext and splits into bytes. Then XORs each 8 bit block with each
        8 bit round key and places into xored_plaintext_chunks list.
        '''

        for key in self.round_keys:
            chunk = BINARY_TEMPLATE.format(int(chunk, 2) ^ int(key, 2), 8)

        self.xored_plaintext_chunks.append(chunk)


    def _add_initial_encryption(self):
        '''
        Split the plaintext file contents into 64 bit binary chunks and adds first encryption through
        XORing with round keys in _xor_binary_plaintext_chunks.
        '''

        binary_plaintext = ""

        for char in self.plaintext_contents:
            binary_plaintext = binary_plaintext + str(BINARY_TEMPLATE.format(ord(char), 8))

        chunks = textwrap.wrap(binary_plaintext, 8)

        for chunk in chunks:
            self._xor_binary_plaintext_chunks(chunk)


    def _substitute_xored_chunk(self, chunk):
        '''
        Takes a 1 byte chunk and splits it in half using the first for the Y axis and the second
        for the X axis when substituting for the corresponding value in SBOX_0.
        '''

        assert len(chunk) == 8
        assert isinstance(chunk, str)

        first_half, second_half = int(chunk[:4], 2), int(chunk[4:], 2)
        substition = SBOX_0[first_half][second_half]
        self.ciphertext_contents = self.ciphertext_contents + substition


    def _write_ciphertext_to_file(self):
        '''
        Creates a file with the same name as the plaintext file but appends ".encrypted" and writes
        ciphertext contents to it.
        '''

        with open(self.ciphertext_file, 'wb') as target_file:
            target_file.write(self.ciphertext_contents)


    def start_encryption(self):
        ''' Main controlling function for encryption. '''

        if self.plaintext_file is None:
            print "[!] Target file not specified. Exiting."
            sys.exit(1)

        self._read_plaintext_file_contents()
        self.round_keys = Public().calculate_round_keys(self.key, self.encryption_rounds, self.round_keys)
        self._add_initial_encryption()

        for chunk in self.xored_plaintext_chunks:
            self._substitute_xored_chunk(chunk)

        self._write_ciphertext_to_file()


class Decrypt():
    def __init__(self, encrypted_file, key, key_length = 128):
        self.key_length = key_length
        self.key = key
        self.encrypted_file = encrypted_file
        self.ciphertext_chunks = []
        self.encryption_rounds = 0
        self.round_keys = []
        self.decrypted_plaintext = ""
        self.plaintext_file = self.encrypted_file.split('.encrypted')[0]

        ''' Calculate number of encryption rounds based off entered key length. '''
        if self.key_length == 128:
            self.encryption_rounds = 16
        elif self.key_length == 256:
            self.encryption_rounds = 24
        elif self.key_length == 512:
            self.encryption_rounds = 32


    def _read_encrypted_data_from_file(self):
        ''' Stores data read from an encrypted file in 1 byte chunks. '''

        with open(self.encrypted_file, 'rb') as target_file:
            byte = target_file.read(1)
            while byte != "":
                self.ciphertext_chunks.append(byte)
                byte = target_file.read(1)


    def _substitute_ciphertext_chunks(self):
        '''
        Iterates over ciphertext chunks resubstituting them in SBOX_0 to find the indexes
        for the original 8 bit binary string.
        '''

        for index_0, chunk in enumerate(self.ciphertext_chunks):
            for sublist in SBOX_0:
                if chunk in sublist:
                    index_1 = SBOX_0.index(sublist)
                    index_2 = sublist.index(chunk)

            self.ciphertext_chunks[index_0] = "{0:04b}".format(index_1) + "{0:04b}".format(index_2)


    def _decrypt_xored_chunks(self):
        '''
        Process for undoing XORing in Encrypt()._xor_binary_plaintext_chunks(). Splits resubstituted chunks into a
        list of bytes. Reverses the encryption by XORing the chunk in reverse with each round key. Then joins the
        chunks to form a binary string,
        '''

        ciphertext_chunks = [self.ciphertext_chunks[x:x+8] for x in xrange(0, len(self.ciphertext_chunks), 8)]

        for index_0, chunk_list in enumerate(ciphertext_chunks):
            for index_1, chunk in enumerate(chunk_list):
                for key in self.round_keys[::-1]:
                    ciphertext_chunks[index_0][index_1] = BINARY_TEMPLATE.format(int(chunk, 2) ^ int(key, 2), 8)

        for index, sublist in enumerate(ciphertext_chunks):
            ciphertext_chunks[index] = ''.join(sublist)

        self.ciphertext_chunks = ''.join(ciphertext_chunks)


    def _process_plaintext_chunks(self):
        ''' Processes binary string in bytes to plaintext by using reverse of ord() function chr(). '''

        joined_ciphertext = ''.join(self.ciphertext_chunks)
        plaintext = ""

        for i in range(0, len(joined_ciphertext), 8):
            plaintext = plaintext + chr(int(joined_ciphertext[i:i+8], 2))

        self.decrypted_plaintext = plaintext


    def _write_plaintext_to_file(self):
        ''' Opens new plaintext file removing the .encryption extension. '''

        with open(self.plaintext_file, 'w') as target_file:
            target_file.write(self.decrypted_plaintext)


    def start_decryption(self):
        ''' Controlling function for decryption. '''

        self.round_keys = Public().calculate_round_keys(self.key, self.encryption_rounds, self.round_keys)
        self._read_encrypted_data_from_file()
        self._substitute_ciphertext_chunks()
        self._decrypt_xored_chunks()
        self._process_plaintext_chunks()
        self._write_plaintext_to_file()


@click.command(help = 'Encrypt a plaintext file.')
@click.option('-f', '--target-file', default = '', help = 'Target plaintext or encrypted file.')
@click.option('-k', '--key', default = '', help = 'Key.')
@click.option('-l', '--key-length', default = 128, help = 'Key length.')
def encrypt(target_file, key, key_length):
    if target_file == '' or key == '':
        print "[!] Target file or key not specified."
        sys.exit(1)

    Encrypt(target_file, key, key_length).start_encryption()


@click.command(help = 'Decrypt an encrypted file.')
@click.option('-f', '--target-file', default = '', help = 'Target plaintext or encrypted file.')
@click.option('-k', '--key', default = '', help = 'Key.')
@click.option('-l', '--key-length', default = 128, help = 'Key length.')
def decrypt(target_file, key, key_length):
    if target_file == '' or key == '':
        print "[!] Target file or key not specified."
        sys.exit(1)

    Decrypt(target_file, key, key_length).start_decryption()


@click.group()
def cipher():
    ''' \b
    Encrypt or decrypt a plaintext or ciphertext file. \b
    Written by Matthew Lovatt for Advanced Software Security at Staffordshire Univeristy.
    '''

cipher.add_command(encrypt, name = 'encrypt')
cipher.add_command(decrypt, name = 'decrypt')


if __name__ == "__main__":
    cipher()
