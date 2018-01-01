#! /usr/bin/env python

import binascii
import os
import textwrap
import sys

class Cipher():
    def __init__(self, key, key_length, target_file = None):
        self.key = key
        self.key_length = key_length
        self.encryption_rounds = 0
        '''
        Sboxes generated with:
        import os
        matrix = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], []]

        for item in matrix:
            for i in range(16):
                item.append(os.urandom(1))
        '''
        self.sbox_0 = [
            ['\x00', '\x83', '\x04', '\x87', '\x08', '\x8b', '\x0c', '\x8f', '\x10', '\x93', '\x14', '\x97', '\x18', '\x9b', '\x1c', '\x9f'],
            [' ', '\xa3', '$', '\xa7', '(', '\xab', ',', '\xaf', '0', '\xb3', '4', '\xb7', '8', '\xbb', '<', '\xbf'],
            ['@', '\xc3', 'D', '\xc7', 'H', '\xcb', 'L', '\xcf', 'P', '\xd3', 'T', '\xd7', 'X', '\xdb', '\\', '\xdf'],
            ['`', '\xe3', 'd', '\xe7', 'h', '\xeb', 'l', '\xef', 'p', '\xf3', 't', '\xf7', 'x', '\xfb', '|', '\xff'],
            ['\x80', '\x03', '\x84', '\x07', '\x88', '\x0b', '\x8c', '\x0f', '\x90', '\x13', '\x94', '\x17', '\x98', '\x1b', '\x9c', '\x1f'],
            ['\xa0', '#', '\xa4', "'", '\xa8', '+', '\xac', '/', '\xb0', '3', '\xb4', '7', '\xb8', ';', '\xbc', '?'],
            ['\xc0', 'C', '\xc4', 'G', '\xc8', 'K', '\xcc', 'O', '\xd0', 'S', '\xd4', 'W', '\xd8', '[', '\xdc', '_'],
            ['\xe0', 'c', '\xe4', 'g', '\xe8', 'k', '\xec', 'o', '\xf0', 's', '\xf4', 'w', '\xf8', '{', '\xfc', '\x7f'],
            ['\x81', '\x02', '\x85', '\x06', '\x89', '\n', '\x8d', '\x0e', '\x91', '\x12', '\x95', '\x16', '\x99', '\x1a', '\x9d', '\x1e'],
            ['\xa1', '"', '\xa5', '&', '\xa9', '*', '\xad', '.', '\xb1', '2', '\xb5', '6', '\xb9', ':', '\xbd', '>'],
            ['\xc1', 'B', '\xc5', 'F', '\xc9', 'J', '\xcd', 'N', '\xd1', 'R', '\xd5', 'V', '\xd9', 'Z', '\xdd', '^'],
            ['\xe1', 'b', '\xe5', 'f', '\xe9', 'j', '\xed', 'n', '\xf1', 'r', '\xf5', 'v', '\xf9', 'z', '\xfd', '~'],
            ['\x01', '\x82', '\x05', '\x86', '\t', '\x8a', '\r', '\x8e', '\x11', '\x92', '\x15', '\x96', '\x19', '\x9a', '\x1d', '\x9e'],
            ['!', '\xa2', '%', '\xa6', ')', '\xaa', '-', '\xae', '1', '\xb2', '5', '\xb6', '9', '\xba', '=', '\xbe'],
            ['A', '\xc2', 'E', '\xc6', 'I', '\xca', 'M', '\xce', 'Q', '\xd2', 'U', '\xd6', 'Y', '\xda', ']', '\xde'],
            ['a', '\xe2', 'e', '\xe6', 'i', '\xea', 'm', '\xee', 'q', '\xf2', 'u', '\xf6', 'y', '\xfa', '}', '\xfe']
        ]
        self.round_keys = []
        self.target_file = target_file
        self.ciphertext_file = self.target_file + '.encrypted'
        self.plaintext_file = self.target_file.split('.encrypted')[0]
        self.xored_chunks = []
        self.plaintext_contents = ''
        self.ciphertext_contents = ''
        self.ciphertext_chunks = []
        self.decrypted_plaintext = ''
        self.binary_format = '{0:0{1}b}'


    def _calculate_rounds(self):
        if self.key_length == 128:
            self.encryption_rounds = 16
        elif self.key_length == 256:
            self.encryption_rounds = 24
        elif self.key_length == 512:
            self.encryption_rounds = 32


    def _write_ciphertext_to_file(self):
        with open(self.ciphertext_file, 'wb') as target_file:
            target_file.write(self.ciphertext_contents)


    def _read_ciphertext_from_file(self):
        with open(self.ciphertext_file, 'rb') as target_file:
            byte = target_file.read(1)
            while byte != "":
                self.ciphertext_chunks.append(byte)

                byte = target_file.read(1)


    def _write_plaintext_to_file(self):
        with open(self.plaintext_file, 'w') as target_file:
            target_file.write(self.decrypted_plaintext)


    def _substitute_ciphertext_chunks(self):
        for index_0, chunk in enumerate(self.ciphertext_chunks):
            for sublist in self.sbox_0:
                if chunk in sublist:
                    index_1 = self.sbox_0.index(sublist)
                    index_2 = sublist.index(chunk)

            self.ciphertext_chunks[index_0] = "{0:04b}".format(index_1) + "{0:04b}".format(index_2)


    def _decrypt_xored_chunks(self):
        ciphertext_chunks = [self.ciphertext_chunks[x:x+8] for x in xrange(0, len(self.ciphertext_chunks), 8)]

        for index_0, chunk_list in enumerate(ciphertext_chunks):
            for index_1, chunk in enumerate(chunk_list):
                for key in self.round_keys[::-1]:
                    ciphertext_chunks[index_0][index_1] = self.binary_format.format(int(chunk, 2) ^ int(key, 2), 8)

        for index, sublist in enumerate(ciphertext_chunks):
            ciphertext_chunks[index] = ''.join(sublist)

        self.ciphertext_chunks = ''.join(ciphertext_chunks)


    def _process_ciphertext_chunks(self):
        joined_ciphertext = ''.join(self.ciphertext_chunks)
        plaintext = ""

        for i in range(0, len(joined_ciphertext), 8):
            plaintext = plaintext + chr(int(joined_ciphertext[i:i+8], 2))

        self.decrypted_plaintext = plaintext


    def _get_starting_keys(self):
        key = ''.join(format(ord(i), 'b') for i in self.key)
        split_key = textwrap.wrap(key, 8)

        while len(split_key) != 4:
            for i in range(0, len(split_key), 2):
                k1 = split_key[i-1]
                k2 = split_key[i]
                split_key[i-1] = self.binary_format.format(int(k1, 2) ^ int(k2, 2), 8)

            while len(split_key) % 4 != 0:
                split_key[0] = self.binary_format.format(int(split_key[0], 2) ^ int(split_key[1], 2), 8)
                del split_key[1]

            split_key = split_key[1::2]

        self.round_keys = self.round_keys + (split_key + ([None] * (self.encryption_rounds - 4)))

        for i in range(4, len(self.round_keys)):
            self.round_keys[i] = self.binary_format.format(int(self.round_keys[i - 4], 2) ^ int(self.round_keys[i - 1], 2), 8)


    def _convert_plaintext_to_binary(self):
        with open(self.plaintext_file, 'rb') as ptf:
            self.plaintext_contents = ptf.read()


    def _substitute_xored_chunk(self, chunk):
        assert len(chunk) == 8
        assert isinstance(chunk, str)

        first_half, second_half = int(chunk[:4], 2), int(chunk[4:], 2)
        substition = self.sbox_0[first_half][second_half]
        self.ciphertext_contents = self.ciphertext_contents + substition


    def _xor_chunk_blocks(self, chunk):
        chunk_block = textwrap.wrap(chunk, 8)

        for index, item in enumerate(chunk_block):
            for key in self.round_keys:
                chunk_block[index] = self.binary_format.format(int(chunk_block[index], 2) ^ int(key, 2), 8)

        return chunk_block


    def _process_plaintext_chunks(self, chunk):
        xored_chunk = self._xor_chunk_blocks(chunk)

        for subchunk in xored_chunk:
            self.xored_chunks.append(subchunk)


    def _process_plaintext(self):
        bin_plaintext = ''
        chunks = []

        for char in self.plaintext_contents:
            print char
            print bin_plaintext
            bin_plaintext = bin_plaintext + str(self.binary_format.format(ord(char), 8))

        for x in range(0, len(bin_plaintext), 64):
            chunks.append(bin_plaintext[x:x + 64])

        for chunk in chunks:
            self._process_plaintext_chunks(chunk)


    def _start_encryption_process(self):
        if self.plaintext_file is None:
            print "[!] Target file not specified. Exiting."
            sys.exit(1)

        self._convert_plaintext_to_binary()
        self._calculate_rounds()
        self._get_starting_keys()
        self._process_plaintext()

        for chunk in self.xored_chunks:
            self._substitute_xored_chunk(chunk)

        self._write_ciphertext_to_file()


    def _start_decryption_process(self):
        self._calculate_rounds()
        self._get_starting_keys()

        self._read_ciphertext_from_file()
        self._substitute_ciphertext_chunks()
        self._decrypt_xored_chunks()
        self._process_ciphertext_chunks()
        self._write_plaintext_to_file()


def main():
    cipher = Cipher(
        key = 'a1e04e496c42c56a4589b23189327d2db63dce050bc0c0e5226903f15f8a4a6b19f1dbdbbe33fb62d5456c45e54162d51047114bdc57339edf8de7c8ad972e5f6edae55d37423d85f3b0712a91f1eb618e6f323b095d7fd0a01ebc56f82ece0deadb035e',
        key_length = 128,
        target_file = 'test_ptf.txt'
    )

    #cipher._start_encryption_process()
    print ''
    cipher._start_decryption_process()


if __name__ == "__main__":
    main()
