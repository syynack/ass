#! /usr/bin/env python

import binascii
import os
import textwrap
import sys

class Cipher():
    def __init__(self, key, key_length, plaintext_file = None):
        self.key = key
        self.key_length = key_length
        self.encryption_rounds = 0
        '''
        Sboxes generated with:
        import os
        matrix = [[], [], [], [], [], [], [], []]

        for item in matrix:
            for i in range(8):
                item.append(os.urandom(1))
        '''
        self.sbox_0 = [
            ['\x1c', '\x05', 'O', ']', '\xae', 'C', 'y', '\xaf'],
            ['q', '9', '\x04', '\xff', '\xd5', '\xbe', '\t', '\x9a'],
            ['\x8d', '\xe9', '\xb9', '\xe4', '\xac', 'i', '\xe8', '\x15'],
            ['M', "'", '_', '\xd1', 't', '\xe9', '\xf1', '\x04'],
            ['\x81', 'g', '\xef', '\x8c', '\x9d', '\xc2', '\x8b', '['],
            ['$', '\xca', '\xfc', '\xae', '\xfc', 'T', '\xba', '!'],
            ['3', '\x92', '\x01', '\x0e', ';', '\xb6', '\xc4', '8'],
            ['k', '\xec', '\xd1', '\xa1', '\xc0', '\x88', 'O', '\xfc']
        ]
        self.sbox_1 = [
            ['\x88', 'D', '\x0f', ' ', 'X', '\xe7', '\x9f', '\x03'],
            ['\xe5', '\xd8', '\xe4', '\xce', '\xce', '3', 'M', '\x9c'],
            ['\x1f', '\x96', ']', '\xe7', '\xa5', '\x80', 'E', '\xbc'],
            ['F', '\xf0', '\xcd', '\x93', '\xb0', '}', '9', '['],
            ['l', '\x96', '=', '\xf4', 'a', 'k', '\x9e', 'Q'],
            ['\x94', '\xb4', '.', ')', 'Y', 'v', '\xab', 'u'],
            ['{', '\xce', '"', '\xa2', '\x08', '\xe9', '\xb0', '\x95'],
            ['*', '\xbe', '\x11', 'R', '\x02', ')', '\xcc', 'b']
        ]
        self.round_keys = []
        self.plaintext_file = plaintext_file
        self.plaintext_contents = ''
        self.target_file = self.plaintext_file + '.enc' if self.plaintext_file is not None else None


    def _calculate_rounds(self):
        if self.key_length == 128:
            self.encryption_rounds = 16
        elif self.key_length == 256:
            self.encryption_rounds = 24
        elif self.key_length == 512:
            self.encryption_rounds = 32


    def _get_starting_keys(self):
        key = ''.join(format(ord(i), 'b') for i in self.key)
        split_key = textwrap.wrap(key, 8)

        while len(split_key) != 4:
            for i in range(0, len(split_key), 2):
                k1 = split_key[i-1]
                k2 = split_key[i]
                split_key[i-1] = '{0:0{1}b}'.format(int(k1, 2) ^ int(k2, 2), 8)

            while len(split_key) % 4 != 0:
                split_key[0] = '{0:0{1}b}'.format(int(split_key[0], 2) ^ int(split_key[1], 2), 8)
                del split_key[1]

            split_key = split_key[1::2]

        self.round_keys + (split_key + ([None] * (self.encryption_rounds - 4)))

        for i in range(4, len(self.round_keys)):
            self.round_keys[i] = '{0:0{1}b}'.format(int(self.round_keys[i - 4], 2) ^ int(self.round_keys[i - 1], 2), 8)


    def _convert_plaintext_to_binary(self):
        with open(self.plaintext_file, 'rb') as ptf:
            self.plaintext_contents = ptf.read()


    def _encrypt(self):
        if self.plaintext_file is None:
            print "[!] Target file not specified. Exiting."
            sys.exit(1)

        self._convert_plaintext_to_binary()


    def _decrypt(self):
        pass


def main():
    cipher = Cipher(
        key = 'a1e04e496c42c56a4589b23189327d2db63dce050bc0c0e5226903f15f8a4a6b19f1dbdbbe33fb62d5456c45e54162d51047114bdc57339edf8de7c8ad972e5f6edae55d37423d85f3b0712a91f1eb618e6f323b095d7fd0a01ebc56f82ece0deadb035e',
        key_length = 128,
        plaintext_file = 'test_ptf.txt'
    )

    cipher._encrypt()



if __name__ == "__main__":
    main()
