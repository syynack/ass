#! /usr/bin/env python

import binascii
import os

class Cipher():
    def __init__(self, key, key_length):
        self.key = key
        self.key_length = key_length
        self.encryption_rounds = 0
        self.sbox_0 = [
            'i', '\xbf', ']', '$', '\x8b', '\x95', '=', ';', '\xdc', '\xa6', '!',
            '\x1b', 'K', '\xf7', '<', '\xfb', '\xf3', '\xd1', '\x8e', '\xf3', 'd',
            '.', '\x92', '\xa1', '\xcd', 'K', '5', '\xe0', '\x98', 'l', '\xe9',
            'l', '\x17', 'L', 'B', 'y', 'v', '\xa6', '\x10', '\xd6', '\x04', '~',
            'g', '\xb4', 'M', '<', '\xd1', '\x80', '\xdf', '\xaa', '\xd3', '\xc3',
            '\x1c', '\xdb', '=', 'd', '\x8e', '\x14', ')', '\x97', '\x9d', '\x95',
            '\xbd', '\xb6', '\xf2', '\xcf', 'M', '\xcc', 'x', ')', 'U', '\x95',
            '\xd5', '\xd4', '\xeb', 'a', '\x91', '\xea', '\xe9', '\xf9', '\x1a',
            '+', '\x90', '\x83', 'h', '\xe4', ')', '\x05', '\xf3', '\xcb', '>',
            '\x8e', 'Y', 'm', '\xbd', '\x17', '\xa1', '<', '\xd5', 'e', 'n', '\x9c',
            '\xc4', '\xa8', '\xb0', ',', 'm', 'P', '\x0e', '7', 'J', '\xbe', '\xc4',
            'j', ';', '#', '\xec', '\x9c', '\x8e', '\xf4', '\x1f', '\xbe', 'U', 'm',
            '\xdc', '\xac', '\x82', '\xc3', '\xc5', '\x9c', '\x8f', 'a', '\x9b', 'g',
            '\xd6', '\xef', '\x9e', '\x96', '&', '\x02', '\x9e', 'U', '\xc7', 'D',
            '\xaa', '\x07', '\xf6', '\x02', '-', '\xd7', ';', '\xbe', 'U', '\xfe',
            '\xab', 'Z', '\x85', '\xdd', '\xfc', '1', '\x05', '\x82', '\x8f', '\xdf',
            '\xb8', '\x7f', '\x9a', 'l', 'r', '!', '\xbf', '\x9d', '\xc1', '#', '\x02',
            '\x0f', 'Z', '\x85', '\x86', '\xa4', 'c', 'k', 'q', '\xb4', '\xd5', '\xc9',
            'T', '\xd5', 'f', '>', '\xb3', '\xa7', '\xea', '\xb3', '\xef', '\x05',
            '\xd0', 'Y', '\xf5', 'u', 'x', '\xa9', '\x94', '\x05', '\x11', '\xf4',
            '\xd9', '5', '\x19', '-', '\xe0', '\xa9', '\xf6', '\x84', 'g', 'v', 'n',
            '\xac', '\x88', 'y', '\xf3', '\xe0', '(', '\xc6', '\xa6', '\x06', 'N',
            '\xec', 'd', '\xbd', ' ', 'Z', '\x01', '\xe1', '\x94', 'z', '$', '@',
            '\x17', ';', '\xc2', 'K', '\x15', ']', 'b', 'P', ']', '\xc9', '\xeb',
            '\xc7', 'u', '\x10', '\xa2', '\x95', '\xe1', '3'
        ]


    def _calculate_rounds(self):
        if self.key_length == 128:
            self.encryption_rounds = 16
        elif self.key_length == 256:
            self.encryption_rounds = 24
        elif self.key_length == 512:
            self.encryption_rounds = 32


    def _get_starting_keys(self):
        key = ''.join(format(ord(i), 'b') for i in self.key)
        starting_keys = [None] * self.encryption_rounds

        for i in range(0, len(key), 16):
            k1 = i[:8]
            k2 = i[8:]
            nk1 = bin((k1 ^ k2) ^ 0xff)
