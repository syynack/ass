import os

sbox_0_test = [
    '\x0b', '2', '\xc2', '\xc3', '\xce', 'S', '\xfe', '\xcb', 'L', '\x1d', '\xbd', '\xb6', '\xb6', '\x18', '\xb8', '6',
    '\xc7', '\xde', 'q', '\xdb', '\x81', 'Y', '\x9f', '\x1d', '\xe2', '"', '_', 'O', 'Q', 'V', '\xb1', '*',
    '\xfe', '\xc8', '\x95', 'B', '\xed', '\xc3', '\xfb', '\x92', '\xfa', '\r', '\x9b', 'o', '\xcf', '\xb9', '\x8b', '\xd1',
    '\xba', '\x9d', 'K', '{', '\x8b', '.', '\xb3', '\x04', '\xdb', 'V', ',', '\xbf', '\xd3', 'R', '\x81', '\xb1',
    '$', '\x82', '\x10', '\x81', 'g', '\x08', '\x12', '\xe1', '\x1c', '\x81', '\xd8', '\x9c', '\xf9', 'B', '4', '\xf3',
    'J', '.', 'X', '\xa9', '\x19', '7', '\xa8', '\x94', '\xaa', '\xfa', '\x00', '\xce', '\xc1', '\xcc', '\x02', '\xb1',
    '\r', '\x8e', '1', '\xbd', 'E', 'U', '\xd9', '\xab', '\x98', '\xc5', '\xe8', '\xda', '<', '&', '5', '\xc9',
    '\xd8', '\xa1', '/', '\xd4', '\x8c', '\x8a', '\xa0', '\x8d', 'D', '\xed', '\x9a', ')', '\xcc', '\x83', '\xb2', '\xc9',
    '\x0b', '\x12', '\xb7', '\x82', '\x81', '\xf6', '\xb5', '|', '4', 'd', '\xd0', '\xd7', '\xa3', '\r', '\x93', '\x90',
    '\xb3', '\xe7', 'U', '\xd2', '\xdf', 'Z', '<', '{', ' ', '\xc2', '\xf0', '\x9d', '\x0c', 'K', '\x06', '\x8c',
    '\x7f', 'U', '\xad', '\xa6', '\xb5', '\xa6', '\xf0', 'h', '\x0f', '\t', 'G', '9', '\xfb', '\x08', '\xfb', '\x8b',
    '\xf0', '\xbd', '\x13', '6', 'o', '7', '\x06', '\xcf', '\x18', '\xe9', '\x90', '\x8e', '\xa6', '\x0e', 'C', '\xd8',
    '\xb2', '\x8a', '\x8b', '+', '%', '\xac', 'K', '\xcb', '0', ')', 'y', '\xbe', '\x06', '\xaa', '}', '\xca',
    '\x06', '\xc3', '\x0b', '\x0b', '\x8a', 'Q', '\xc2', '\xf2', '\t', '\xad', '\xfe', '\xb0', '\xe7', '\xf8', '\xc8', '\x7f',
    '\xc5', '\xd2', '\x87', '\xcc', '\x83', ')', 'T', '\xbc', '?', 'w', '\xf9', '\x15', 'R', '\x92', 'Z', '\xbf',
    '\x1d', '\xc5', '\x1f', 'E', '\x95', '\xa5', '\xe4', 'y', '\xb7', '\x0f', '\xb7', 'c', '\x11', 'V', '|', '\xb1'
]

new_sbox = []
new_sbox = list(set(sbox_0_test))

while len(new_sbox) != 256:
    new_sbox.append(os.urandom(1))
    new_sbox = list(set(new_sbox))

print len(set(new_sbox))
print list(new_sbox)

sublists_sbox = [list(new_sbox)[x:x+16] for x in xrange(0, len(new_sbox), 16)]
print sublists_sbox

[
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