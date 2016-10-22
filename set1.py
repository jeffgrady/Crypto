#!/usr/bin/env python

# Always operate on raw bytes, never on encoded strings.
# Only use hex and base64 for pretty-printing.

import base64
import struct
import unittest

def hex_decode(hex_input):
    output = list()
    for i in xrange(0, len(hex_input), 2):
        number = 0
        char1 = hex_input[i]
        if char1.isdigit():
            number = (ord(char1) - ord('0')) << 4
        else:
            number = (ord(char1.lower()) - ord('a') + 10) << 4
        char2 = hex_input[i+1]
        if char2.isdigit():
            number += ord(char2) - ord('0')
        else:
            number += ord(char2.lower()) - ord('a') + 10
        output.append(number)
    return output

def hex_encode(string1):
    output = u''
    for i in xrange(0, len(string1)):
        output += '%x' % (ord(string1[i]))
    return output

def hex_to_base64(hex_input):
    output = hex_decode(hex_input)
    output = struct.pack('B' * len(output), *output)
    output = base64.b64encode(output)
    return output

def fixed_xor(string1, key):
    string1 = hex_decode(string1)
    key = hex_decode(key)
    output = list()
    for i in xrange(0, len(string1)):
        output.append(string1[i] ^ key[i])
    output = struct.pack('B' * len(output), *output)
    output = hex_encode(output)
    return output

class TestSet1(unittest.TestCase):

    def test_hex_to_base64(self):
        hex_input = '49276d206b696c6c696e6720796f757220627261696e206c696'
        hex_input += 'b65206120706f69736f6e6f7573206d757368726f6f6d'
        output = hex_to_base64(hex_input)
        expected_output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc'
        expected_output += '29ub3VzIG11c2hyb29t'
        self.assertEqual(output, expected_output)

    def test_fixed_xor(self):
        hex_input = '1c0111001f010100061a024b53535009181c'
        key = '686974207468652062756c6c277320657965'
        output = fixed_xor(hex_input, key)
        expected_output = '746865206b696420646f6e277420706c6179'
        self.assertEqual(output, expected_output)

if __name__ == '__main__':
    unittest.main()
