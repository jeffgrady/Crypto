#!/usr/bin/env python

# Always operate on raw bytes, never on encoded strings.
# Only use hex and base64 for pretty-printing.

import base64
import struct
import unittest

def pack_bytes(string1):
    return struct.pack('B' * len(string1), *string1)

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
        output += '%0.2x' % (ord(string1[i]))
    return output

def hex_to_base64(hex_input):
    output = pack_bytes(hex_input)
    output = base64.b64encode(output)
    return output

def fixed_xor(string1, key):
    output = list()
    for i in xrange(0, len(string1)):
        output.append(string1[i] ^ key[i])
    return output

def single_byte_xor_cipher(string1, key_byte):
    key = ('%0.2x' % key_byte) * len(string1)
    key = hex_decode(key)
    output = fixed_xor(string1, key)
    return output

def score_english_text(string1):
    score = 0
    most_freq_str = 'ETAOIN SHRDLU'
    most_freq = {}
    bonus = len(most_freq_str) + 1
    for char in most_freq_str:
        most_freq[char] = bonus
        bonus -= 1
    for char in string1.upper():
        if char not in most_freq:
            score -= 1
        else:
            score += most_freq[char]
    return score

class TestSet1(unittest.TestCase):

    def test_hex_to_base64(self):
        hex_input = '49276d206b696c6c696e6720796f757220627261696e206c696'
        hex_input += 'b65206120706f69736f6e6f7573206d757368726f6f6d'
        hex_input = hex_decode(hex_input)
        output = hex_to_base64(hex_input)
        expected_output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc'
        expected_output += '29ub3VzIG11c2hyb29t'
        self.assertEqual(output, expected_output)

    def test_fixed_xor(self):
        hex_input = '1c0111001f010100061a024b53535009181c'
        key = '686974207468652062756c6c277320657965'
        hex_input = hex_decode(hex_input)
        key = hex_decode(key)
        output = fixed_xor(hex_input, key)
        output = pack_bytes(output)
        output = hex_encode(output)
        expected_output = '746865206b696420646f6e277420706c6179'
        self.assertEqual(output, expected_output)

    def test_single_byte_xor_cipher(self):
        key_byte = 0
        string1 = '1b37373331363f78151b7f2b783431333d78397828372d363c783'
        string1 += '73e783a393b3736'
        string1 = hex_decode(string1)
        scores = {}
        for key in xrange(0, 256):
            output = single_byte_xor_cipher(string1, key)
            output = pack_bytes(output)
            score = score_english_text(output)
            scores[score] = key
        best_score = max(scores)
        best_key = scores[best_score]
        output = single_byte_xor_cipher(string1, best_key)
        output = pack_bytes(output)
        self.assertEqual(output, "Cooking MC's like a pound of bacon")

    def test_find_encrypted_string_in_file(self):
        lines = list()
        with open('set1_challenge4.txt', 'r') as data:
            lines = map(lambda x: x.strip(), data.readlines())
        best_scores = {}
        i = 0
        for line in lines:
            scores = {}
            for key in xrange(0, 256):
                decoded_line = hex_decode(line)
                output = single_byte_xor_cipher(decoded_line, key)
                output = pack_bytes(output)
                score = score_english_text(output)
                scores[score] = key
            best_score = max(scores)
            best_key = scores[best_score]
            best_scores[best_score] = (i, best_key)
            i += 1
        most_smartest_score = max(best_scores)
        line_num, best_key = best_scores[most_smartest_score]
        decoded_line = hex_decode(lines[line_num])
        output = single_byte_xor_cipher(decoded_line, best_key)
        output = pack_bytes(output)
        self.assertEqual(output, 'Now that the party is jumping\n')
        self.assertEqual(line_num, 170)

if __name__ == '__main__':
    unittest.main()
