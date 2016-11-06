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

def create_repeating_key(string1, key):
    repeats = int(len(string1) / len(key))
    remainder = len(string1) % len(key)
    full_key = key * repeats
    if remainder != 0:
        full_key += key[:remainder]
    full_key = hex_encode(full_key)
    full_key = hex_decode(full_key)
    return full_key

def repeating_key_xor_cipher(string1, key):
    full_key = create_repeating_key(string1, key)
    output = fixed_xor(string1, full_key)
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

def hamming_distance(input1, input2):
    """Return the number of bits that differ between two strings."""
    # the strings should be the same length, but just in case...
    length = min(len(input1), len(input2))
    input1 = input1[:length]
    input2 = input2[:length]
    input1 = hex_decode(hex_encode(input1))
    input2 = hex_decode(hex_encode(input2))
    # the general strategy here is to xor the two strings together
    # and then just count the number of 1s in the output (i.e., where the
    # two strings differed).
    output = fixed_xor(input1, input2)
    distance = 0
    for byte in output:
        for i in range(8):
            bit_mask = 1 << i
            if (bit_mask & byte) == bit_mask:
                distance += 1
    return distance

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

    def test_repeating_key_xor(self):
        input1 = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
        input1 = hex_encode(input1)
        input1 = hex_decode(input1)
        key = "ICE"
        output = repeating_key_xor_cipher(input1, key)
        output = pack_bytes(output)
        output = hex_encode(output)
        expected_output = "0b3637272a2b2e63622c2e69692a23693a2a3c63242"
        expected_output += "02d623d63343c2a26226324272765272"
        expected_output += "a282b2f20430a652e2c652a3124333a653e2b20276"
        expected_output += "30c692b20283165286326302e27282f"
        self.assertEqual(output, expected_output)

    def test_hamming_distance(self):
        input1 = "this is a test"
        input2 = "wokka wokka!!!"
        output = hamming_distance(input1, input2)
        self.assertEqual(output, 37)

if __name__ == '__main__':
    unittest.main()
