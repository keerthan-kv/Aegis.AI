from utils.audio_utils import read_wave, write_wave
import numpy as np

def hamming_encode(bit_str):
    data = [int(b) for b in bit_str]
    while len(data) % 4 != 0:
        data.append(0)
    encoded = []
    for i in range(0, len(data), 4):
        d = data[i:i+4]
        p1 = d[0] ^ d[1] ^ d[3]
        p2 = d[0] ^ d[2] ^ d[3]
        p3 = d[1] ^ d[2] ^ d[3]
        encoded += [p1, p2, d[0], p3, d[1], d[2], d[3]]
    return encoded

def hamming_decode(bits):
    decoded = []
    for i in range(0, len(bits), 7):
        block = bits[i:i+7]
        if len(block) < 7:
            break
        p1, p2, d1, p3, d2, d3, d4 = block
        syndrome = [
            p1 ^ d1 ^ d2 ^ d4,
            p2 ^ d1 ^ d3 ^ d4,
            p3 ^ d2 ^ d3 ^ d4
        ]
        error_pos = sum([(2**i)*bit for i, bit in enumerate(syndrome)])
        if error_pos:
            block[error_pos-1] ^= 1
        decoded.extend([block[2], block[4], block[5], block[6]])
    return decoded

def embed_lsb_hamming(cover_path, message, out_path):
    samples, params = read_wave(cover_path)
    message_bits = ''.join(f'{ord(c):08b}' for c in message)
    encoded_bits = hamming_encode(message_bits)

    if len(encoded_bits) > len(samples):
        raise ValueError("Message too large to embed.")

    stego_samples = np.copy(samples)
    for i, bit in enumerate(encoded_bits):
        stego_samples[i] = (stego_samples[i] & ~1) | bit

    write_wave(out_path, stego_samples, params)

def extract_lsb_hamming(stego_path, length):
    samples, _ = read_wave(stego_path)
    bits = [s & 1 for s in samples[:length * 14]]  # each char ~14 encoded bits
    decoded_bits = hamming_decode(bits)
    message = ''.join(chr(int(''.join(map(str, decoded_bits[i:i+8])), 2)) for i in range(0, len(decoded_bits), 8))
    return message.strip('\x00')
