def hamming_encode(data_bits):
    def encode_byte(byte):
        d = [int(x) for x in format(byte, '08b')]
        code = [0]*7
        code[2] = d[0]
        code[4] = d[1]
        code[5] = d[2]
        code[6] = d[3]
        code[0] = code[2] ^ code[4] ^ code[6]
        code[1] = code[2] ^ code[5] ^ code[6]
        code[3] = code[4] ^ code[5] ^ code[6]
        return code
    bits = []
    for byte in data_bits:
        bits.extend(encode_byte(byte))
    return bits

def hamming_decode(code_bits):
    def decode_block(block):
        p1 = block[0] ^ block[2] ^ block[4] ^ block[6]
        p2 = block[1] ^ block[2] ^ block[5] ^ block[6]
        p4 = block[3] ^ block[4] ^ block[5] ^ block[6]
        error_pos = p4 * 4 + p2 * 2 + p1 * 1
        if error_pos != 0:
            block[error_pos - 1] ^= 1
        return [block[2], block[4], block[5], block[6]]
    bits = []
    for i in range(0, len(code_bits), 7):
        block = code_bits[i:i+7]
        if len(block) == 7:
            bits.extend(decode_block(block))
    return bits