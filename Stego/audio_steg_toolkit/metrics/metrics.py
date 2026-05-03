import numpy as np

def snr(original, modified):
    noise = original - modified
    noise_power = np.mean(noise ** 2)
    signal_power = np.mean(original ** 2)
    return 10 * np.log10(signal_power / noise_power)

def psnr(original, modified):
    mse = np.mean((original - modified) ** 2)
    max_val = np.max(original)
    return 20 * np.log10(max_val / np.sqrt(mse))

def bit_error_rate(original_bits, received_bits):
    errors = sum(o != r for o, r in zip(original_bits, received_bits))
    return errors / len(original_bits)

def accuracy(original_bits, received_bits):
    matches = sum(o == r for o, r in zip(original_bits, received_bits))
    return matches / len(original_bits)
