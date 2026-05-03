import wave
import numpy as np

def read_wave(file_path):
    with wave.open(file_path, 'rb') as wav:
        params = wav.getparams()
        frames = wav.readframes(params.nframes)
        samples = np.frombuffer(frames, dtype=np.int16)
    return samples, params

def write_wave(file_path, samples, params):
    with wave.open(file_path, 'wb') as wav:
        wav.setparams(params)
        wav.writeframes(samples.astype(np.int16).tobytes())
