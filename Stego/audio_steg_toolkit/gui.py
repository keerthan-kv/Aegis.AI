import tkinter as tk
from tkinter import filedialog, messagebox
from steg.lsb_hamming import embed_lsb_hamming, extract_lsb_hamming
from utils.audio_utils import read_wave
from metrics.metrics import snr, psnr
import os
import numpy as np

class AudioStegGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Audio Steganography Toolkit")
        self.root.geometry("600x400")
        self.root.configure(bg="#f0f0f0")

        self.cover_audio_path = ""
        self.stego_audio_path = ""

        self.setup_widgets()

    def setup_widgets(self):
        title = tk.Label(self.root, text="🎵 Audio Steganography Toolkit", font=("Helvetica", 18, "bold"), bg="#f0f0f0")
        title.pack(pady=20)

        # File Select
        btn_cover = tk.Button(self.root, text="📂 Select Cover Audio", command=self.load_cover_audio, width=30)
        btn_cover.pack(pady=5)

        self.cover_label = tk.Label(self.root, text="No file selected", bg="#f0f0f0")
        self.cover_label.pack()

        # Text Input
        self.message_entry = tk.Entry(self.root, width=50)
        self.message_entry.pack(pady=10)
        self.message_entry.insert(0, "Enter secret message...")

        # Embed Button
        btn_embed = tk.Button(self.root, text="🔐 Embed Message", command=self.embed_message, width=30, bg="#d1e7dd")
        btn_embed.pack(pady=5)

        # Stego File
        btn_stego = tk.Button(self.root, text="📂 Select Stego Audio", command=self.load_stego_audio, width=30)
        btn_stego.pack(pady=5)

        self.stego_label = tk.Label(self.root, text="No file selected", bg="#f0f0f0")
        self.stego_label.pack()

        # Extract Button
        btn_extract = tk.Button(self.root, text="🕵️ Extract Message", command=self.extract_message, width=30, bg="#fff3cd")
        btn_extract.pack(pady=5)

        # Metrics
        btn_metrics = tk.Button(self.root, text="📊 Show Metrics", command=self.show_metrics, width=30, bg="#cfe2ff")
        btn_metrics.pack(pady=10)

    def load_cover_audio(self):
        path = filedialog.askopenfilename(filetypes=[("WAV files", "*.wav")])
        if path:
            self.cover_audio_path = path
            self.cover_label.config(text=os.path.basename(path))

    def load_stego_audio(self):
        path = filedialog.askopenfilename(filetypes=[("WAV files", "*.wav")])
        if path:
            self.stego_audio_path = path
            self.stego_label.config(text=os.path.basename(path))

    def embed_message(self):
        if not self.cover_audio_path:
            messagebox.showerror("Error", "Select a cover audio file first.")
            return

        message = self.message_entry.get()
        if not message:
            messagebox.showerror("Error", "Enter a message to embed.")
            return

        try:
            out_path = filedialog.asksaveasfilename(defaultextension=".wav", filetypes=[("WAV files", "*.wav")])
            if not out_path:
                return

            embed_lsb_hamming(self.cover_audio_path, message, out_path)
            messagebox.showinfo("Success", f"Message embedded successfully in {out_path}")
        except Exception as e:
            messagebox.showerror("Embedding Failed", str(e))

    def extract_message(self):
        if not self.stego_audio_path:
            messagebox.showerror("Error", "Select a stego audio file first.")
            return

        try:
            length = int(tk.simpledialog.askstring("Length", "Enter message length (characters):"))
            extracted = extract_lsb_hamming(self.stego_audio_path, length)
            messagebox.showinfo("Extracted Message", extracted)
        except Exception as e:
            messagebox.showerror("Extraction Failed", str(e))

    def show_metrics(self):
        if not (self.cover_audio_path and self.stego_audio_path):
            messagebox.showerror("Error", "Select both cover and stego audio files.")
            return

        try:
            orig, _ = read_wave(self.cover_audio_path)
            mod, _ = read_wave(self.stego_audio_path)
            s = snr(orig[:len(mod)], mod)
            p = psnr(orig[:len(mod)], mod)
            result = f"SNR: {s:.2f} dB\nPSNR: {p:.2f} dB"
            messagebox.showinfo("Metrics", result)
        except Exception as e:
            messagebox.showerror("Metrics Failed", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = AudioStegGUI(root)
    root.mainloop()
