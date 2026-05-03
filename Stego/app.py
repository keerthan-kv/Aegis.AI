import streamlit as st
import os

st.title("📂 Universal File Steganography App")

st.sidebar.header("Navigation")
page = st.sidebar.radio("Go to", ["Embed File", "Extract File"])

def embed_data(cover_bytes, secret_bytes, secret_ext):
    delimiter = b'<<STEGO_DELIM>>'
    return cover_bytes + delimiter + secret_ext.encode('utf-8') + delimiter + secret_bytes

def extract_data(stego_bytes):
    delimiter = b'<<STEGO_DELIM>>'
    if delimiter not in stego_bytes:
        raise ValueError("No hidden file found.")
    parts = stego_bytes.split(delimiter)
    secret_ext = parts[-2].decode('utf-8')
    secret_data = parts[-1]
    return secret_data, secret_ext

if page == "Embed File":
    st.header("Embed a Secret File in a Cover File")

    cover_file = st.file_uploader("Upload a Cover file (Any format)", key="cover")
    secret_file = st.file_uploader("Upload a Secret file to hide (Any format)", key="secret")

    if cover_file and secret_file:
        if st.button("Embed"):
            cover_bytes = cover_file.read()
            secret_bytes = secret_file.read()
            
            cover_ext = os.path.splitext(cover_file.name)[1]
            secret_ext = os.path.splitext(secret_file.name)[1]

            stego_bytes = embed_data(cover_bytes, secret_bytes, secret_ext)

            st.success("File embedded successfully!")
            st.download_button(
                label="Download Stego File",
                data=stego_bytes,
                file_name=f"stego_output{cover_ext}",
                mime="application/octet-stream"
            )

elif page == "Extract File":
    st.header("Extract a Secret File from a Stego File")

    stego_file = st.file_uploader("Upload a Stego file (Any format)")

    if stego_file:
        if st.button("Extract"):
            try:
                stego_bytes = stego_file.read()
                secret_data, secret_ext = extract_data(stego_bytes)

                st.success("File extracted successfully!")
                st.download_button(
                    label="Download Extracted Secret",
                    data=secret_data,
                    file_name=f"extracted_secret{secret_ext}",
                    mime="application/octet-stream"
                )
            except Exception as e:
                st.error(f"Error extracting file: {e}")

