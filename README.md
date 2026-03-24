# File Type Identification Tool

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Try%20it%20now-4f8ef7?style=for-the-badge)](https://file-type-identification-tool.onrender.com)

A cybersecurity tool that detects the true type of a file by reading its magic bytes and compares it against the declared file extension to flag suspicious mismatches.

## The Problem It Solves

Attackers frequently rename malicious files to bypass naive extension-based filters — a Windows executable saved as `invoice.pdf` or malware packed inside `photo.jpg`. Antivirus tools and email gateways that only check the extension can be fooled. This tool reads the actual binary content of the file and identifies its real format, regardless of what the extension says.

## How It Works

Every file format reserves the first few bytes of its content for a unique signature called a **magic number**. For example:

- PNG files always start with `89 50 4E 47`
- PDF files always start with `25 50 44 46` (ASCII `%PDF`)
- Windows executables always start with `4D 5A` (ASCII `MZ`)
- Linux ELF binaries always start with `7F 45 4C 46` (ASCII `.ELF`)

The tool reads the first 16 bytes of any uploaded file in binary mode, converts them to hex, and matches them against a dictionary of known signatures. It then compares the detected type to the file's declared extension. A mismatch is flagged as suspicious.

## Project Structure

```
file_type_identification_tool/
├── app.py              # Flask backend — receives uploads, returns JSON results
├── magic_reader.py     # Core logic — magic number dictionary, detection, comparison
└── templates/
    └── index.html      # Drag-and-drop frontend
```

## Installation

**Requirements:** Python 3.5+

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/file-type-identification-tool.git
cd file-type-identification-tool

# Install Flask
pip3 install flask
```

## Running the Tool

```bash
python3 app.py
```

Then open your browser at `http://127.0.0.1:5000`.

Drag and drop any file onto the page. The tool will show:
- Detected type (from magic bytes)
- Declared type (from extension)
- Hex prefix of the first bytes
- A green "Safe" or red "Suspicious" verdict

To stop the server press `Ctrl + C`.

## Supported File Types

Images: PNG, JPEG, GIF, BMP, TIFF
Audio: MP3, WAV, FLAC
Video: MP4, AVI, MOV, MKV
Archives: ZIP, GZ, TAR, RAR, 7Z
Documents: PDF, DOC, DOCX, XLSX, PPTX
Executables: EXE/DLL (Windows PE), ELF (Linux), Java CLASS
Database: SQLite

## Cybersecurity Use Cases

- Detect executables disguised as documents or images
- Verify file integrity during incident response
- Identify polyglot files (valid in two formats simultaneously)
- Triage suspicious email attachments or downloaded files
