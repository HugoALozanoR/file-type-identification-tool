# Keys are hex strings matching what read_magic_bytes() returns.
# A dictionary gives O(1) lookup — no loops needed to find a match.
# We only store the identifying prefix, not all 16 bytes, because
# magic numbers vary in length (JPEG needs 4 bytes, PDF needs 4, etc.)
MAGIC_NUMBERS = {
    # --- Images ---
    '89504e47': 'PNG',    # \x89PNG — the \x89 byte is non-ASCII on purpose to detect
                          # transmission corruption; used to hide malware in "image" files

    'ffd8ffe0': 'JPEG',   # FFD8 = JPEG Start of Image marker; FFE0 = JFIF app segment
    'ffd8ffe1': 'JPEG',   # FFD8 + FFE1 = EXIF variant (camera metadata)
    'ffd8ffe2': 'JPEG',   # FFD8 + FFE2 = Canon JPEG
    'ffd8ffdb': 'JPEG',   # FFD8 + FFDB = raw quantization table, no JFIF/EXIF header

    '47494638': 'GIF',    # ASCII "GIF8" — GIF87a or GIF89a; historically used for
                          # polyglot attacks (valid GIF that is also valid JavaScript)

    '424d':     'BMP',    # ASCII "BM" — Windows Bitmap; often abused to carry
                          # embedded shellcode in the pixel data region

    '49492a00': 'TIFF',   # "II*\0" little-endian TIFF; used in document forensics
    '4d4d002a': 'TIFF',   # "MM\0*" big-endian TIFF

    # --- Audio ---
    '494433':   'MP3',    # ASCII "ID3" — ID3 metadata tag prepended to MP3 frames;
                          # malware has been embedded in ID3 tags to exploit players
    'fffb':     'MP3',    # Raw MPEG frame sync (no ID3 header)
    'fff3':     'MP3',    # MPEG-1 Layer 3 variant frame sync
    '52494646': 'WAV',    # ASCII "RIFF" — WAV uses RIFF container; same bytes as AVI,
                          # so the next 4 bytes would disambiguate (not needed here)
    '664c6143': 'FLAC',   # ASCII "fLaC" — lossless audio; relevant when analysts
                          # receive audio evidence files and need to verify authenticity

    # --- Video ---
    '000000':   'MP4',    # MP4/MOV files start with a length + "ftyp" box; the first
                          # 3 bytes are almost always 00 00 00 — rough but practical match
    '1a45dfa3': 'MKV',    # EBML magic number for Matroska/WebM; used in media forensics
    '52494646': 'AVI',    # "RIFF" container (shared with WAV — context matters)
    '00000014': 'MOV',    # QuickTime MOV ftyp box size prefix (20 bytes)

    # --- Archives ---
    '504b0304': 'ZIP',    # "PK\x03\x04" — Phil Katz's initials; ZIP is also the
                          # container for DOCX/XLSX/PPTX/JAR/APK — high value for detection
    '377abcaf': 'SEVENZIP',# 7-Zip signature; commonly used to pack and deliver malware
    '526172211a0700': 'RAR', # "Rar!\x1a\x07\x00" RAR4 signature
    '526172211a070100': 'RAR', # RAR5 signature
    '1f8b':     'GZ',     # GZip magic bytes; \x1F\x8B followed by compression method;
                          # used to compress payloads and evade content inspection
    '7573746172': 'TAR',  # ASCII "ustar" POSIX tar header at offset 257 —
                          # appears at start only in some tar variants; approximate match

    # --- Documents ---
    '25504446': 'PDF',    # ASCII "%PDF" — extremely common malware delivery vehicle;
                          # PDF can embed JavaScript, shellcode, and exploit streams
    'd0cf11e0': 'DOC',    # Microsoft Compound Document (OLE2) magic — covers legacy
                          # DOC, XLS, PPT; notorious for macro malware

    # ZIP-based Office formats (DOCX, XLSX, PPTX) share the ZIP signature '504b0304'
    # They are detected as ZIP here; the app layer can refine by checking internal paths

    # --- Executables ---
    '4d5a':     'EXE',    # ASCII "MZ" (Mark Zbikowski) — PE format header for all
                          # Windows executables, DLLs, drivers; highest-priority detection
    '7f454c46': 'ELF',    # "\x7fELF" — Linux/Unix Executable and Linkable Format;
                          # critical for detecting Linux malware, rootkits, and implants
    'cafebabe': 'CLASS',  # Java class file magic; also Mach-O fat binary on macOS;
                          # Java deserialization exploits often arrive as .class files

    # --- Database ---
    '53514c69746520666f726d6174203300': 'SQLITE',
                          # ASCII "SQLite format 3\0" — full 16-byte signature;
                          # SQLite DBs store browser history, credentials, chat logs —
                          # key artifact in digital forensics investigations
}


def read_magic_bytes(filepath: str) -> str:
    # Open the file in binary mode ('rb') so Python reads raw bytes,
    # not text — no encoding is applied, no newline translation happens
    with open(filepath, 'rb') as f:

        # Read only the first 16 bytes from the file.
        # Most file format signatures ("magic numbers") live in this range.
        # If the file is smaller than 16 bytes, read() returns however many exist.
        raw_bytes = f.read(16)

    # Convert the bytes object to a plain hex string.
    # e.g. b'\x89PNG\r\n\x1a\n' becomes '89504e470d0a1a0a'
    # .hex() is a built-in bytes method available since Python 3.5 — no imports needed.
    return raw_bytes.hex()


def identify_file(filepath: str) -> dict:
    import os

    hex_str = read_magic_bytes(filepath)

    # Dictionary keys have different lengths (e.g. '4d5a' = 4 chars, '89504e47' = 8 chars).
    # We can't do a single dict[hex_str] lookup because hex_str is always 32 chars (16 bytes).
    # Instead, for each key we slice hex_str to the same length as that key, then check equality.
    # This lets short keys like EXE ('4d5a') match without requiring the full 16 bytes to align.
    detected_type = None
    for magic, filetype in MAGIC_NUMBERS.items():
        if hex_str[:len(magic)] == magic:
            detected_type = filetype
            break

    # Extract the extension from the filename, uppercased and stripped of the dot.
    # os.path.splitext("file.jpg") → ("file", ".jpg"), so [1][1:] drops the dot.
    ext = os.path.splitext(filepath)[1][1:].upper()

    # Map extensions to the same labels used in MAGIC_NUMBERS for a fair comparison.
    EXT_MAP = {
        # Images
        'PNG': 'PNG', 'JPG': 'JPEG', 'JPEG': 'JPEG',
        'BMP': 'BMP', 'TIFF': 'TIFF', 'TIF': 'TIFF', 'GIF': 'GIF',
        # Audio
        'MP3': 'MP3', 'WAV': 'WAV', 'FLAC': 'FLAC',
        # Video
        'MP4': 'MP4', 'AVI': 'AVI', 'MOV': 'MOV', 'MKV': 'MKV',
        # Archives
        'ZIP': 'ZIP', 'GZ': 'GZ', 'TAR': 'TAR',
        '7Z': 'SEVENZIP', 'RAR': 'RAR',
        # Documents
        'PDF': 'PDF', 'DOC': 'DOC', 'XLS': 'DOC', 'PPT': 'DOC',
        'DOCX': 'ZIP', 'XLSX': 'ZIP', 'PPTX': 'ZIP',
        # Executables
        'EXE': 'EXE', 'DLL': 'EXE', 'SYS': 'EXE',
        'ELF': 'ELF', 'CLASS': 'CLASS',
        # Database
        'DB': 'SQLITE', 'SQLITE': 'SQLITE', 'SQLITE3': 'SQLITE',
    }
    declared_type = EXT_MAP.get(ext)

    # A mismatch means the file's actual content differs from what its extension claims.
    suspicious = detected_type != declared_type

    return {
        'filepath':      filepath,
        'hex_prefix':    hex_str[:16],   # first 8 bytes for readability
        'detected_type': detected_type,
        'declared_type': declared_type,
        'suspicious':    suspicious,
    }
