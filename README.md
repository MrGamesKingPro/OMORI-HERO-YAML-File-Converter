# OMORI-HERO-YAML-File-Converter
tool for encrypting and decrypting OMORI's .HERO files. These files in OMORI are typically YAML data files encrypted with AES. This tool allows modders or curious users to view/edit these YAML files.

![omori-hero-yaml-File-converter](https://github.com/user-attachments/assets/32a6ed97-08ea-461e-b052-3ccf41fe6cac)

**How to Use the Tool**

1.  **Prerequisites:**
    *   Python 3 installed.
    *   Install the library: `pip install cryptography PyYAML`

2.  **Run the Script:**
    *   Run the script: `python omori-hero-yaml-File-converter.py`

3.  **Using the GUI:**
    *   **Select Files:**
        *   Click the "Select Files" button.
        *   A file dialog will open. You can navigate to your OMORI game's `www/languages/en` directory (or wherever your `.HERO` files are) or to your modded `.yaml` files.
        *   Select one or more files (`.HERO`, `.yaml`, `.yml`). You can use Ctrl+Click or Shift+Click for multiple selections.
        *   The selected files will appear in the listbox, showing their name and parent directory.
    *   **Clear Selection:**
        *   Click "Clear Selection" to remove all files from the listbox.
    *   **Decrypt (HERO -> YAML):**
        *   Select one or more `.HERO` files from the listbox.
        *   Click the "Decrypt Selected (HERO -> YAML)" button.
        *   The tool will attempt to decrypt each selected `.HERO` file.
        *   A corresponding `.yaml` file will be created in the same directory as the original `.HERO` file.
        *   Progress and any errors will be shown in the "Log" text area.
        *   A message box will pop up summarizing the operation.
    *   **Encrypt (YAML -> HERO):**
        *   Select one or more `.yaml` or `.yml` files from the listbox.
        *   Click the "Encrypt Selected (YAML -> HERO)" button.
        *   The tool will attempt to encrypt each selected YAML file.
        *   A corresponding `.HERO` file will be created in the same directory as the original `.yaml` file.
        *   Progress and any errors will be shown in the "Log" text area.
        *   A message box will pop up summarizing the operation.
    *   **Log Area:**
        *   This area at the bottom provides detailed information about each step, including successful operations, warnings (e.g., YAML parsing issues if `PyYAML` is used), and errors (e.g., file not found, decryption failure).

**Important Considerations:**

*   **Backup Files:** Always back up your original game files before modifying them or replacing them with encrypted/decrypted versions.
*   **Key Specificity:** This tool uses a key known for OMORI v1.0.8. If you are working with files from a different game version or a different game entirely that uses a similar encryption scheme, this key might not work.
*   **File Corruption:** If a `.HERO` file is corrupted or not a valid OMORI encrypted file, decryption will likely fail, potentially with a `UnicodeDecodeError` or an error from the cryptography library.
*   **UTF-8 Encoding:** The tool assumes the decrypted content is UTF-8 encoded YAML. If the original data was not UTF-8, decryption might succeed, but the resulting text could be garbled or `UnicodeDecodeError` might occur. Similarly, when encrypting, the YAML file is read as UTF-8.

This tool provides a convenient way to interact with OMORI's encrypted data files, primarily for modding purposes.
