import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Try to import PyYAML for optional YAML validation
try:
    import yaml
    PYYAML_AVAILABLE = True
except ImportError:
    PYYAML_AVAILABLE = False

# Key for .HERO files in OMORI v1.0.8, used as a literal string, then UTF-8 encoded
OMORI_HERO_KEY_STRING = "6bdb2e585882fbd48826ef9cffd4c511" # This is a 32-character string

# --- Core Encryption/Decryption Logic ---

def decrypt_hero_file(encrypted_filepath, decrypted_filepath, log_callback=print):
    """
    Decrypts an OMORI .HERO file to a .yaml file.
    """
    try:
        key_bytes = OMORI_HERO_KEY_STRING.encode('utf-8')
        if len(key_bytes) != 32:
            log_callback(f"KeyError: Key must be 32 bytes for AES-256. Got {len(key_bytes)} bytes.")
            return False

        with open(encrypted_filepath, 'rb') as f_in:
            iv = f_in.read(16)
            if len(iv) != 16:
                log_callback(f"FileError: Could not read 16 bytes for IV from '{encrypted_filepath}'. File too short or corrupted.")
                return False
            ciphertext = f_in.read()

        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        try:
            decrypted_text = decrypted_padded_data.decode('utf-8')
        except UnicodeDecodeError as ude:
            log_callback(f"DecodeError: Could not decode decrypted data as UTF-8 for '{encrypted_filepath}'. {ude}")
            log_callback("The file might be corrupted, not a valid HERO file, or encrypted with a different key/method.")
            return False

        with open(decrypted_filepath, 'w', encoding='utf-8') as f_out:
            f_out.write(decrypted_text)
            
        log_callback(f"Successfully decrypted '{os.path.basename(encrypted_filepath)}' to '{os.path.basename(decrypted_filepath)}'")

        if os.path.exists(decrypted_filepath):
            if PYYAML_AVAILABLE:
                try:
                    with open(decrypted_filepath, 'r', encoding='utf-8') as f_val:
                        yaml.safe_load(f_val)
                    log_callback("  Verification: Decrypted YAML content seems valid (basic load test successful).")
                except yaml.YAMLError as ye:
                    log_callback(f"  Warning: Decrypted YAML content in '{os.path.basename(decrypted_filepath)}' might have issues: {ye}")
                except Exception as e_val:
                    log_callback(f"  Warning: Error during YAML validation of '{os.path.basename(decrypted_filepath)}': {e_val}")
            else:
                log_callback("  Verification: PyYAML not installed, skipping YAML validation. To enable, run: pip install PyYAML")
        return True

    except FileNotFoundError:
        log_callback(f"Error: File not found at '{encrypted_filepath}'")
    except ValueError as ve: # Should be caught by specific checks, but as a fallback
        log_callback(f"ValueError during decryption of '{encrypted_filepath}': {ve}")
    except Exception as e:
        log_callback(f"An unexpected error occurred during decryption of '{encrypted_filepath}': {e}")
    return False

def encrypt_hero_file(yaml_filepath, hero_filepath, log_callback=print):
    """
    Encrypts a .yaml file to an OMORI .HERO file.
    """
    try:
        key_bytes = OMORI_HERO_KEY_STRING.encode('utf-8')
        if len(key_bytes) != 32:
            log_callback(f"KeyError: Key must be 32 bytes for AES-256. Got {len(key_bytes)} bytes.")
            return False

        with open(yaml_filepath, 'r', encoding='utf-8') as f_in:
            yaml_text = f_in.read()
        
        plaintext_bytes = yaml_text.encode('utf-8')
        iv = os.urandom(16) # Generate a new random IV for each encryption

        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()

        with open(hero_filepath, 'wb') as f_out:
            f_out.write(iv)
            f_out.write(ciphertext)
            
        log_callback(f"Successfully encrypted '{os.path.basename(yaml_filepath)}' to '{os.path.basename(hero_filepath)}'")
        if os.path.exists(hero_filepath) and os.path.getsize(hero_filepath) == (16 + len(ciphertext)):
             log_callback(f"  Verification: Encrypted file '{os.path.basename(hero_filepath)}' created successfully.")
        else:
             log_callback(f"  Warning: Encrypted file '{os.path.basename(hero_filepath)}' problem (not created or wrong size).")
        return True

    except FileNotFoundError:
        log_callback(f"Error: File not found at '{yaml_filepath}'")
    except ValueError as ve: # Should be caught by specific checks, but as a fallback
        log_callback(f"ValueError during encryption of '{yaml_filepath}': {ve}")
    except Exception as e:
        log_callback(f"An unexpected error occurred during encryption of '{yaml_filepath}': {e}")
    return False

# --- GUI Application ---
class HeroConverterApp:
    def __init__(self, master):
        self.master = master
        master.title("OMORI HERO/YAML File Converter By MrGamesKingPro")
        master.geometry("700x550") # Adjusted size

        self.selected_files = [] # Stores full paths of selected files

        # Styling
        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat", font=('Segoe UI', 10))
        style.configure("TLabel", padding=5, font=('Segoe UI', 10))
        style.configure("Header.TLabel", font=('Segoe UI', 12, 'bold'))

        # Main frame
        main_frame = ttk.Frame(master, padding="10 10 10 10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- File Selection Frame ---
        selection_frame = ttk.LabelFrame(main_frame, text="File Selection", padding="10")
        selection_frame.pack(fill=tk.X, pady=5)

        self.file_listbox = tk.Listbox(selection_frame, selectmode=tk.EXTENDED, height=8, font=('Segoe UI', 9))
        self.file_listbox_scrollbar_y = ttk.Scrollbar(selection_frame, orient=tk.VERTICAL, command=self.file_listbox.yview)
        self.file_listbox_scrollbar_x = ttk.Scrollbar(selection_frame, orient=tk.HORIZONTAL, command=self.file_listbox.xview)
        self.file_listbox.config(yscrollcommand=self.file_listbox_scrollbar_y.set, xscrollcommand=self.file_listbox_scrollbar_x.set)
        
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.file_listbox_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox_scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X, before=self.file_listbox_scrollbar_y)


        buttons_frame = ttk.Frame(selection_frame)
        buttons_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10,0))

        self.select_button = ttk.Button(buttons_frame, text="Select Files", command=self._select_files)
        self.select_button.pack(pady=5, fill=tk.X)

        self.clear_button = ttk.Button(buttons_frame, text="Clear Selection", command=self._clear_selection)
        self.clear_button.pack(pady=5, fill=tk.X)

        # --- Action Frame ---
        action_frame = ttk.LabelFrame(main_frame, text="Actions", padding="10")
        action_frame.pack(fill=tk.X, pady=10)

        self.encrypt_button = ttk.Button(action_frame, text="Encrypt Selected (YAML -> HERO)", command=self._process_files_encrypt)
        self.encrypt_button.pack(pady=5, fill=tk.X)

        self.decrypt_button = ttk.Button(action_frame, text="Decrypt Selected (HERO -> YAML)", command=self._process_files_decrypt)
        self.decrypt_button.pack(pady=5, fill=tk.X)

        # --- Log Frame ---
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10, state=tk.DISABLED, font=('Segoe UI', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        self._log("OMORI HERO/YAML Converter Initialized.")
        if not PYYAML_AVAILABLE:
            self._log("Note: PyYAML library not found. YAML validation during decryption will be skipped.")
            self._log("      To enable validation, install it: pip install PyYAML")

    def _log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END) # Scroll to the end
        self.log_text.config(state=tk.DISABLED)
        self.master.update_idletasks() # Ensure GUI updates during processing

    def _refresh_file_listbox(self):
        self.file_listbox.delete(0, tk.END)
        for filepath in self.selected_files:
            self.file_listbox.insert(tk.END, os.path.basename(filepath) + f" ({os.path.dirname(filepath)})")


    def _select_files(self):
        file_types = [
            ("OMORI Moddable Files", "*.HERO *.yaml *.yml"),
            ("HERO files", "*.HERO"),
            ("YAML files", "*.yaml *.yml"),
            ("All files", "*.*")
        ]
        newly_selected_paths = filedialog.askopenfilenames(
            parent=self.master,
            title="Select Files to Process",
            filetypes=file_types
        )
        
        added_count = 0
        if newly_selected_paths:
            for path in newly_selected_paths:
                if path not in self.selected_files:
                    self.selected_files.append(path)
                    added_count += 1
            if added_count > 0:
                self._refresh_file_listbox()
                self._log(f"Added {added_count} new file(s) to selection. Total selected: {len(self.selected_files)}.")
            else:
                self._log("No new files added (they might be already selected).")


    def _clear_selection(self):
        if not self.selected_files:
            self._log("Selection is already empty.")
            return
        self.selected_files.clear()
        self._refresh_file_listbox()
        self._log("Selection cleared.")

    def _process_files_encrypt(self):
        if not self.selected_files:
            self._log("No files selected for encryption.")
            messagebox.showwarning("No Files", "Please select files first.", parent=self.master)
            return

        self._log("\n--- Starting Encryption (YAML to HERO) ---")
        processed_count = 0
        actual_processed_count = 0 # Files actually attempted to process
        
        for filepath in self.selected_files:
            filename = os.path.basename(filepath)
            if filename.lower().endswith((".yaml", ".yml")):
                actual_processed_count += 1
                output_dir = os.path.dirname(filepath)
                output_hero_file = os.path.join(output_dir, os.path.splitext(filename)[0] + ".HERO")
                
                self._log(f"Attempting to encrypt: {filename} -> {os.path.basename(output_hero_file)}")
                if encrypt_hero_file(filepath, output_hero_file, log_callback=self._log):
                    processed_count +=1
                # else: The function itself logs detailed errors
            else:
                self._log(f"Skipping non-YAML file for encryption: {filename}")
        
        if actual_processed_count == 0:
            self._log("--- Encryption process finished. No YAML files were found in the selection. ---")
            messagebox.showinfo("Encryption Info", "No suitable YAML files (.yaml, .yml) were found in the selection to encrypt.", parent=self.master)
        elif processed_count == actual_processed_count:
            self._log(f"--- Encryption process finished. All {processed_count} YAML file(s) processed successfully. ---")
            messagebox.showinfo("Encryption Success", f"Encryption completed for {processed_count} file(s). Check log for details.", parent=self.master)
        else:
            self._log(f"--- Encryption process finished. {processed_count} out of {actual_processed_count} YAML file(s) processed. Check log for errors. ---")
            messagebox.showwarning("Encryption Partially Done", f"Encryption completed for {processed_count} out of {actual_processed_count} file(s). Some files may have failed. Check log for details.", parent=self.master)

    def _process_files_decrypt(self):
        if not self.selected_files:
            self._log("No files selected for decryption.")
            messagebox.showwarning("No Files", "Please select files first.", parent=self.master)
            return

        self._log("\n--- Starting Decryption (HERO to YAML) ---")
        processed_count = 0
        actual_processed_count = 0 # Files actually attempted to process

        for filepath in self.selected_files:
            filename = os.path.basename(filepath)
            if filename.lower().endswith(".hero"):
                actual_processed_count += 1
                output_dir = os.path.dirname(filepath)
                output_yaml_file = os.path.join(output_dir, os.path.splitext(filename)[0] + ".yaml")

                self._log(f"Attempting to decrypt: {filename} -> {os.path.basename(output_yaml_file)}")
                if decrypt_hero_file(filepath, output_yaml_file, log_callback=self._log):
                    processed_count += 1
                # else: The function itself logs detailed errors
            else:
                self._log(f"Skipping non-HERO file for decryption: {filename}")

        if actual_processed_count == 0:
            self._log("--- Decryption process finished. No HERO files were found in the selection. ---")
            messagebox.showinfo("Decryption Info", "No suitable HERO files (.hero) were found in the selection to decrypt.", parent=self.master)
        elif processed_count == actual_processed_count:
            self._log(f"--- Decryption process finished. All {processed_count} HERO file(s) processed successfully. ---")
            messagebox.showinfo("Decryption Success", f"Decryption completed for {processed_count} file(s). Check log for details.", parent=self.master)
        else:
            self._log(f"--- Decryption process finished. {processed_count} out of {actual_processed_count} HERO file(s) processed. Check log for errors. ---")
            messagebox.showwarning("Decryption Partially Done", f"Decryption completed for {processed_count} out of {actual_processed_count} file(s). Some files may have failed. Check log for details.", parent=self.master)


if __name__ == "__main__":
    root = tk.Tk()
    app = HeroConverterApp(root)
    root.mainloop()
