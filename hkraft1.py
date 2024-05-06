import hashlib
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
import os

def open_documentation():
    documentation_text = """Welcome to HashKraft: File Integrity Checker!

Instructions:
1. Upload a file by clicking the 'Browse' button under 'Upload File'.
2. Select a hashing algorithm from the dropdown menu under 'Hash Calculation'.
3. Click 'Calculate Hash' to generate the hash of the uploaded file.
4. The progress bar shows the hashing progress.
5. The hash value will be displayed under 'File Hash'.

To Verify Integrity:
1. Enter the hash value to verify under 'Verify Integrity'.
2. Select the same hashing algorithm used for hashing the file.
3. Click 'Compare Hash' to check the file integrity.
4. If the hashes match, you'll receive a verification message.

Note: Ensure to use the same hash algorithm for verification that was used for hashing the file.

For any queries or support, contact our support team at support@hashkraft.com.
"""
    messagebox.showinfo("Documentation", documentation_text)

def browse_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(tk.END, file_path)
    display_file_info(file_path)

def display_file_info(file_path):
    if os.path.exists(file_path):
        file_info = os.stat(file_path)
        file_size = file_info.st_size
        last_modified = file_info.st_mtime
        file_info_label.config(text=f"File Size: {file_size} bytes\nLast Modified: {last_modified}")
    else:
        file_info_label.config(text="File Information: File not found!")

def clear_file_entry():
    file_entry.delete(0, tk.END)
    file_info_label.config(text="File Information:")

def hash_file():
    file_path = file_entry.get()
    algorithm_choice = file_algorithm_combobox.get()

    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            hash_object = hashlib.new(algorithm_choice)
            file_size = len(content)
            chunk_size = 4096
            hashed_data = bytearray()

            for i in range(0, file_size, chunk_size):
                chunk = content[i:i + chunk_size]
                hash_object.update(chunk)
                hashed_data.extend(chunk)
                progress = min(i + chunk_size, file_size)
                hash_progress['value'] = (progress / file_size) * 100
                root.update_idletasks()

            file_hash_entry.delete(0, tk.END)
            file_hash_entry.insert(tk.END, hash_object.hexdigest())
    except FileNotFoundError:
        pass  # Do nothing if the file is not found
    except Exception as e:
        messagebox.showerror("Error", f"Error hashing the file: {e}")

def clear_file_hash_entry():
    file_hash_entry.delete(0, tk.END)

def compare_hashes():
    current_hash = file_hash_entry.get()
    verify_hash = verify_hash_entry.get()
    verify_algorithm_choice = verify_algorithm_combobox.get()

    if verify_algorithm_choice != file_algorithm_combobox.get():
        messagebox.showerror("Verification", "Integrity cannot be checked for different hash algorithms!")
        return

    if current_hash == verify_hash:
        messagebox.showinfo("Verification", "File integrity verified!")
    else:
        messagebox.showerror("Verification", "File integrity verification failed!")

def copy_file_hash():
    root.clipboard_clear()
    root.clipboard_append(file_hash_entry.get())
    messagebox.showinfo("Copy", "File hash copied to clipboard!")

def clear_verify_hash_entry():
    verify_hash_entry.delete(0, tk.END)

def paste_verify_hash():
    verify_hash_entry.delete(0, tk.END)
    verify_hash_entry.insert(tk.END, root.clipboard_get())

def save_hash_results():
    file_hash = file_hash_entry.get()
    file_path = os.path.basename(file_entry.get())  # Extract filename only
    save_path = filedialog.asksaveasfilename(defaultextension=".txt")
    with open(save_path, 'w') as file:
        file.write(f"File Name: {file_path}\n")
        file.write(f"File Hash: {file_hash}\n")

root = tk.Tk()
root.title("HashKraft: File Integrity Checker")

open_documentation()

style = ttk.Style()
style.theme_use("clam")

# Define themes
theme_options = ["light", "dark", "default"]

upload_frame = ttk.LabelFrame(root, text="Upload File", padding=(10, 5))
upload_frame.pack(padx=20, pady=10, fill="both", expand=True)

file_info_label = ttk.Label(upload_frame, text="File Information:")
file_info_label.grid(row=1, column=0, padx=5, pady=5, columnspan=2)

hash_frame = ttk.LabelFrame(root, text="Hash Calculation", padding=(10, 5))
hash_frame.pack(padx=20, pady=10, fill="both", expand=True)

verify_frame = ttk.LabelFrame(root, text="Verify Integrity", padding=(10, 5))
verify_frame.pack(padx=20, pady=10, fill="both", expand=True)

file_label = ttk.Label(upload_frame, text="Select File:")
file_label.grid(row=0, column=0, padx=5, pady=5)
file_entry = ttk.Entry(upload_frame, width=40)
file_entry.grid(row=0, column=1, padx=5, pady=5)
browse_button = ttk.Button(upload_frame, text="Browse", command=browse_file)
browse_button.grid(row=0, column=2, padx=5, pady=5)
clear_file_button = ttk.Button(upload_frame, text="Clear", command=clear_file_entry)
clear_file_button.grid(row=0, column=3, padx=5, pady=5)

hash_algorithms = ["MD5", "SHA1", "SHA256", "SHA512"]
file_algorithm_label = ttk.Label(hash_frame, text="Select Hashing Algorithm:")
file_algorithm_label.grid(row=0, column=0, padx=5, pady=5)
file_algorithm_combobox = ttk.Combobox(hash_frame, values=hash_algorithms, width=36)
file_algorithm_combobox.grid(row=0, column=1, padx=5, pady=5)
file_algorithm_combobox.current(0)

hash_progress = ttk.Progressbar(hash_frame, orient=tk.HORIZONTAL, length=200, mode='determinate', style="color.Horizontal.TProgressbar")
style.configure("color.Horizontal.TProgressbar", troughcolor='lightblue', background='blue', bordercolor='black', borderwidth=2)
hash_progress.grid(row=1, columnspan=2, padx=5, pady=5)

hash_button = ttk.Button(hash_frame, text="Calculate Hash", command=hash_file)
hash_button.grid(row=2, columnspan=2, padx=5, pady=10)

file_hash_label = ttk.Label(hash_frame, text="File Hash:")
file_hash_label.grid(row=3, column=0, padx=5, pady=5)
file_hash_entry = ttk.Entry(hash_frame, width=40)
file_hash_entry.grid(row=3, column=1, padx=5, pady=5)
copy_button = ttk.Button(hash_frame, text="Copy", command=copy_file_hash)
copy_button.grid(row=3, column=2, padx=5, pady=5)
clear_file_hash_button = ttk.Button(hash_frame, text="Clear", command=clear_file_hash_entry)
clear_file_hash_button.grid(row=3, column=3, padx=5, pady=5)

verify_hash_label = ttk.Label(verify_frame, text="Enter Hash to Verify:")
verify_hash_label.grid(row=0, column=0, padx=5, pady=5)
verify_hash_entry = ttk.Entry(verify_frame, width=40)
verify_hash_entry.grid(row=0, column=1, padx=5, pady=5)
paste_button = ttk.Button(verify_frame, text="Paste", command=paste_verify_hash)
paste_button.grid(row=0, column=2, padx=5, pady=5)
clear_verify_hash_button = ttk.Button(verify_frame, text="Clear", command=clear_verify_hash_entry)
clear_verify_hash_button.grid(row=0, column=3, padx=5, pady=5)

verify_algorithm_label = ttk.Label(verify_frame, text="Select Verification Algorithm:")
verify_algorithm_label.grid(row=1, column=0, padx=5, pady=5)
verify_algorithm_combobox = ttk.Combobox(verify_frame, values=hash_algorithms, width=36)
verify_algorithm_combobox.grid(row=1, column=1, padx=5, pady=5)
verify_algorithm_combobox.current(0)

compare_button = ttk.Button(verify_frame, text="Compare Hash", command=compare_hashes)
compare_button.grid(row=2, columnspan=2, padx=5, pady=10)

save_button = ttk.Button(hash_frame, text="Save Hash Results", command=save_hash_results)
save_button.grid(row=4, columnspan=2, padx=5, pady=10)

# Function to change theme
def change_theme(event):
    selected_theme = theme_combobox.get()
    if selected_theme == "light":
        root.tk_setPalette(background='#ffffff', foreground='black', activeBackground='#eeeeee', activeForeground='black')
    elif selected_theme == "dark":
        root.tk_setPalette(background='#333333', foreground='white', activeBackground='#666666', activeForeground='white')
    elif selected_theme == "default":
        root.tk_setPalette(background='', foreground='', activeBackground='', activeForeground='')

theme_label = ttk.Label(root, text="Select Theme:")
theme_label.pack(padx=20, pady=5)
theme_combobox = ttk.Combobox(root, values=theme_options, width=12)
theme_combobox.pack(padx=20, pady=5)
theme_combobox.bind("<<ComboboxSelected>>", change_theme)
theme_combobox.current(0)

root.mainloop()