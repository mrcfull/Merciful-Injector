# Made by Zudozuka on Github, December 23rd 2021, Recovered by mrcfull (Zudozuka) in August 2023, code is very unstable, not that many bugs are in the code, I did try to refine it and update it, but still basic.
# If you're developing a similar project, feel completely free to use my code in your project.

import os
import ctypes
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, scrolledtext
import psutil
from ttkthemes import ThemedStyle

# Function to select a DLL payload
def select_payload_dll():
    payload_dll = filedialog.askopenfilename(filetypes=[("DLL Files", "*.dll")])
    payload_entry.delete(0, tk.END)
    payload_entry.insert(0, payload_dll)

# Function to inject DLL into the selected process
def inject_dll():
    selected_process = process_combobox.get()
    payload_dll = payload_entry.get()
    injection_mode = injection_mode_var.get()

    if not payload_dll:
        log_text.insert(tk.END, "Please select a payload DLL\n")
        return

    try:
        # Load the target process
        process_id = None
        for process in psutil.process_iter(attrs=['pid', 'name']):
            if process.info['name'].lower() == selected_process.lower():
                process_id = process.info['pid']
                break

        if process_id is None:
            log_text.insert(tk.END, f"Failed to find the selected process: {selected_process}\n")
            return

        # Access the kernel32 module
        kernel32 = ctypes.WinDLL("kernel32")

        process_handle = kernel32.OpenProcess(0x1F0FFF, False, process_id)
        if not process_handle:
            log_text.insert(tk.END, f"Failed to open process: {ctypes.GetLastError()}\n")
            return

        # Allocate memory in the target process
        payload_path = os.path.abspath(payload_dll)
        payload_size = len(payload_path) + 1
        remote_payload = kernel32.VirtualAllocEx(process_handle, None, payload_size, 0x3000, 0x40)
        if not remote_payload:
            log_text.insert(tk.END, f"Failed to allocate memory: {ctypes.GetLastError()}\n")
            kernel32.CloseHandle(process_handle)
            return

        # Write the payload path to the allocated memory
        written = ctypes.c_ulong(0)
        kernel32.WriteProcessMemory(process_handle, remote_payload, payload_path.encode(), payload_size, ctypes.byref(written))
        if written.value != payload_size:
            log_text.insert(tk.END, "Failed to write payload path to memory\n")
            kernel32.VirtualFreeEx(process_handle, remote_payload, 0, 0x8000)
            kernel32.CloseHandle(process_handle)
            return

        # Load the DLL into the target process
        kernel32.CreateRemoteThread(process_handle, None, 0, ctypes.cast(kernel32.LoadLibraryA, ctypes.c_void_p),
                                    remote_payload, 0, None)

        log_text.insert(tk.END, f"DLL injected into {selected_process} using {injection_mode} mode\n")

        # Clean up
        kernel32.CloseHandle(process_handle)
        kernel32.VirtualFreeEx(process_handle, remote_payload, 0, 0x8000)
    except Exception as e:
        log_text.insert(tk.END, f"Error during injection: {str(e)}\n")

# Function to enumerate running processes
def enumerate_processes():
    process_combobox['values'] = sorted([process.info['name'] for process in psutil.process_iter(attrs=['name'])])

# Create the main window
root = tk.Tk()
root.title("DLL Injector")
root.geometry("900x600")

# Use ThemedStyle for modern styling
style = ThemedStyle(root)
style.set_theme("plastik")  # You can choose different themes

# Create tabs at the top for options
tab_control = ttk.Notebook(root)
tab_control.pack(fill="both", expand=True)

# Create Targets tab
targets_tab = ttk.Frame(tab_control)
tab_control.add(targets_tab, text="Injection")

# Create a combobox for selecting the target process
process_combobox = ttk.Combobox(targets_tab, values=[], state="readonly")
process_combobox.set("")  # Set an initial empty value
process_combobox.pack(pady=10)

# Create Payload tab
payload_tab = ttk.Frame(tab_control)
tab_control.add(payload_tab, text="Payload")

payload_label = ttk.Label(payload_tab, text="Select Payload DLL:")
payload_label.pack()

payload_entry = ttk.Entry(payload_tab, width=40)
payload_entry.pack()

select_payload_button = ttk.Button(payload_tab, text="Browse", command=select_payload_dll)
select_payload_button.pack()

# Create Injection tab
injection_tab = ttk.Frame(tab_control)
tab_control.add(injection_tab, text="Inject")

injection_mode_label = ttk.Label(injection_tab, text="Select Injection Mode:")
injection_mode_label.pack()

injection_mode_var = tk.StringVar()
injection_mode_var.set("Standard")

injection_mode_menu = ttk.OptionMenu(injection_tab, injection_mode_var, "Standard", "Manual Map", "Reflective DLL")
injection_mode_menu.pack()

inject_button = ttk.Button(injection_tab, text="Inject DLL", command=inject_dll)
inject_button.pack()

# Create Log tab
log_tab = ttk.Frame(tab_control)
tab_control.add(log_tab, text="Log")

log_text = scrolledtext.ScrolledText(log_tab, wrap=tk.WORD, width=40, height=20, state=tk.DISABLED)
log_text.pack(fill=tk.BOTH, expand=True)

# Automatically enumerate processes upon launch
enumerate_processes()

# Start the GUI application
root.mainloop()
