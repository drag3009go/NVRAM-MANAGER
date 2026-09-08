import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import ctypes
from ctypes import wintypes
import sys
import os
import struct
import binascii
import subprocess
import shutil
import string

EFI_GLOBAL_GUID = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
ERROR_ENVVAR_NOT_FOUND = 203

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    script = os.path.abspath(sys.argv[0])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, script, None, 1)
    sys.exit()

if not is_admin():
    run_as_admin()

def enable_system_environment_privilege():
    SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege"
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x2

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD),
                    ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID),
                    ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    OpenProcessToken = advapi32.OpenProcessToken
    OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    OpenProcessToken.restype = wintypes.BOOL

    LookupPrivilegeValueW = advapi32.LookupPrivilegeValueW
    LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
    LookupPrivilegeValueW.restype = wintypes.BOOL

    AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
    AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
                                      wintypes.DWORD, ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(wintypes.DWORD)]
    AdjustTokenPrivileges.restype = wintypes.BOOL

    hToken = wintypes.HANDLE()
    if not OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(hToken)):
        return False

    try:
        luid = LUID()
        if not LookupPrivilegeValueW(None, SE_SYSTEM_ENVIRONMENT_NAME, ctypes.byref(luid)):
            return False

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        if not AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None):
            return False

        if ctypes.GetLastError() == 1300:
            return False

        return True
    finally:
        if hToken:
            kernel32.CloseHandle(hToken)

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
GetFirmwareEnvironmentVariableW = kernel32.GetFirmwareEnvironmentVariableW
GetFirmwareEnvironmentVariableW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPVOID, wintypes.DWORD]
GetFirmwareEnvironmentVariableW.restype = wintypes.DWORD

SetFirmwareEnvironmentVariableW = kernel32.SetFirmwareEnvironmentVariableW
SetFirmwareEnvironmentVariableW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPVOID, wintypes.DWORD]
SetFirmwareEnvironmentVariableW.restype = wintypes.BOOL

def read_uefi_var(name, guid):
    buffer = ctypes.create_string_buffer(8192)
    length = GetFirmwareEnvironmentVariableW(name, guid, buffer, 8192)
    if length == 0:
        return None, ctypes.get_last_error()
    return buffer.raw[:length], 0

def write_uefi_var(name, guid, data):
    if data is None or len(data) == 0:
        result = SetFirmwareEnvironmentVariableW(name, guid, None, 0)
    else:
        result = SetFirmwareEnvironmentVariableW(name, guid, data, len(data))
    if not result:
        return False, ctypes.get_last_error()
    return True, 0

def parse_device_path(data, offset, path_length):
    parts = []
    pos = offset
    end_pos = min(len(data), offset + path_length) if path_length > 0 else len(data)

    while pos < end_pos:
        if pos + 4 > end_pos:
            break

        type_byte = data[pos]
        sub_type = data[pos + 1]
        length = struct.unpack_from('<H', data, pos + 2)[0]

        if length < 4 or pos + length > end_pos:
            break

        if type_byte == 0x7F:
            break

        if type_byte == 1:
            if sub_type == 1:
                pci_dev, pci_fn = data[pos+4], data[pos+5]
                parts.append(f"PciRoot(0x0)/Pci(0x{pci_dev:X},0x{pci_fn:X})")
            elif sub_type == 18:
                parts.append("NVMe")
            else:
                parts.append(f"Hw({type_byte}:{sub_type})")

        elif type_byte == 3:
            if sub_type == 1:
                parts.append("SATA/CDROM")
            elif sub_type == 14:
                parts.append("Floppy")
            elif sub_type == 16:
                parts.append("USB")
            elif sub_type == 23:
                if length >= 8:
                    nsid = struct.unpack_from('<I', data, pos + 4)[0]
                    parts.append(f"NVMe(NSID=0x{nsid:X})")
                else:
                    parts.append("NVMe")
            elif sub_type == 24:
                parts.append("MAC/Network")
            else:
                parts.append(f"Msg({sub_type})")

        elif type_byte == 4:
            if sub_type == 2 and length >= 42:
                partition_num = struct.unpack_from('<I', data, pos + 4)[0]
                partition_start = struct.unpack_from('<Q', data, pos + 8)[0]
                partition_size = struct.unpack_from('<Q', data, pos + 16)[0]
                partition_format = data[pos + 38]

                if partition_format == 2:
                    guid_bytes = data[pos + 22:pos + 38]
                    d1, d2, d3 = struct.unpack_from('<IHH', guid_bytes, 0)
                    d4 = guid_bytes[8:16]
                    guid_str = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[:2].hex().upper()}-{d4[2:].hex().upper()}"
                    parts.append(
                        f"HD({partition_num},GPT,{guid_str},"
                        f"0x{partition_start:X},0x{partition_size:X})"
                    )
                else:
                    parts.append(f"HD({partition_num},MBR)")

            elif sub_type == 4:
                path_bytes = data[pos + 4 : pos + length]
                try:
                    path_str = path_bytes.decode('utf-16-le').rstrip('\x00')
                    if path_str:
                        if not path_str.startswith('\\'):
                            path_str = '\\' + path_str
                        parts.append(path_str)
                except Exception:
                    pass

        pos += length

    return "/".join(parts) if parts else ""

def parse_boot_option(data):
    if len(data) < 6:
        return "", ""

    file_path_len = struct.unpack_from('<H', data, 4)[0]
    pos = 6
    desc_bytes = bytearray()
    while pos + 1 < len(data):
        char_val = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        if char_val == 0:
            break
        desc_bytes.extend(struct.pack('<H', char_val))

    description = desc_bytes.decode('utf-16-le', errors='ignore')
    full_path = parse_device_path(data, pos, file_path_len)

    return description, full_path

def get_all_variables():
    known_names = [
        "BootOrder", "BootCurrent", "Timeout", "SecureBoot",
        "SetupMode", "PlatformLang", "Lang", "VendorKeys",
        "BootNext", "OsIndications", "ConIn", "ConOut", "ErrOut",
    ]
    for i in range(0x0000, 0x0200):
        known_names.append(f"Boot{i:04X}")

    variables = []
    for name in known_names:
        data, err = read_uefi_var(name, EFI_GLOBAL_GUID)
        if data is None:
            if err in (2, ERROR_ENVVAR_NOT_FOUND):
                continue
            variables.append((name, "", f"<Error {err}>", ""))
            continue

        hex_value = binascii.hexlify(data).decode('ascii').upper()
        desc = ""
        file_path = ""

        if name.startswith("Boot") and len(name) == 8 and name[4:].isalnum():
            desc, file_path = parse_boot_option(data)
        else:
            try:
                text = data.decode('utf-16-le').rstrip('\x00')
                if text.isprintable():
                    desc = text
            except:
                pass

        variables.append((name, hex_value, desc, file_path))

    return variables

def delete_boot_entry(name):
    success, err = write_uefi_var(name, EFI_GLOBAL_GUID, None)
    return success, err

def update_boot_order(order_list):
    data = bytearray()
    for name in order_list:
        num = int(name[4:8], 16)
        data.extend(struct.pack('<H', num))
    success, err = write_uefi_var("BootOrder", EFI_GLOBAL_GUID, bytes(data))
    return success, err

def update_boot_description(name, new_description):
    data, err = read_uefi_var(name, EFI_GLOBAL_GUID)
    if data is None:
        return False, err

    if len(data) < 6:
        return False, -1
    file_path_len = struct.unpack_from('<H', data, 4)[0]
    pos = 6
    while pos + 1 < len(data):
        if data[pos] == 0 and data[pos+1] == 0:
            pos += 2
            break
        pos += 2
    device_path_data = data[pos:pos+file_path_len] if file_path_len > 0 else b''

    attributes = 0x00000001
    desc_utf16 = new_description.encode('utf-16-le') + b'\x00\x00'
    new_data = struct.pack('<I', attributes)
    new_data += struct.pack('<H', file_path_len)
    new_data += desc_utf16
    new_data += device_path_data

    success, err = write_uefi_var(name, EFI_GLOBAL_GUID, new_data)
    return success, err

def get_free_drive_letter():
    used = [d[0] for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
    for letter in string.ascii_uppercase:
        if letter not in used:
            return letter
    return None

def mount_efi_partition(drive_letter):
    try:
        cmd = f'mountvol {drive_letter}: /S'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return False, result.stderr
        if not os.path.exists(f"{drive_letter}:\\EFI"):
            return False, "EFI folder not found after mounting."
        return True, None
    except Exception as e:
        return False, str(e)

def unmount_efi_partition(drive_letter):
    try:
        cmd = f'mountvol {drive_letter}: /D'
        subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return True
    except:
        return False

def get_embedded_file_path(filename):
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base, filename)
    if os.path.exists(path):
        return path
    return None

def restore_boot_files():
    drive_letter = get_free_drive_letter()
    if not drive_letter:
        return "No free drive letter available for mounting EFI partition."

    ok, err = mount_efi_partition(drive_letter)
    if not ok:
        return f"Failed to mount EFI partition: {err}"

    esp_root = f"{drive_letter}:"
    try:
        if not os.path.exists(f"{esp_root}\\EFI"):
            return f"EFI folder not found at {esp_root}\\EFI after mounting."

        bootmgfw_src = get_embedded_file_path('bootmgfw.efi')
        bootx64_src = get_embedded_file_path('bootx64.efi')
        if not bootmgfw_src:
            return "bootmgfw.efi not found in embedded resources."
        if not bootx64_src:
            bootx64_src = bootmgfw_src

        dest_microsoft = f"{esp_root}\\EFI\\Microsoft\\Boot"
        dest_boot = f"{esp_root}\\EFI\\Boot"
        os.makedirs(dest_microsoft, exist_ok=True)
        os.makedirs(dest_boot, exist_ok=True)

        def safe_replace(src, dst):
            try:
                if os.path.exists(dst):
                    os.chmod(dst, 0o777)
                    os.remove(dst)
                shutil.copy2(src, dst)
                return True, None
            except Exception as e:
                return False, str(e)

        dst1 = os.path.join(dest_microsoft, 'bootmgfw.efi')
        ok1, err1 = safe_replace(bootmgfw_src, dst1)
        if not ok1:
            return f"Error replacing bootmgfw.efi: {err1}"

        dst2 = os.path.join(dest_boot, 'bootx64.efi')
        ok2, err2 = safe_replace(bootx64_src, dst2)
        if not ok2:
            return f"Error replacing bootx64.efi: {err2}"

        found = False
        for i in range(0x0000, 0x0200):
            name = f"Boot{i:04X}"
            data, _ = read_uefi_var(name, EFI_GLOBAL_GUID)
            if data is not None:
                desc, path = parse_boot_option(data)
                if "Windows Boot Manager" in desc or "bootmgfw.efi" in path.lower():
                    found = True
                    break

        if found:
            return (f"Files replaced on {esp_root}.\n"
                    "Windows Boot Manager entry found. Please reboot.")

        windows_drive = os.environ.get('SystemDrive', 'C:')
        cmd = f'bcdboot {windows_drive}\\Windows /s {esp_root} /f UEFI'
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"Files replaced, boot entry created via bcdboot."
            else:
                manual = (
                    f"bootmgfw.efi and bootx64.efi successfully replaced.\n"
                    f"Could not automatically create boot entry.\n"
                    f"To complete recovery manually run:\n"
                    f"   bcdboot {windows_drive}\\Windows /s {esp_root} /f UEFI"
                )
                return manual
        except Exception as e:
            return f"Error running bcdboot: {e}\n\nFiles replaced but boot entry not created."

    finally:
        unmount_efi_partition(drive_letter)

def find_free_boot_number():
    for i in range(0x0000, 0x0200):
        name = f"Boot{i:04X}"
        data, err = read_uefi_var(name, EFI_GLOBAL_GUID)
        if data is None and (err == 2 or err == ERROR_ENVVAR_NOT_FOUND):
            return name
    for i in range(0x0200, 0x10000):
        name = f"Boot{i:04X}"
        data, err = read_uefi_var(name, EFI_GLOBAL_GUID)
        if data is None and (err == 2 or err == ERROR_ENVVAR_NOT_FOUND):
            return name
    return None

def create_boot_entry(description, file_path_hex):
    try:
        file_path_bytes = bytes.fromhex(file_path_hex)
    except ValueError:
        return False, "Invalid hex format"

    attributes = 0x00000001
    file_path_len = len(file_path_bytes)
    desc_utf16 = description.encode('utf-16-le') + b'\x00\x00'

    new_data = struct.pack('<I', attributes)
    new_data += struct.pack('<H', file_path_len)
    new_data += desc_utf16
    new_data += file_path_bytes

    boot_name = find_free_boot_number()
    if boot_name is None:
        return False, "No free Boot numbers found (checked up to 0xFFFF)."

    success, err = write_uefi_var(boot_name, EFI_GLOBAL_GUID, new_data)
    if success:
        return True, (boot_name, err)
    return False, err

def update_boot_path(name, new_file_path_hex):
    data, err = read_uefi_var(name, EFI_GLOBAL_GUID)
    if data is None:
        return False, err
    if len(data) < 6:
        return False, -1

    attributes = struct.unpack_from('<I', data, 0)[0]

    pos = 6
    while pos + 1 < len(data):
        if data[pos] == 0 and data[pos+1] == 0:
            pos += 2
            break
        pos += 2

    try:
        new_path_bytes = bytes.fromhex(new_file_path_hex)
    except ValueError:
        return False, "Invalid hex format"

    new_file_path_len = len(new_path_bytes)
    new_data = struct.pack('<I', attributes)
    new_data += struct.pack('<H', new_file_path_len)
    desc_data = data[6:pos]
    new_data += desc_data
    new_data += new_path_bytes

    success, err = write_uefi_var(name, EFI_GLOBAL_GUID, new_data)
    return success, err

def extract_file_path_hex(data):
    if len(data) < 6:
        return None
    file_path_len = struct.unpack_from('<H', data, 4)[0]
    pos = 6
    while pos + 1 < len(data):
        if data[pos] == 0 and data[pos+1] == 0:
            pos += 2
            break
        pos += 2
    file_path_bytes = data[pos:pos+file_path_len]
    return file_path_bytes.hex().upper()

def add_to_boot_order(boot_name):
    data, _ = read_uefi_var("BootOrder", EFI_GLOBAL_GUID)
    if data is None:
        num = int(boot_name[4:8], 16)
        new_order = struct.pack('<H', num)
        return write_uefi_var("BootOrder", EFI_GLOBAL_GUID, new_order)
    else:
        current_order = []
        for i in range(0, len(data), 2):
            num = struct.unpack_from('<H', data, i)[0]
            current_order.append(f"Boot{num:04X}")
        if boot_name in current_order:
            return True, 0
        num = int(boot_name[4:8], 16)
        new_order = data + struct.pack('<H', num)
        return write_uefi_var("BootOrder", EFI_GLOBAL_GUID, new_order)

def path_to_utf16le_hex(file_path):
    if not file_path.startswith('\\'):
        file_path = '\\' + file_path
    utf16_bytes = file_path.encode('utf-16-le') + b'\x00\x00'
    return utf16_bytes.hex().upper()

def get_relative_efi_path(file_path):
    drive = os.path.splitdrive(file_path)[0]
    if not drive:
        return None
    root = drive + '\\'
    if os.path.exists(root + 'EFI'):
        rel = os.path.relpath(file_path, root)
        rel = rel.replace('/', '\\')
        if not rel.startswith('\\'):
            rel = '\\' + rel
        return rel
    return None

class NVRAMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NVRAM Manager (UEFI) - Made by DragonNew17 :-D")
        self.root.geometry("1500x750")

        style = ttk.Style()
        if 'clam' in style.theme_names():
            style.theme_use('clam')
        style.configure('Treeview',
                        background='#2d2d2d',
                        foreground='white',
                        fieldbackground='#2d2d2d',
                        rowheight=25)
        style.map('Treeview',
                  background=[('selected', '#347083')],
                  foreground=[('selected', 'white')])
        style.configure('Treeview.Heading',
                        background='#3a3a3a',
                        foreground='white',
                        relief='flat')
        style.map('Treeview.Heading',
                  background=[('active', '#4a4a4a')])
        style.configure('TButton',
                        background='#3a3a3a',
                        foreground='white',
                        borderwidth=1)
        style.map('TButton',
                  background=[('active', '#4a4a4a')])
        style.configure('TLabel', background='#2d2d2d', foreground='white')
        style.configure('TFrame', background='#2d2d2d')
        self.root.configure(bg='#2d2d2d')

        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ("name", "hex_value", "description", "file_path")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings")
        self.tree.heading("name", text="Name")
        self.tree.heading("hex_value", text="Value (hex)")
        self.tree.heading("description", text="Description")
        self.tree.heading("file_path", text="Device Path")

        self.tree.column("name", width=100, anchor="w", stretch=False)
        self.tree.column("hex_value", width=250, anchor="w", stretch=False)
        self.tree.column("description", width=250, anchor="w", stretch=False)
        self.tree.column("file_path", width=800, anchor="w", stretch=True)

        v_scroll = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scroll = ttk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<Button-3>", self.show_context_menu)

        control_frame = ttk.Frame(root)
        control_frame.pack(pady=5, fill=tk.X)

        ttk.Button(control_frame, text="Refresh", command=self.refresh).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Delete Selected", command=self.delete_selected_entries).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Edit Description", command=self.edit_description_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Change Boot Order", command=self.edit_boot_order).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Restore Bootloader", command=self.restore_boot).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Add Entry", command=self.add_boot_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Edit Path", command=self.edit_boot_path).pack(side=tk.LEFT, padx=5)

        self.status = ttk.Label(root, text="Ready - Made by DragonNew17 :-D", relief=tk.SUNKEN, anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)
        self.status.configure(background='#3a3a3a', foreground='white')

        self.refresh()

    def set_status(self, text, is_error=False):
        self.status.config(text=text, foreground="red" if is_error else "white")

    def refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        vars_list = get_all_variables()
        for name, hex_val, desc, fpath in vars_list:
            self.tree.insert("", tk.END, values=(name, hex_val, desc, fpath))
        self.set_status(f"Loaded {len(vars_list)} variables.")

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
        menu = tk.Menu(self.root, tearoff=0, bg='#3a3a3a', fg='white')
        menu.add_command(label="Delete Selected", command=self.delete_selected_entries)
        menu.add_command(label="Edit Description", command=self.edit_description_selected)
        menu.add_separator()
        menu.add_command(label="Edit Path", command=self.edit_boot_path)
        menu.add_separator()
        menu.add_command(label="Add Entry", command=self.add_boot_entry)
        menu.add_separator()
        menu.add_command(label="Change Boot Order", command=self.edit_boot_order)
        menu.add_command(label="Refresh", command=self.refresh)
        menu.post(event.x_root, event.y_root)

    def delete_selected_entries(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No selection", "Please select at least one entry.")
            return
        names = []
        for item in selected:
            name = self.tree.item(item, 'values')[0]
            if name.startswith("Boot") and len(name) == 8 and name[4:].isalnum():
                names.append(name)
        if not names:
            messagebox.showwarning("No boot entries", "Selected items do not include BootXXXX entries.")
            return
        if not messagebox.askyesno("Confirm", f"Delete {len(names)} entries?"):
            return
        errors = []
        for name in names:
            success, err = delete_boot_entry(name)
            if not success:
                errors.append(f"{name}: {err}")
        if errors:
            self.set_status(f"Errors: {', '.join(errors)}", True)
            messagebox.showerror("Errors", "Not all entries were deleted:\n" + "\n".join(errors))
        else:
            self.set_status(f"Deleted {len(names)} entries.")
            messagebox.showinfo("Success", f"Deleted {len(names)} entries.")
        self.refresh()

    def edit_description_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No selection", "Please select an entry.")
            return
        item = selected[0]
        name = self.tree.item(item, 'values')[0]
        if not (name.startswith("Boot") and len(name) == 8 and name[4:].isalnum()):
            messagebox.showerror("Invalid entry", "Only BootXXXX entries can be edited.")
            return
        current_desc = self.tree.item(item, 'values')[2]
        new_desc = simpledialog.askstring("Edit Description",
                                          f"New description for {name}:",
                                          initialvalue=current_desc)
        if new_desc is None:
            return
        if not new_desc.strip():
            messagebox.showwarning("Empty description", "Description cannot be empty.")
            return
        success, err = update_boot_description(name, new_desc.strip())
        if success:
            self.set_status(f"Description for {name} updated.")
            self.refresh()
        else:
            self.set_status(f"Error: {err}", True)
            messagebox.showerror("Error", f"Failed to update description. Code: {err}")

    def edit_boot_order(self):
        data, err = read_uefi_var("BootOrder", EFI_GLOBAL_GUID)
        if data is None:
            messagebox.showerror("Error", "Failed to read BootOrder.")
            return
        current_order = []
        for i in range(0, len(data), 2):
            num = struct.unpack_from('<H', data, i)[0]
            current_order.append(f"Boot{num:04X}")

        all_boots = []
        for child in self.tree.get_children():
            name = self.tree.item(child, 'values')[0]
            if name.startswith("Boot") and len(name) == 8:
                all_boots.append(name)

        order_window = tk.Toplevel(self.root)
        order_window.title("Boot Order")
        order_window.geometry("400x500")
        order_window.configure(bg='#2d2d2d')

        listbox = tk.Listbox(order_window, selectmode=tk.SINGLE, exportselection=False,
                             bg='#3a3a3a', fg='white', selectbackground='#347083')
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        for name in current_order:
            if name in all_boots:
                listbox.insert(tk.END, name)

        btn_frame = ttk.Frame(order_window)
        btn_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5)

        def move_up():
            idx = listbox.curselection()
            if idx and idx[0] > 0:
                item = listbox.get(idx[0])
                listbox.delete(idx[0])
                listbox.insert(idx[0]-1, item)
                listbox.selection_set(idx[0]-1)

        def move_down():
            idx = listbox.curselection()
            if idx and idx[0] < listbox.size()-1:
                item = listbox.get(idx[0])
                listbox.delete(idx[0])
                listbox.insert(idx[0]+1, item)
                listbox.selection_set(idx[0]+1)

        ttk.Button(btn_frame, text="↑ Up", command=move_up).pack(pady=5)
        ttk.Button(btn_frame, text="↓ Down", command=move_down).pack(pady=5)

        def apply_order():
            new_order = listbox.get(0, tk.END)
            if not new_order:
                messagebox.showwarning("Empty order", "Boot order list cannot be empty.")
                return
            success, err = update_boot_order(new_order)
            if success:
                messagebox.showinfo("Success", "Boot order updated.")
                order_window.destroy()
                self.refresh()
            else:
                messagebox.showerror("Error", f"Failed to update BootOrder. Code: {err}")

        ttk.Button(order_window, text="Apply", command=apply_order).pack(pady=10)

    def restore_boot(self):
        if not messagebox.askyesno("Confirm",
                                   "Replace bootmgfw.efi and bootx64.efi with embedded files?"):
            return
        self.set_status("Restoring...")
        self.root.update()
        result = restore_boot_files()
        if "success" in result.lower() or "replaced" in result.lower():
            self.set_status(result)
            messagebox.showinfo("Result", result)
            self.refresh()
        else:
            self.set_status(result, True)
            messagebox.showwarning("Attention", result)

    def add_boot_entry(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Boot Entry")
        dialog.geometry("700x380")
        dialog.configure(bg='#2d2d2d')

        ttk.Label(dialog, text="Description:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        desc_entry = ttk.Entry(dialog, width=60)
        desc_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(dialog, text="Device Path (hex):").grid(row=1, column=0, padx=5, pady=5, sticky="ne")
        path_entry = ttk.Entry(dialog, width=80)
        path_entry.grid(row=1, column=1, padx=5, pady=5)

        def pick_file_and_encode():
            file_path = filedialog.askopenfilename(title="Select EFI file (e.g., bootmgfw.efi)")
            if not file_path:
                return
            rel = get_relative_efi_path(file_path)
            if rel:
                hex_path = path_to_utf16le_hex(rel)
                path_entry.delete(0, tk.END)
                path_entry.insert(0, hex_path)
                messagebox.showinfo("Success", f"Relative path {rel} converted to HEX.")
            else:
                hex_path = path_to_utf16le_hex(file_path)
                path_entry.delete(0, tk.END)
                path_entry.insert(0, hex_path)
                messagebox.showwarning("Attention",
                                       "Selected file is not on an EFI partition (no EFI folder in root).\n"
                                       "Full path encoded, but a full Device Path is required for boot.\n"
                                       "It is recommended to copy the device prefix from an existing entry.")
        ttk.Button(dialog, text="Select file and encode path", command=pick_file_and_encode).grid(row=2, column=0, columnspan=2, pady=5)

        def paste_from_selected():
            sel = self.tree.selection()
            if sel:
                item = sel[0]
                name = self.tree.item(item, 'values')[0]
                if name.startswith("Boot") and len(name) == 8:
                    data, _ = read_uefi_var(name, EFI_GLOBAL_GUID)
                    if data:
                        hex_path = extract_file_path_hex(data)
                        if hex_path:
                            path_entry.delete(0, tk.END)
                            path_entry.insert(0, hex_path)
                            return
            messagebox.showwarning("No suitable entry", "Select a BootXXXX entry in the main list to copy its path.")
        ttk.Button(dialog, text="Copy path from selected entry", command=paste_from_selected).grid(row=3, column=0, columnspan=2, pady=5)

        def on_create():
            desc = desc_entry.get().strip()
            if not desc:
                messagebox.showwarning("Empty description", "Please enter a description.")
                return
            hex_path = path_entry.get().strip().replace(" ", "").replace("\t", "")
            if not hex_path:
                messagebox.showwarning("Empty path", "Please enter a hex path.")
                return
            try:
                bytes.fromhex(hex_path)
            except ValueError:
                messagebox.showerror("Error", "Invalid hex format (only hex digits allowed).")
                return

            success, result = create_boot_entry(desc, hex_path)
            if success:
                boot_name = result[0]
                self.set_status(f"Entry {boot_name} created.")
                if messagebox.askyesno("Add to BootOrder", f"Add {boot_name} to boot order (at the end)?"):
                    ok, err = add_to_boot_order(boot_name)
                    if ok:
                        self.set_status(f"{boot_name} added to BootOrder.")
                    else:
                        self.set_status(f"Failed to add to BootOrder: {err}", True)
                dialog.destroy()
                self.refresh()
            else:
                messagebox.showerror("Error", f"Failed to create entry: {result}")

        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="Create", command=on_create).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def edit_boot_path(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No selection", "Please select an entry.")
            return
        item = selected[0]
        name = self.tree.item(item, 'values')[0]
        if not (name.startswith("Boot") and len(name) == 8 and name[4:].isalnum()):
            messagebox.showerror("Invalid entry", "Only BootXXXX entries can be edited.")
            return

        data, err = read_uefi_var(name, EFI_GLOBAL_GUID)
        if data is None:
            messagebox.showerror("Error", f"Failed to read {name}: {err}")
            return
        current_hex_path = extract_file_path_hex(data)
        if current_hex_path is None:
            messagebox.showerror("Error", "Could not extract path from entry.")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Edit Path for {name}")
        dialog.geometry("700x320")
        dialog.configure(bg='#2d2d2d')

        ttk.Label(dialog, text="Current path (hex):").grid(row=0, column=0, padx=5, pady=5, sticky="ne")
        path_display = tk.Text(dialog, height=3, width=80, bg='#3a3a3a', fg='white', wrap=tk.NONE)
        path_display.grid(row=0, column=1, padx=5, pady=5)
        path_display.insert(tk.END, current_hex_path)
        path_display.config(state=tk.DISABLED)

        ttk.Label(dialog, text="New path (hex):").grid(row=1, column=0, padx=5, pady=5, sticky="ne")
        new_path_entry = ttk.Entry(dialog, width=80)
        new_path_entry.grid(row=1, column=1, padx=5, pady=5)
        new_path_entry.insert(0, current_hex_path)

        def pick_file_and_encode_edit():
            file_path = filedialog.askopenfilename(title="Select EFI file")
            if not file_path:
                return
            rel = get_relative_efi_path(file_path)
            if rel:
                hex_path = path_to_utf16le_hex(rel)
                new_path_entry.delete(0, tk.END)
                new_path_entry.insert(0, hex_path)
                messagebox.showinfo("Success", f"Relative path {rel} converted to HEX.")
            else:
                hex_path = path_to_utf16le_hex(file_path)
                new_path_entry.delete(0, tk.END)
                new_path_entry.insert(0, hex_path)
                messagebox.showwarning("Attention",
                                       "File not on EFI partition. Full path encoded, but a full Device Path is required for boot.")
        ttk.Button(dialog, text="Select file and encode path", command=pick_file_and_encode_edit).grid(row=2, column=0, columnspan=2, pady=5)

        def on_update():
            new_hex = new_path_entry.get().strip().replace(" ", "").replace("\t", "")
            if not new_hex:
                messagebox.showwarning("Empty path", "Please enter a hex path.")
                return
            try:
                bytes.fromhex(new_hex)
            except ValueError:
                messagebox.showerror("Error", "Invalid hex format.")
                return
            success, err = update_boot_path(name, new_hex)
            if success:
                self.set_status(f"Path for {name} updated.")
                dialog.destroy()
                self.refresh()
            else:
                messagebox.showerror("Error", f"Failed to update path: {err}")

        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="Update", command=on_update).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

def main():
    if not enable_system_environment_privilege():
        root = tk.Tk()
        root.title("Error")
        tk.Label(root, text="Failed to enable SeSystemEnvironmentPrivilege.", fg="red").pack(padx=20, pady=20)
        root.mainloop()
        return

    root = tk.Tk()
    app = NVRAMApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
