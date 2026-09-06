import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import ctypes
from ctypes import wintypes
import sys
import os
import struct
import binascii
import subprocess
import shutil
import string

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
    EFI_GLOBAL_GUID = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"

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
            if err not in (2, 0):
                variables.append((name, "", f"<Ошибка {err}>", ""))
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
    EFI_GLOBAL_GUID = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
    success, err = write_uefi_var(name, EFI_GLOBAL_GUID, None)
    return success, err

def update_boot_order(order_list):
    EFI_GLOBAL_GUID = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
    data = bytearray()
    for name in order_list:
        num = int(name[4:8], 16)
        data.extend(struct.pack('<H', num))
    success, err = write_uefi_var("BootOrder", EFI_GLOBAL_GUID, bytes(data))
    return success, err

def update_boot_description(name, new_description):
    EFI_GLOBAL_GUID = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
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
            return False, "Папка EFI не найдена после монтирования."
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
        return "Нет свободных букв для монтирования EFI-раздела."

    ok, err = mount_efi_partition(drive_letter)
    if not ok:
        return f"Не удалось смонтировать EFI-раздел: {err}"

    esp_root = f"{drive_letter}:"
    try:
        if not os.path.exists(f"{esp_root}\\EFI"):
            return f"После монтирования не найдена папка {esp_root}\\EFI."

        bootmgfw_src = get_embedded_file_path('bootmgfw.efi')
        bootx64_src = get_embedded_file_path('bootx64.efi')
        if not bootmgfw_src:
            return "Файл bootmgfw.efi не найден во встроенных ресурсах EXE."
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
            return f"Ошибка замены bootmgfw.efi: {err1}"

        dst2 = os.path.join(dest_boot, 'bootx64.efi')
        ok2, err2 = safe_replace(bootx64_src, dst2)
        if not ok2:
            return f"Ошибка замены bootx64.efi: {err2}"

        EFI_GLOBAL_GUID = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
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
            return (f"Файлы заменены на встроенные на диске {esp_root}.\n"
                    "Запись Windows Boot Manager найдена. Рекомендуется перезагрузить компьютер.")

        windows_drive = os.environ.get('SystemDrive', 'C:')
        cmd = f'bcdboot {windows_drive}\\Windows /s {esp_root} /f UEFI'
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return f"Файлы заменены, запись создана с помощью bcdboot."
            else:
                manual = (
                    f"Файлы bootmgfw.efi и bootx64.efi успешно заменены.\n"
                    f"Не удалось автоматически создать загрузочную запись.\n"
                    f"Для завершения восстановления выполните вручную:\n"
                    f"   bcdboot {windows_drive}\\Windows /s {esp_root} /f UEFI"
                )
                return manual
        except Exception as e:
            return f"Ошибка при выполнении bcdboot: {e}\n\nФайлы заменены, но запись не создана."

    finally:
        unmount_efi_partition(drive_letter)

class NVRAMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NVRAM Manager (UEFI)")
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
        self.tree.heading("name", text="Имя")
        self.tree.heading("hex_value", text="Значение (hex)")
        self.tree.heading("description", text="Описание")
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

        ttk.Button(control_frame, text="Обновить список", command=self.refresh).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Удалить выбранные", command=self.delete_selected_entries).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Редактировать описание", command=self.edit_description_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Изменить порядок загрузки", command=self.edit_boot_order).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Восстановить загрузчик", command=self.restore_boot).pack(side=tk.LEFT, padx=5)

        self.status = ttk.Label(root, text="Готово", relief=tk.SUNKEN, anchor=tk.W)
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
        self.set_status(f"Загружено переменных: {len(vars_list)}")

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
        menu = tk.Menu(self.root, tearoff=0, bg='#3a3a3a', fg='white')
        menu.add_command(label="Удалить выбранные записи", command=self.delete_selected_entries)
        menu.add_command(label="Редактировать описание", command=self.edit_description_selected)
        menu.add_separator()
        menu.add_command(label="Изменить порядок загрузки", command=self.edit_boot_order)
        menu.add_command(label="Обновить список", command=self.refresh)
        menu.post(event.x_root, event.y_root)

    def delete_selected_entries(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Нет выбора", "Выберите хотя бы одну запись.")
            return
        names = []
        for item in selected:
            name = self.tree.item(item, 'values')[0]
            if name.startswith("Boot") and len(name) == 8 and name[4:].isalnum():
                names.append(name)
        if not names:
            messagebox.showwarning("Нет загрузочных записей", "Среди выбранных нет BootXXXX.")
            return
        if not messagebox.askyesno("Подтверждение", f"Удалить {len(names)} записей?"):
            return
        errors = []
        for name in names:
            success, err = delete_boot_entry(name)
            if not success:
                errors.append(f"{name}: {err}")
        if errors:
            self.set_status(f"Ошибки: {', '.join(errors)}", True)
            messagebox.showerror("Ошибки", "Не все записи удалены:\n" + "\n".join(errors))
        else:
            self.set_status(f"Удалено {len(names)} записей")
            messagebox.showinfo("Успех", f"Удалено {len(names)} записей.")
        self.refresh()

    def edit_description_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Нет выбора", "Выберите запись.")
            return
        item = selected[0]
        name = self.tree.item(item, 'values')[0]
        if not (name.startswith("Boot") and len(name) == 8 and name[4:].isalnum()):
            messagebox.showerror("Неверная запись", "Можно редактировать только BootXXXX.")
            return
        current_desc = self.tree.item(item, 'values')[2]
        new_desc = simpledialog.askstring("Редактирование описания",
                                          f"Новое описание для {name}:",
                                          initialvalue=current_desc)
        if new_desc is None:
            return
        if not new_desc.strip():
            messagebox.showwarning("Пустое описание", "Описание не может быть пустым.")
            return
        success, err = update_boot_description(name, new_desc.strip())
        if success:
            self.set_status(f"Описание {name} обновлено.")
            self.refresh()
        else:
            self.set_status(f"Ошибка: {err}", True)
            messagebox.showerror("Ошибка", f"Не удалось обновить описание. Код: {err}")

    def edit_boot_order(self):
        EFI_GLOBAL_GUID = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
        data, err = read_uefi_var("BootOrder", EFI_GLOBAL_GUID)
        if data is None:
            messagebox.showerror("Ошибка", "Не удалось прочитать BootOrder.")
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
        order_window.title("Порядок загрузки")
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

        ttk.Button(btn_frame, text="↑ Вверх", command=move_up).pack(pady=5)
        ttk.Button(btn_frame, text="↓ Вниз", command=move_down).pack(pady=5)

        def apply_order():
            new_order = listbox.get(0, tk.END)
            if not new_order:
                messagebox.showwarning("Пустой порядок", "Список не должен быть пустым.")
                return
            success, err = update_boot_order(new_order)
            if success:
                messagebox.showinfo("Успех", "Порядок загрузки обновлён.")
                order_window.destroy()
                self.refresh()
            else:
                messagebox.showerror("Ошибка", f"Не удалось обновить BootOrder. Код: {err}")

        ttk.Button(order_window, text="Применить", command=apply_order).pack(pady=10)

    def restore_boot(self):
        if not messagebox.askyesno("Подтверждение",
                                   "Заменить bootmgfw.efi и bootx64.efi на встроенные?"):
            return
        self.set_status("Восстановление...")
        self.root.update()
        result = restore_boot_files()
        if "успешно" in result.lower() or "заменены" in result.lower():
            self.set_status(result)
            messagebox.showinfo("Результат", result)
            self.refresh()
        else:
            self.set_status(result, True)
            messagebox.showwarning("Внимание", result)

def main():
    if not enable_system_environment_privilege():
        root = tk.Tk()
        root.title("Ошибка")
        tk.Label(root, text="Не удалось включить привилегию SeSystemEnvironmentPrivilege.", fg="red").pack(padx=20, pady=20)
        root.mainloop()
        return

    root = tk.Tk()
    app = NVRAMApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()