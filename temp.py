import tkinter as tk
from tkinter import ttk, Menu, Toplevel, filedialog, messagebox
from ttkbootstrap import Style
import socket
import json
import threading
from ipaddress import ip_network
import csv
import pandas as pd
import webbrowser
import subprocess
import os

class MinerScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Miner Scanner App")
        self.style = Style(theme="darkly")

        self.menu_bar = Menu(self.root)
        self.file_menu = Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Экспорт в CSV", command=self.export_to_csv)
        self.file_menu.add_command(label="Экспорт в XLSX", command=self.export_to_xlsx)
        self.menu_bar.add_cascade(label="Файл", menu=self.file_menu)

        self.location_menu = Menu(self.menu_bar, tearoff=0)
        self.location_menu.add_command(label="Добавить локацию", command=self.add_location)
        self.menu_bar.add_cascade(label="Локация", menu=self.location_menu)

        self.settings_menu = Menu(self.menu_bar, tearoff=0)
        self.settings_menu.add_command(label="Настройки", command=self.open_settings)
        self.menu_bar.add_cascade(label="Настройки", menu=self.settings_menu)

        self.theme_menu = Menu(self.menu_bar, tearoff=0)
        self.theme_menu.add_command(label="Светлая", command=lambda: self.change_theme("flatly"))
        self.theme_menu.add_command(label="Темная", command=lambda: self.change_theme("darkly"))
        self.menu_bar.add_cascade(label="Тема", menu=self.theme_menu)

        self.info_menu = Menu(self.menu_bar, tearoff=0)
        self.info_menu.add_command(label="Информация", command=self.show_info)
        self.menu_bar.add_cascade(label="Информация", menu=self.info_menu)

        self.root.config(menu=self.menu_bar)

        self.site_frame = tk.Frame(self.root)
        self.site_frame.pack(side="left", padx=10, pady=10, fill="y")

        self.selected_location_label = tk.Label(self.site_frame, text="Локация: ")
        self.selected_location_label.pack(pady=5)

        self.add_site_label = tk.Label(self.site_frame, text="+ Добавить контейнер", fg="blue", cursor="hand2")
        self.add_site_label.pack(pady=5)
        self.add_site_label.bind("<Button-1>", lambda e: self.open_add_site_window())

        self.site_listbox = tk.Listbox(self.site_frame, selectmode=tk.MULTIPLE)
        self.site_listbox.pack(pady=5, fill="y", expand=True)
        self.site_listbox.bind("<Double-1>", self.open_site_window)

        self.search_entry = tk.Entry(self.site_frame)
        self.search_entry.insert(0, 'Поиск')
        self.search_entry.pack(pady=5)
        self.search_entry.bind("<KeyRelease>", self.search_tree)

        self.scan_button = tk.Button(self.site_frame, text="Scan", command=self.scan_selected_sites)
        self.scan_button.pack(side="bottom", pady=10)

        columns = ("IP", "Type", "GHS av", "GHS 5s", "total_freqavg", "miner_version", "Pool", "User", "Elapsed")
        self.tree_frame = tk.Frame(self.root)
        self.tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.tree_scroll_y = tk.Scrollbar(self.tree_frame, orient="vertical")
        self.tree_scroll_y.pack(side="right", fill="y")

        self.tree_scroll_x = tk.Scrollbar(self.tree_frame, orient="horizontal")
        self.tree_scroll_x.pack(side="bottom", fill="x")

        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings", style="Treeview",
                                 yscrollcommand=self.tree_scroll_y.set, xscrollcommand=self.tree_scroll_x.set)
        self.tree.pack(fill="both", expand=True)

        self.tree_scroll_y.config(command=self.tree.yview)
        self.tree_scroll_x.config(command=self.tree.xview)

        for col in columns:
            self.tree.heading(col, text=col, command=lambda _col=col: self.sort_by(_col, False))
            self.tree.column(col, width=100)

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Control-c>", self.copy_selection)
        self.tree.bind("<Button-3>", self.show_context_menu)

        self.scanned_data = {}
        self.scanned_data_lock = threading.Lock()

        self.locations = {}
        self.current_location = None
        self.sites = {}
        self.load_data()

        self.status_label = tk.Label(self.root, text="В сети: 0")
        self.status_label.pack(side="bottom", fill="x")

        self.update_scan_count()

    def change_theme(self, theme_name):
        self.style.theme_use(theme_name)

    def add_location(self):
        self.add_location_window = Toplevel(self.root)
        self.add_location_window.title("Добавить локацию")
        self.add_location_window.geometry("300x100")

        tk.Label(self.add_location_window, text="Название локации:").pack(pady=5)
        self.location_name_entry = tk.Entry(self.add_location_window)
        self.location_name_entry.pack(pady=5)

        self.save_location_button = tk.Button(self.add_location_window, text="Сохранить", command=self.save_location)
        self.save_location_button.pack(pady=10)

    def save_location(self):
        location_name = self.location_name_entry.get()
        if location_name:
            self.locations[location_name] = []
            self.update_location_menu()
            self.add_location_window.destroy()
            self.save_data()

    def update_location_menu(self):
        self.location_menu.delete(2, tk.END)
        for location in self.locations:
            submenu = Menu(self.location_menu, tearoff=0)
            submenu.add_command(label="Редактировать", command=lambda loc=location: self.edit_location(loc))
            submenu.add_command(label="Удалить", command=lambda loc=location: self.delete_location(loc))
            self.location_menu.add_cascade(label=location, menu=submenu)
            self.location_menu.entryconfig(location, command=lambda loc=location: self.select_location(loc))

    def select_location(self, location_name):
        self.current_location = location_name
        self.selected_location_label.config(text=f"Локация: {location_name}")
        self.update_site_list()

    def update_site_list(self):
        self.site_listbox.delete(0, tk.END)
        if self.current_location and self.current_location in self.locations:
            for site in self.locations[self.current_location]:
                self.site_listbox.insert(tk.END, site)
                threading.Thread(target=self.ping_mikrotik, args=(self.sites[site]['mikrotik_ip'], site)).start()

    def edit_location(self, location_name):
        self.edit_location_window = Toplevel(self.root)
        self.edit_location_window.title("Редактировать локацию")
        self.edit_location_window.geometry("300x100")

        tk.Label(self.edit_location_window, text="Название локации:").pack(pady=5)
        self.location_name_entry = tk.Entry(self.edit_location_window)
        self.location_name_entry.insert(0, location_name)
        self.location_name_entry.pack(pady=5)

        self.save_location_button = tk.Button(self.edit_location_window, text="Сохранить", command=lambda loc=location_name: self.save_edited_location(loc))
        self.save_location_button.pack(pady=10)

    def save_edited_location(self, old_location_name):
        new_location_name = self.location_name_entry.get()
        if new_location_name and old_location_name in self.locations:
            self.locations[new_location_name] = self.locations.pop(old_location_name)
            if self.current_location == old_location_name:
                self.current_location = new_location_name
            self.update_location_menu()
            self.update_site_list()
            self.edit_location_window.destroy()
            self.save_data()

    def delete_location(self, location_name):
        if messagebox.askyesno("Удалить локацию", f"Точно хотите удалить локацию {location_name}?"):
            if location_name in self.locations:
                del self.locations[location_name]
                if self.current_location == location_name:
                    self.current_location = None
                    self.selected_location_label.config(text="Локация: ")
                self.update_location_menu()
                self.update_site_list()
                self.save_data()

    def open_add_site_window(self):
        self.add_site_window = Toplevel(self.root)
        self.add_site_window.title("Добавить контейнер")
        self.add_site_window.geometry("300x400")

        tk.Label(self.add_site_window, text="Название:").pack(pady=5)
        self.site_name_entry = tk.Entry(self.add_site_window)
        self.site_name_entry.pack(pady=5)

        self.ip_range_frame = tk.Frame(self.add_site_window)
        self.ip_range_frame.pack(pady=5)

        self.add_ip_range_button = tk.Button(self.add_site_window, text="+ Добавить диапазон ip", command=self.add_ip_range_field)
        self.add_ip_range_button.pack(pady=5)

        tk.Label(self.add_site_window, text="IP Микротика:").pack(pady=5)
        self.mikrotik_ip_entry = tk.Entry(self.add_site_window)
        self.mikrotik_ip_entry.pack(pady=5)

        tk.Label(self.add_site_window, text="Локация:").pack(pady=5)
        self.location_var = tk.StringVar()
        self.location_var.set(self.current_location if self.current_location else "Добавить локацию")
        self.location_option_menu = ttk.Combobox(self.add_site_window, textvariable=self.location_var)
        self.location_option_menu['values'] = ["Добавить локацию"] + list(self.locations.keys())
        self.location_option_menu.pack(pady=5)

        self.save_site_button = tk.Button(self.add_site_window, text="Сохранить", command=self.save_site)
        self.save_site_button.pack(pady=10)

    def add_ip_range_field(self):
        ip_range_entry = tk.Entry(self.ip_range_frame)
        ip_range_entry.pack(pady=5)
        self.ip_range_frame.pack()

    def save_site(self):
        site_name = self.site_name_entry.get()
        mikrotik_ip = self.mikrotik_ip_entry.get()
        ip_ranges = [entry.get() for entry in self.ip_range_frame.winfo_children()]
        selected_location = self.location_var.get()

        if selected_location == "Добавить локацию":
            self.add_location()
            return

        if site_name and mikrotik_ip and selected_location in self.locations:
            self.sites[site_name] = {
                "name": site_name,
                "ip_ranges": ip_ranges,
                "mikrotik_ip": mikrotik_ip
            }
            self.locations[selected_location].append(site_name)
            self.update_site_list()
            self.add_site_window.destroy()
            self.save_data()

    def load_data(self):
        try:
            with open("data.json", "r") as file:
                data = json.load(file)
                self.locations = data.get("locations", {})
                self.sites = data.get("sites", {})
        except FileNotFoundError:
            self.locations = {}
            self.sites = {}

    def save_data(self):
        with open("data.json", "w") as file:
            data = {
                "locations": self.locations,
                "sites": self.sites
            }
            json.dump(data, file, indent=4)

    def export_to_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if file_path:
            with open(file_path, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["IP", "Type", "GHS av", "GHS 5s", "total_freqavg", "miner_version", "Pool", "User", "Elapsed"])
                for site, data in self.scanned_data.items():
                    for item in data:
                        writer.writerow(item)

    def export_to_xlsx(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".xlsx",
                                                 filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")])
        if file_path:
            df = pd.DataFrame(columns=["IP", "Type", "GHS av", "GHS 5s", "total_freqavg", "miner_version", "Pool", "User", "Elapsed"])
            for site, data in self.scanned_data.items():
                for item in data:
                    df = df.append(pd.Series(item, index=df.columns), ignore_index=True)
            df.to_excel(file_path, index=False)

    def show_info(self):
        messagebox.showinfo("Информация", "Miner Scanner App v1.0\nРазработано OpenAI GPT-4")

    def open_settings(self):
        webbrowser.open("settings.html")

    def sort_by(self, col, descending):
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children("")]
        data.sort(reverse=descending)
        for idx, item in enumerate(data):
            self.tree.move(item[1], "", idx)
        self.tree.heading(col, command=lambda col=col: self.sort_by(col, not descending))

    def on_double_click(self, event):
        item = self.tree.selection()[0]
        values = self.tree.item(item, "values")
        ip_address = values[0]
        self.open_terminal(ip_address)

    def open_terminal(self, ip_address):
        subprocess.run(["gnome-terminal", "--", "ping", ip_address])

    def copy_selection(self, event):
        selection = self.tree.selection()
        text = ""
        for item in selection:
            values = self.tree.item(item, "values")
            text += "\t".join(values) + "\n"
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def show_context_menu(self, event):
        self.context_menu = Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Сменить пулы", command=self.open_change_pools_window)
        self.context_menu.add_command(label="Перезагрузить", command=self.reboot_device)
        
        mode_menu = Menu(self.context_menu, tearoff=0)
        mode_menu.add_command(label="Low", command=lambda: self.set_mode("Low"))
        mode_menu.add_command(label="Normal", command=lambda: self.set_mode("Normal"))
        mode_menu.add_command(label="High performance", command=lambda: self.set_mode("High performance"))
        self.context_menu.add_cascade(label="Режим работы", menu=mode_menu)

        self.context_menu.add_command(label="Отправить в сон", command=self.put_to_sleep)
        self.context_menu.add_command(label="Обновить", command=self.refresh_data)
        self.context_menu.add_command(label="Подсветить", command=self.toggle_light)

        self.context_menu.post(event.x_root, event.y_root)

    def open_change_pools_window(self):
        pass

    def reboot_device(self):
        pass

    def set_mode(self, mode):
        pass

    def put_to_sleep(self):
        pass

    def refresh_data(self):
        pass

    def toggle_light(self):
        pass

    def search_tree(self, event):
        search_text = self.search_entry.get()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for site, data in self.scanned_data.items():
            for item in data:
                if search_text.lower() in " ".join(item).lower():
                    self.tree.insert("", "end", values=item)

    def scan_selected_sites(self):
        selected_sites = self.site_listbox.curselection()
        for i in selected_sites:
            site_name = self.site_listbox.get(i)
            threading.Thread(target=self.scan_site, args=(site_name,)).start()

    def scan_site(self, site_name):
        # Ваш код для сканирования сайта
        pass

    def ping_mikrotik(self, ip, site_name):
        # Ваш код для пинга Микротика
        pass

    def update_scan_count(self):
        self.status_label.config(text=f"В сети: {len(self.scanned_data)}")
        self.root.after(10000, self.update_scan_count)


if __name__ == "__main__":
    root = tk.Tk()
    app = MinerScannerApp(root)
    root.mainloop()
