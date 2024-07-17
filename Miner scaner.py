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

        self.sites = {}
        self.load_sites()

        self.status_label = tk.Label(self.root, text="В сети: 0")
        self.status_label.pack(side="bottom", fill="x")

        self.update_scan_count()

    def change_theme(self, theme_name):
        self.style.theme_use(theme_name)

    def open_add_site_window(self):
        self.add_site_window = Toplevel(self.root)
        self.add_site_window.title("Ребактировать локацию")
        self.add_site_window.geometry("300x400")

        tk.Label(self.add_site_window, text="Название:").pack(pady=5)
        self.site_name_entry = tk.Entry(self.add_site_window)
        self.site_name_entry.pack(pady=5)

        self.ip_range_frame = tk.Frame(self.add_site_window)
        self.ip_range_frame.pack(pady=5)

        self.add_ip_range_button = tk.Button(self.add_site_window, text="+ Добавить диапазон ip", command=self.add_ip_range_field)
        self.add_ip_range_button.pack(pady=5)

        tk.Label(self.add_site_window, text="ip микротика (если есть):").pack(pady=5)
        self.mikrotik_ip_entry = tk.Entry(self.add_site_window)
        self.mikrotik_ip_entry.pack(pady=5)

        self.save_button = tk.Button(self.add_site_window, text="Сохранить", command=self.save_site)
        self.save_button.pack(pady=10)

        self.ip_range_entries = []

    def add_ip_range_field(self):
        frame = tk.Frame(self.ip_range_frame)
        frame.pack(fill="x", pady=2)
        entry = tk.Entry(frame)
        entry.pack(side="left", fill="x", expand=True)
        self.ip_range_entries.append(entry)

    def save_site(self):
        site_name = self.site_name_entry.get()
        ip_ranges = [entry.get() for entry in self.ip_range_entries]
        mikrotik_ip = self.mikrotik_ip_entry.get()

        if site_name and ip_ranges:
            self.sites[site_name] = {"ip_ranges": ip_ranges, "mikrotik_ip": mikrotik_ip}
            self.site_listbox.insert(tk.END, site_name)
            threading.Thread(target=self.ping_mikrotik, args=(mikrotik_ip, site_name)).start()
            self.save_sites()
        self.add_site_window.destroy()

    def ping_mikrotik(self, ip, site_name):
        if ip:
            response = subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            status = "" if response.returncode == 0 else "red"
            self.update_site_status(site_name, status)

    def update_site_status(self, site_name, status):
        index = self.site_listbox.get(0, "end").index(site_name)
        self.site_listbox.itemconfig(index, {'fg': status})

    def scan_selected_sites(self):
        self.clear_tree()
        selected_sites = [self.site_listbox.get(idx) for idx in self.site_listbox.curselection()]

        for site_name in selected_sites:
            ip_ranges = self.sites[site_name]["ip_ranges"]
            for ip_range in ip_ranges:
                try:
                    ips = [str(ip) for ip in ip_network(f"{ip_range}.1/24", strict=False)]
                except ValueError:
                    continue

                for ip in ips:
                    threading.Thread(target=self.scan_miner, args=(ip,)).start()

    def scan_miner(self, ip):
        self.scan_command(ip, "stats")
        self.scan_command(ip, "pools")

    def scan_command(self, ip, command):
        try:
            HOST = ip.strip()
            PORT = 4028

            m = {"command": command}
            jdata = json.dumps(m)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((HOST, PORT))
                s.sendall(bytes(jdata, encoding="utf-8"))
                data = ''
                while True:
                    chunk = s.recv(4026)
                    if not chunk:
                        break
                    data += chunk.decode("utf-8")

                datajs = json.loads(data[:-1])

                if command == "stats":
                    self.update_data(HOST, stats=datajs)
                elif command == "pools":
                    self.update_data(HOST, pools=datajs)

        except Exception:
            pass

    def update_data(self, ip, stats=None, pools=None):
        with self.scanned_data_lock:
            if ip not in self.scanned_data:
                self.scanned_data[ip] = {"stats": None, "pools": None}

            if stats:
                self.scanned_data[ip]["stats"] = stats
            if pools:
                self.scanned_data[ip]["pools"] = pools

            if self.scanned_data[ip]["stats"] and self.scanned_data[ip]["pools"]:
                self.root.after(0, self.update_tree, ip, self.scanned_data[ip])
                del self.scanned_data[ip]

    def update_tree(self, ip, data):
        stats_data = data["stats"].get("STATS", [{}])
        pools_data = data["pools"].get("POOLS", [{}])

        stat = stats_data[0] if len(stats_data) > 0 else {}
        stat_s = stats_data[1] if len(stats_data) > 0 else {}
        pool_one = pools_data[0] if len(pools_data) > 0 else {}
        pool_two = pools_data[1] if len(pools_data) > 0 else {}
        pool_three = pools_data[2] if len(pools_data) > 0 else {}

        values = [
            ip,
            stat.get("Type", ""),
            stat_s.get("GHS av", ""),
            stat_s.get("GHS 5s", ""),
            stat_s.get("total_freqavg", ""),
            stat_s.get("miner_version", ""),
            pool_one.get("URL", ""),
            pool_two.get("User", ""),
            stat_s.get("Elapsed", "")
        ]

        self.tree.insert("", "end", values=values)
        self.update_scan_count()

    def clear_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def sort_by(self, col, descending):
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children()]
        data.sort(reverse=descending)

        for index, item in enumerate(data):
            self.tree.move(item[1], '', index)

        self.tree.heading(col, command=lambda: self.sort_by(col, not descending))

    def on_double_click(self, event):
        item = self.tree.selection()[0]
        ip = self.tree.item(item, "values")[0]
        webbrowser.open(f"http://{ip}")

    def export_to_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow([self.tree.heading(col)["text"] for col in self.tree["columns"]])

                for row_id in self.tree.get_children():
                    row = self.tree.item(row_id)["values"]
                    writer.writerow(row)

    def export_to_xlsx(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")])
        if file_path:
            data = {col: [] for col in self.tree["columns"]}

            for row_id in self.tree.get_children():
                row = self.tree.item(row_id)["values"]
                for col, value in zip(data.keys(), row):
                    data[col].append(value)

            df = pd.DataFrame(data)
            df.to_excel(file_path, index=False)

    def open_settings(self):
        settings_window = Toplevel(self.root)
        settings_window.title("Настройки")
        settings_window.geometry("300x200")
        tk.Label(settings_window, text="Настройки").pack(pady=10)

    def show_info(self):
        info_window = Toplevel(self.root)
        info_window.title("Информация")
        info_window.geometry("300x200")
        tk.Label(info_window, text="Информация о приложении").pack(pady=10)

    def open_site_window(self, event):
        selection = self.site_listbox.curselection()
        if selection:
            index = selection[0]
            site_name = self.site_listbox.get(index)
            self.site_window = Toplevel(self.root)
            self.site_window.title(site_name)
            self.site_window.geometry("300x200")
            tk.Label(self.site_window, text=f"Информация о {site_name}").pack(pady=10)

            site_info = self.sites[site_name]
            tk.Label(self.site_window, text=f"IP Ranges: {', '.join(site_info['ip_ranges'])}").pack(pady=5)
            tk.Label(self.site_window, text=f"Mikrotik IP: {site_info['mikrotik_ip']}").pack(pady=5)

            delete_label = tk.Label(self.site_window, text="Удалить", fg="red", cursor="hand2")
            delete_label.pack(pady=5)
            delete_label.bind("<Button-1>", lambda e, sn=site_name: self.delete_site(sn))

    def delete_site(self, site_name):
        index = self.site_listbox.get(0, "end").index(site_name)
        self.site_listbox.delete(index)
        del self.sites[site_name]
        self.site_window.destroy()
        self.save_sites()

    def save_sites(self):
        with open(os.path.join(os.path.dirname(__file__), "data.json"), "w") as f:
            json.dump(self.sites, f)

    def load_sites(self):
        if os.path.exists(os.path.join(os.path.dirname(__file__), "data.json")):
            with open(os.path.join(os.path.dirname(__file__), "data.json"), "r") as f:
                self.sites = json.load(f)
            for site_name in self.sites:
                self.site_listbox.insert(tk.END, site_name)
                threading.Thread(target=self.ping_mikrotik, args=(self.sites[site_name]['mikrotik_ip'], site_name)).start()

    def select_all_sites(self):
        self.site_listbox.select_set(0, tk.END)

    def search_tree(self, event):
        query = self.search_entry.get().lower()
        for row in self.tree.get_children():
            values = self.tree.item(row)["values"]
            if any(query in str(value).lower() for value in values):
                self.tree.selection_set(row)
                self.tree.see(row)
            else:
                self.tree.selection_remove(row)

    def copy_selection(self, event):
        selection = self.tree.selection()
        if selection:
            selected_text = ""
            for item in selection:
                row = self.tree.item(item)["values"]
                selected_text += "\t".join(str(value) for value in row) + "\n"
            self.root.clipboard_clear()
            self.root.clipboard_append(selected_text)

    def show_context_menu(self, event):
        selection = self.tree.selection()
        if selection:
            context_menu = Menu(self.root, tearoff=0)
            context_menu.add_command(label="Смена пулов", command=self.open_change_pools_window)
            context_menu.post(event.x_root, event.y_root)

   
    def open_change_pools_window(self):
        self.change_pools_window = Toplevel(self.root)
        self.change_pools_window.title("Смена пулов")
        self.change_pools_window.geometry("806x200")

        for i in range(3):
            tk.Label(self.change_pools_window, text=f"Stratum {i + 1}").grid(row=i, column=0, padx=10, pady=5)
            tk.Entry(self.change_pools_window).grid(row=i, column=1, padx=10, pady=5)
            tk.Label(self.change_pools_window, text=f"Worker {i + 1}").grid(row=i, column=2, padx=10, pady=5)
            tk.Entry(self.change_pools_window).grid(row=i, column=3, padx=10, pady=5)
            tk.Label(self.change_pools_window, text=f"Password {i + 1}").grid(row=i, column=4, padx=10, pady=5)
            tk.Entry(self.change_pools_window).grid(row=i, column=5, padx=10, pady=5)
            tk.Checkbutton(self.change_pools_window, text=f"Option {i + 1}").grid(row=i, column=6, padx=10, pady=5)

            tk.Button(self.change_pools_window, text="Применить", command=self.apply_pools).grid(row=4, columnspan=7, padx=10, pady=20)


    def apply_pools(self):
        # Functionality to apply pools will be added here later
        self.change_pools_window.destroy()

        
    def update_scan_count(self):
        count = len(self.tree.get_children())
        self.status_label.config(text=f"В сети: {count}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MinerScannerApp(root)
    root.mainloop()
