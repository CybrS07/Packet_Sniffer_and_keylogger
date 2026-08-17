"""
Network Packet Sniffer — Tkinter GUI
Imports all parsing from back_NetSniffer.py (original code untouched).

Run:  sudo python3 net_sniffer_gui.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
import time

from back_NetSniffer import (
    eth_frame, ipv4_packet, ipv4, icmp_packet, tcp_packet, udp_packet,
    format_multi_line, get_mac_addr,
    TAB_1, TAB_2, TAB_3, DATA_TAB_3,
)

PROTO_COLORS = {
    'TCP': '#22c55e', 'UDP': '#3b82f6', 'ICMP': '#f59e0b',
    'HTTP': '#a855f7', 'HTTPS': '#ec4899', 'DNS': '#06b6d4', 'OTHER': '#94a3b8',
}


class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("1050x650")
        self.root.configure(bg='#0f1219')
        self.root.minsize(800, 500)

        self.capturing = False
        self.filter = 'ALL'
        self.packets_data = []

        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.build_ui()

    def build_ui(self):
        # ── Header ──
        header = tk.Frame(self.root, bg='#131720', height=50)
        header.pack(fill='x')
        header.pack_propagate(False)

        tk.Label(header, text="Packet Sniffer", font=("Arial", 14, "bold"),
                 bg='#131720', fg='#e6edf3').pack(side='left', padx=15)

        self.live_label = tk.Label(header, text="● LIVE", font=("Arial", 9),
                                   bg='#131720', fg='#22c55e')

        self.count_label = tk.Label(header, text="0 packets", font=("Consolas", 10),
                                    bg='#131720', fg='#64748b')
        self.count_label.pack(side='right', padx=15)

        btn_frame = tk.Frame(header, bg='#131720')
        btn_frame.pack(side='right', padx=5)

        self.btn_capture = tk.Button(btn_frame, text="▶ Capture", font=("Arial", 10, "bold"),
                                     bg='#22c55e', fg='#0f1219', relief='flat',
                                     padx=16, pady=4, cursor='hand2',
                                     command=self.toggle_capture)
        self.btn_capture.pack(side='left', padx=3)

        tk.Button(btn_frame, text="Clear", font=("Arial", 10),
                  bg='#1e2533', fg='#8892a4', relief='flat',
                  padx=12, pady=4, cursor='hand2',
                  command=self.clear_all).pack(side='left', padx=3)

        tk.Frame(self.root, bg='#1e2533', height=1).pack(fill='x')

        # ── Packet Table (must be created BEFORE filters call set_filter) ──
        tk.Frame(self.root, bg='#1e2533', height=1).pack(fill='x')

        pane = tk.PanedWindow(self.root, orient='vertical', bg='#0f1219',
                               sashwidth=3, sashrelief='flat')
        pane.pack(fill='both', expand=True)

        table_frame = tk.Frame(pane, bg='#0f1219')
        pane.add(table_frame, stretch='always')

        cols = ('time', 'proto', 'source', 'destination', 'sport', 'dport', 'size', 'info')
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings', selectmode='browse')

        widths = {'time': 65, 'proto': 60, 'source': 130, 'destination': 130,
                  'sport': 65, 'dport': 65, 'size': 55, 'info': 350}
        labels = {'time': 'Time', 'proto': 'Proto', 'source': 'Source',
                  'destination': 'Destination', 'sport': 'SPort', 'dport': 'DPort',
                  'size': 'Size', 'info': 'Info'}
        for c in cols:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], minwidth=40)

        self.style.configure('Treeview', background='#0f1219', foreground='#c9d1d9',
                              fieldbackground='#0f1219', rowheight=24, font=('Consolas', 10))
        self.style.configure('Treeview.Heading', background='#111621', foreground='#586069',
                              font=('Arial', 9, 'bold'))
        self.style.map('Treeview', background=[('selected', '#1a2332')],
                        foreground=[('selected', '#e6edf3')])

        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self.on_select)

        for proto, color in PROTO_COLORS.items():
            self.tree.tag_configure(proto, foreground=color)

        # Detail panel
        detail_frame = tk.Frame(pane, bg='#111621')
        pane.add(detail_frame, stretch='never')

        self.detail_text = scrolledtext.ScrolledText(
            detail_frame, bg='#111621', fg='#c9d1d9',
            font=('Consolas', 10), relief='flat', wrap='word',
            insertbackground='#c9d1d9', padx=12, pady=10, height=10)
        self.detail_text.pack(fill='both', expand=True)
        self.detail_text.configure(state='disabled')

        self.detail_text.tag_configure('header', foreground='#e6edf3', font=('Consolas', 10, 'bold'))
        for proto, color in PROTO_COLORS.items():
            self.detail_text.tag_configure('proto_{}'.format(proto), foreground=color, font=('Consolas', 10, 'bold'))

        # ── Now build filter bar and insert it above the pane ──
        # (We create it after tree exists, then repack in correct order)
        pane.pack_forget()

        fbar = tk.Frame(self.root, bg='#111621', height=36)
        fbar.pack(fill='x')
        fbar.pack_propagate(False)

        self.filter_btns = {}
        for proto in ['ALL', 'TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS']:
            btn = tk.Button(fbar, text=proto, font=("Arial", 8, "bold"),
                            bg='#1a2030', fg='#64748b', relief='flat',
                            padx=10, pady=2, cursor='hand2',
                            command=lambda p=proto: self.set_filter(p))
            btn.pack(side='left', padx=2, pady=5)
            self.filter_btns[proto] = btn

        tk.Frame(self.root, bg='#1e2533', height=1).pack(fill='x')
        pane.pack(fill='both', expand=True)

        # Safe to call now — self.tree exists
        self.set_filter('ALL')

    # ── Filter ──

    def set_filter(self, proto):
        self.filter = proto
        for p, btn in self.filter_btns.items():
            if p == proto:
                btn.configure(bg=PROTO_COLORS.get(p, '#e6edf3'), fg='#0f1219')
            else:
                btn.configure(bg='#1a2030', fg='#64748b')
        self.refresh_tree()

    def refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        for pkt in self.packets_data:
            if self.filter == 'ALL' or pkt['proto'] == self.filter:
                self.insert_row(pkt)

    # ── Capture ──

    def toggle_capture(self):
        if self.capturing:
            self.capturing = False
            self.btn_capture.configure(text="▶ Capture", bg='#22c55e')
            self.live_label.pack_forget()
        else:
            self.capturing = True
            self.btn_capture.configure(text="■ Stop", bg='#dc2626')
            self.live_label.pack(side='left', padx=5)
            threading.Thread(target=self.capture_loop, daemon=True).start()

    def capture_loop(self):
        try:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except (OSError, AttributeError) as e:
            self.root.after(0, lambda: self.show_msg(
                "ERROR: {}\n\nRequires Linux + root.\nRun:  sudo python3 net_sniffer_gui.py".format(e)))
            self.root.after(0, self.toggle_capture)
            return

        conn.settimeout(0.5)
        while self.capturing:
            try:
                raw_data, addr = conn.recvfrom(65536)
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                pkt = self.parse_packet(raw_data)
                self.root.after(0, self.add_packet, pkt)
            except Exception:
                pass
        conn.close()

    def parse_packet(self, raw_data):
        """Use the original back_NetSniffer functions to parse."""
        dest_mac, src_mac, eth_proto, data = eth_frame(raw_data)
        ts = "{:.3f}".format(time.time() % 60)

        pkt = {
            'time': ts, 'src_mac': src_mac, 'dst_mac': dest_mac,
            'eth_proto': eth_proto, 'proto': 'OTHER',
            'src': '', 'dst': '', 'sport': '', 'dport': '',
            'size': len(raw_data), 'info': '', 'detail': '',
        }

        detail = 'Ethernet Frame:\n'
        detail += TAB_1 + 'Destination: {}, Source: {}, Protocol: {}\n'.format(dest_mac, src_mac, eth_proto)

        if eth_proto != 8:
            pkt['info'] = 'Non-IPv4 (EtherType: {})'.format(eth_proto)
            pkt['detail'] = detail + TAB_1 + 'Non-IPv4 Packet'
            return pkt

        version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
        pkt['src'] = src
        pkt['dst'] = target

        detail += TAB_1 + 'IPv4 Packet:\n'
        detail += TAB_2 + 'Version: {}, Header Length: {}, TTL: {}\n'.format(version, header_length, ttl)
        detail += TAB_2 + 'Protocol: {}, Source: {}, Target: {}\n'.format(proto, src, target)

        # ICMP
        if proto == 1:
            icmp_type, code, checksum, payload = icmp_packet(data)
            icmp_names = {0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request',
                          11: 'Time Exceeded', 5: 'Redirect'}
            type_name = icmp_names.get(icmp_type, 'Type {}'.format(icmp_type))
            pkt['proto'] = 'ICMP'
            pkt['info'] = '{} ({} → {})'.format(type_name, src, target)
            detail += TAB_1 + 'ICMP Packet:\n'
            detail += TAB_2 + 'Type: {} ({}), Code: {}, Checksum: {}\n'.format(icmp_type, type_name, code, checksum)
            detail += TAB_2 + 'Source: {}, Destination: {}\n'.format(src, target)
            detail += TAB_2 + 'Data:\n' + format_multi_line(DATA_TAB_3, payload) + '\n'

        # TCP
        elif proto == 6:
            src_port, dest_port, sequence, ack, flags, payload = tcp_packet(data)
            pkt['sport'] = src_port
            pkt['dport'] = dest_port
            flag_str = ' '.join(k for k, v in flags.items() if v)

            detail += TAB_1 + 'TCP Segment:\n'
            detail += TAB_2 + 'Source Port: {}, Destination Port: {}\n'.format(src_port, dest_port)
            detail += TAB_2 + 'Sequence: {}, Acknowledgment: {}\n'.format(sequence, ack)
            detail += TAB_2 + 'Flags:\n'
            detail += TAB_3 + 'URG: {}, ACK: {}, PSH: {}\n'.format(flags['URG'], flags['ACK'], flags['PSH'])
            detail += TAB_3 + 'RST: {}, SYN: {}, FIN: {}\n'.format(flags['RST'], flags['SYN'], flags['FIN'])

            if src_port == 80 or dest_port == 80:
                pkt['proto'] = 'HTTP'
                try:
                    http = payload.decode('utf-8', errors='replace')
                    pkt['info'] = http.split('\r\n')[0][:100]
                    detail += TAB_2 + 'HTTP Data:\n'
                    for line in http.split('\r\n'):
                        if line:
                            detail += DATA_TAB_3 + line + '\n'
                except Exception:
                    pkt['info'] = 'HTTP [{}]'.format(flag_str)
                    detail += TAB_2 + 'Data:\n' + format_multi_line(DATA_TAB_3, payload) + '\n'

            elif src_port == 443 or dest_port == 443:
                pkt['proto'] = 'HTTPS'
                detail += TAB_2 + 'HTTPS (Encrypted):\n'
                if len(payload) >= 3:
                    tls_types = {0x16: 'Handshake', 0x17: 'Application Data',
                                 0x14: 'ChangeCipherSpec', 0x15: 'Alert'}
                    content_type = tls_types.get(payload[0], hex(payload[0]))
                    pkt['info'] = 'TLS {}'.format(content_type)
                    detail += DATA_TAB_3 + 'TLS Content Type: {}\n'.format(content_type)
                else:
                    pkt['info'] = 'HTTPS [{}]'.format(flag_str)
                detail += format_multi_line(DATA_TAB_3, payload) + '\n'

            else:
                pkt['proto'] = 'TCP'
                pkt['info'] = '[{}] Seq={} Ack={}'.format(flag_str, sequence, ack)
                detail += TAB_2 + 'Data:\n' + format_multi_line(DATA_TAB_3, payload) + '\n'

        # UDP
        elif proto == 17:
            src_port, dest_port, length, payload = udp_packet(data)
            pkt['sport'] = src_port
            pkt['dport'] = dest_port

            detail += TAB_1 + 'UDP Segment:\n'
            detail += TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}\n'.format(src_port, dest_port, length)

            if src_port == 53 or dest_port == 53:
                pkt['proto'] = 'DNS'
                pkt['info'] = 'DNS Response' if src_port == 53 else 'DNS Query'
                detail += TAB_2 + 'DNS Data:\n' + format_multi_line(DATA_TAB_3, payload) + '\n'
            else:
                pkt['proto'] = 'UDP'
                pkt['info'] = 'Len={}'.format(length)
                detail += TAB_2 + 'Data:\n' + format_multi_line(DATA_TAB_3, payload) + '\n'

        else:
            pkt['info'] = 'IP Protocol {}'.format(proto)
            detail += TAB_1 + 'Other IPv4 Protocol: {}\n'.format(proto)
            detail += TAB_2 + 'Data:\n' + format_multi_line(DATA_TAB_3, data) + '\n'

        pkt['detail'] = detail
        return pkt

    # ── UI updates ──

    def add_packet(self, pkt):
        self.packets_data.append(pkt)
        if len(self.packets_data) > 500:
            self.packets_data = self.packets_data[-500:]
            self.refresh_tree()
            return
        self.count_label.configure(text="{} packets".format(len(self.packets_data)))
        if self.filter == 'ALL' or pkt['proto'] == self.filter:
            self.insert_row(pkt)
            self.tree.yview_moveto(1.0)

    def insert_row(self, pkt):
        self.tree.insert('', 'end', values=(
            pkt['time'], pkt['proto'], pkt['src'], pkt['dst'],
            pkt['sport'], pkt['dport'], pkt['size'], pkt['info']
        ), tags=(pkt['proto'],))

    def on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0])['values']
        for pkt in reversed(self.packets_data):
            if str(pkt['time']) == str(vals[0]) and pkt['proto'] == vals[1]:
                self.show_detail(pkt)
                break

    def show_detail(self, pkt):
        self.detail_text.configure(state='normal')
        self.detail_text.delete('1.0', 'end')
        self.detail_text.insert('end', '  [{}] '.format(pkt['proto']), 'proto_{}'.format(pkt['proto']))
        self.detail_text.insert('end', 'Packet — {} bytes\n\n'.format(pkt['size']), 'header')
        self.detail_text.insert('end', pkt['detail'])
        self.detail_text.configure(state='disabled')

    def show_msg(self, msg):
        self.detail_text.configure(state='normal')
        self.detail_text.delete('1.0', 'end')
        self.detail_text.insert('end', msg)
        self.detail_text.configure(state='disabled')

    def clear_all(self):
        self.packets_data.clear()
        self.tree.delete(*self.tree.get_children())
        self.count_label.configure(text="0 packets")
        self.detail_text.configure(state='normal')
        self.detail_text.delete('1.0', 'end')
        self.detail_text.configure(state='disabled')


if __name__ == '__main__':
    root = tk.Tk()
    SnifferApp(root)
    root.mainloop()