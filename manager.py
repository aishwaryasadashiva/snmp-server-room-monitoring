#!/usr/bin/env python3
# =============================================================================
# manager.py  —  SNMP Manager GUI  for  SERVER-MONITOR-MIB
#
# Shows every SNMP request sent and every response received in a structured
# Communication Log — matching what the Agent's Exchange Monitor displays.
#
# Different-network support:
#   python3 manager.py --agent-ip 192.168.193.10   # ZeroTier IP
#   python3 manager.py --agent-ip <any reachable IP>
# =============================================================================

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import socket, threading, queue, time, argparse
from datetime import datetime

# ── CLI args ──────────────────────────────────────────────────────────────────
_ap = argparse.ArgumentParser(description='SNMP Manager GUI')
_ap.add_argument('--agent-ip',   default=None)
_ap.add_argument('--agent-port', type=int, default=None)
_ap.add_argument('--trap-port',  type=int, default=None)
_args = _ap.parse_args()

import config as _cfg
if _args.agent_ip:   _cfg.AGENT_HOST         = _args.agent_ip
if _args.agent_port: _cfg.AGENT_PORT          = _args.agent_port
if _args.trap_port:  _cfg.MANAGER_TRAP_PORT   = _args.trap_port

from config import (
    AGENT_HOST, AGENT_PORT,
    MANAGER_BIND_HOST, MANAGER_TRAP_PORT,
    COMMUNITY_READ,
    OID_TEMPERATURE, OID_HUMIDITY, OID_AC_STATUS, OID_FAN_STATUS, OID_ALERT_STATUS,
    OID_SNMP_TRAP_OID,
    ALL_SCALAR_OIDS, ENTERPRISE_OID, OID_NAMES, SOCKET_BUFFER_SIZE,
    TEMP_ALERT_THRESHOLD, HUMIDITY_ALERT_THRESHOLD,
    TEMP_FAN_ON_THRESHOLD, TEMP_AC_ON_THRESHOLD,
)
from snmp_core import (
    Tag, ErrorStatus,
    encode_integer, encode_null,
    build_get_request, build_get_next_request,
    build_get_bulk_request, build_set_request,
    parse_message, DecodeError, oid_is_prefix,
)
import config as _live

# ── Colour palette ────────────────────────────────────────────────────────────
C = {
    'bg'      : '#1e1e2e', 'panel'  : '#2a2a3e', 'card'   : '#313145',
    'entry'   : '#3d3d55', 'accent' : '#7c6fe0', 'teal'   : '#5bbbac',
    'green'   : '#4caf7d', 'warn'   : '#e0a030', 'red'    : '#e05555',
    'text'    : '#e0e0f0', 'dim'    : '#9090b0', 'border' : '#44445a',
    'btn'     : '#5b5b80', 'btnhov' : '#6d6d99', 'logbg'  : '#0a0a18',
    'req_col' : '#6be5b0',   # outgoing request   (green)
    'resp_col': '#7ab8f5',   # incoming response  (blue)
    'trap_col': '#f5a623',   # trap received      (amber)
    'err_col' : '#f55555',
    'sys_col' : '#9090b0',
    'hdr_mgr' : '#2a1a4a',  # manager header (dark purple)
}


# =============================================================================
# MIB WALK POPUP
# =============================================================================
_MIB_TREE = [
    # (indent, label, oid, obj_name, type_str, description)
    (0, '● iso (1)',                             '1',                       'iso',              'OID',       'ISO root'),
    (1, '├─ org (1.3)',                           '1.3',                    'org',              'OID',       'ISO org'),
    (2, '├─ dod (1.3.6)',                         '1.3.6',                  'dod',              'OID',       'US Dept of Defense'),
    (3, '├─ internet (1.3.6.1)',                  '1.3.6.1',                'internet',         'OID',       'Internet root'),
    (4, '├─ private (1.3.6.1.4)',                 '1.3.6.1.4',              'private',          'OID',       'Private'),
    (5, '├─ enterprises (1.3.6.1.4.1)',           '1.3.6.1.4.1',            'enterprises',      'OID',       'Enterprise MIBs'),
    (6, '▼ serverMonitor (1.3.6.1.4.1.9999)',     '1.3.6.1.4.1.9999',       'serverMonitor',    'OID',       '★ YOUR MIB ROOT'),
    (7, '├─ serverMonitorObjects (1–5)',           '1.3.6.1.4.1.9999.1-5',   'objects',          'OID',       'Scalar objects group'),
    (8, '├─ temperature (1.3.6.1.4.1.9999.1.0)',  OID_TEMPERATURE,           'temperature',      'Integer32', f'Room temp °C  (API, alert≥{TEMP_ALERT_THRESHOLD}°C)'),
    (8, '├─ humidity (1.3.6.1.4.1.9999.2.0)',     OID_HUMIDITY,              'humidity',         'Integer32', f'Humidity %  (API, alert≥{HUMIDITY_ALERT_THRESHOLD}%)'),
    (8, '├─ acStatus (1.3.6.1.4.1.9999.3.0)',     OID_AC_STATUS,             'acStatus',         'Integer32', f'AC unit  (1=ON when temp≥{TEMP_AC_ON_THRESHOLD}°C)'),
    (8, '├─ fanStatus (1.3.6.1.4.1.9999.4.0)',    OID_FAN_STATUS,            'fanStatus',        'Integer32', f'Fan  (1=ON when temp≥{TEMP_FAN_ON_THRESHOLD}°C)'),
    (8, '└─ alertStatus (1.3.6.1.4.1.9999.5.0)',  OID_ALERT_STATUS,          'alertStatus',      'Integer32', 'Alert  (1=ALERT, 0=NORMAL)'),
    (7, '└─ serverMonitorTraps (.0)',              '1.3.6.1.4.1.9999.0',      'traps',            'OID',       'Trap subtree'),
    (8, '├─ temperatureAlertTrap (.0.1)',          '1.3.6.1.4.1.9999.0.1',    'tempAlertTrap',    'TRAP',      f'Fires when temp ≥ {TEMP_ALERT_THRESHOLD}°C'),
    (8, '├─ humidityAlertTrap (.0.2)',             '1.3.6.1.4.1.9999.0.2',    'humAlertTrap',     'TRAP',      f'Fires when humidity ≥ {HUMIDITY_ALERT_THRESHOLD}%'),
    (8, '└─ normalStatusTrap (.0.3)',              '1.3.6.1.4.1.9999.0.3',    'normalTrap',       'TRAP',      'Fires when alert condition clears'),
]

class MibWalkWindow:
    def __init__(self, parent, varbinds):
        self.top = tk.Toplevel(parent)
        self.top.title("MIB Walk — Full OID Tree  |  SERVER-MONITOR-MIB")
        self.top.geometry("1100x680")
        self.top.configure(bg='#0f1117')
        self.vals = {oid: val for oid, val, _ in varbinds}
        self._build()

    def _fmt_val(self, oid, val):
        if oid == OID_TEMPERATURE:
            return f"{val} °C", ('alert' if val >= TEMP_ALERT_THRESHOLD
                                 else 'warning' if val >= TEMP_FAN_ON_THRESHOLD
                                 else 'normal')
        if oid == OID_HUMIDITY:
            return (f"{val} %",
                    'alert' if val >= HUMIDITY_ALERT_THRESHOLD else 'normal')
        if oid == OID_AC_STATUS:
            return ('● ON', 'on') if val else ('○ OFF', 'normal')
        if oid == OID_FAN_STATUS:
            return ('● ON', 'on') if val else ('○ OFF', 'normal')
        if oid == OID_ALERT_STATUS:
            return ('△ ALERT', 'alert') if val else ('✓ NORMAL', 'normal')
        return str(val), 'normal'

    def _build(self):
        hdr = tk.Frame(self.top, bg='#3a2f7a', height=50)
        hdr.pack(fill='x'); hdr.pack_propagate(False)
        tk.Label(hdr, text="MIB Walk — Full OID Tree  |  SERVER-MONITOR-MIB",
                 bg='#3a2f7a', fg='white', font=('Consolas',13,'bold')).pack(side='left', padx=16)

        stat_row = tk.Frame(self.top, bg='#16192a', height=30)
        stat_row.pack(fill='x'); stat_row.pack_propagate(False)
        n_data = sum(1 for l,_,oid,_,t,_ in _MIB_TREE if t=='Integer32')
        for lbl, val, col in [('Root:', ENTERPRISE_OID, '#aaa0f0'),
                               ('MIB:', 'SERVER-MONITOR-MIB', '#aaa0f0'),
                               ('Objects:', str(n_data), '#aaa0f0'),
                               ('Status:', '✓ Walk complete', '#4caf7d')]:
            tk.Label(stat_row, text=lbl, bg='#16192a', fg='#8080a0',
                     font=('Consolas',9)).pack(side='left', padx=(12,2))
            tk.Label(stat_row, text=val, bg='#16192a', fg=col,
                     font=('Consolas',9,'bold')).pack(side='left', padx=(0,14))

        fr = tk.Frame(self.top, bg='#0f1117'); fr.pack(fill='both', expand=True)
        cols = ('Object','Type','Value','Description')
        style = ttk.Style()
        style.configure('Walk.Treeview',
            background='#1a1d2e', foreground='#c0c0d8',
            fieldbackground='#1a1d2e', font=('Consolas',10), rowheight=26)
        style.configure('Walk.Treeview.Heading',
            background='#4a3f8a', foreground='#d0c8ff',
            font=('Consolas',10,'bold'), relief='flat')
        style.map('Walk.Treeview', background=[('selected','#4a3f8a')])

        tv = ttk.Treeview(fr, columns=cols, show='tree headings',
                          selectmode='browse', style='Walk.Treeview')
        tv.heading('#0',          text='OID Tree',      anchor='w')
        tv.heading('Object',      text='Object',        anchor='center')
        tv.heading('Type',        text='Type',          anchor='center')
        tv.heading('Value',       text='Value',         anchor='center')
        tv.heading('Description', text='Description',   anchor='w')
        tv.column('#0',          width=400, anchor='w')
        tv.column('Object',      width=130, anchor='center')
        tv.column('Type',        width=80,  anchor='center')
        tv.column('Value',       width=90,  anchor='center')
        tv.column('Description', width=370, anchor='w')

        tv.tag_configure('path',    background='#141620', foreground='#8888aa')
        tv.tag_configure('normal',  background='#1a1d2e', foreground='#c0c0d8')
        tv.tag_configure('alert',   background='#3a1010', foreground='#ffaaaa')
        tv.tag_configure('warning', background='#3a2a00', foreground='#ffd080')
        tv.tag_configure('on',      background='#0a2a10', foreground='#90ffb8')
        tv.tag_configure('trap',    background='#141620', foreground='#888880')
        tv.tag_configure('root',    background='#1f1540', foreground='#c0a8ff')

        parent_stack = {-1: ''}
        counts = {'alert':0,'on':0,'warning':0,'normal':0}
        for level, label, oid, obj_name, type_str, desc in _MIB_TREE:
            parent_iid = parent_stack.get(level-1, '')
            val_str = '—'; tag = 'path'
            if type_str == 'Integer32' and oid in self.vals:
                val_str, tag = self._fmt_val(oid, self.vals[oid])
                counts[tag] = counts.get(tag,0) + 1
            elif type_str == 'TRAP':   tag = 'trap'
            elif 'serverMonitor' in label and '9999' in label: tag = 'root'

            iid = tv.insert(parent_iid, 'end', text=label,
                            values=(obj_name, type_str, val_str, desc),
                            tags=(tag,), open=True)
            parent_stack[level] = iid

        vsb = ttk.Scrollbar(fr, orient='vertical',   command=tv.yview)
        hsb = ttk.Scrollbar(fr, orient='horizontal', command=tv.xview)
        tv.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side='right', fill='y'); hsb.pack(side='bottom', fill='x')
        tv.pack(fill='both', expand=True)

        foot = tk.Frame(self.top, bg='#16192a', height=36)
        foot.pack(fill='x', side='bottom'); foot.pack_propagate(False)
        for sym, cnt, lbl, col in [('■',counts.get('alert',0),'alert','#e05555'),
                                    ('■',counts.get('on',0),'ON','#4caf7d'),
                                    ('■',counts.get('warning',0),'warning','#e0a030'),
                                    ('■',counts.get('normal',0),'normal','#8888aa')]:
            tk.Label(foot, text=f"{sym} {cnt} {lbl}", bg='#16192a', fg=col,
                     font=('Consolas',9)).pack(side='left', padx=12)
        ttk.Button(foot, text='Close',  command=self.top.destroy).pack(side='right', padx=8,  pady=4)


# =============================================================================
# SNMP WORKER THREAD
# =============================================================================
class SnmpWorker(threading.Thread):
    TIMEOUT = 3.0

    def __init__(self, result_cb, commlog_cb, walk_cb):
        super().__init__(daemon=True, name='SnmpWorker')
        self._q         = queue.Queue()
        self._result    = result_cb
        self._commlog   = commlog_cb   # posts structured comm events
        self._walk_done = walk_cb
        self._running   = True

    def stop(self): self._running=False; self._q.put(None)
    def submit(self, task_type, **kw): self._q.put({'type':task_type,**kw})

    def run(self):
        while self._running:
            task = self._q.get()
            if task is None: break
            try: self._dispatch(task)
            except Exception as e: self._commlog(('err', str(e)))

    def _dispatch(self, t):
        tp = t['type']
        if   tp=='get':     self._do_get(t)
        elif tp=='getnext': self._do_getnext(t)
        elif tp=='getbulk': self._do_getbulk(t)
        elif tp=='walk':    self._do_walk(t)
        elif tp=='set':     self._do_set(t)
        elif tp=='test':    self._do_test(t)

    def _udp(self, raw, host, port, req_id):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.TIMEOUT)
        try:
            s.sendto(raw, (host, port))
            deadline = time.time() + self.TIMEOUT
            while True:
                rem = deadline - time.time()
                if rem <= 0:
                    raise TimeoutError(
                        f"No response from {host}:{port} after {self.TIMEOUT}s\n"
                        f"  Check: agent running? IP correct? Firewall OK?")
                s.settimeout(rem)
                try: resp_raw, _ = s.recvfrom(SOCKET_BUFFER_SIZE)
                except socket.timeout:
                    raise TimeoutError(f"No response from {host}:{port}")
                try: resp = parse_message(resp_raw)
                except DecodeError: continue
                if resp['request_id'] == req_id: return resp
        finally: s.close()

    # ── GET ───────────────────────────────────────────────────────────────────
    def _do_get(self, t):
        h,p,c,v = t['host'],t['port'],t['community'],t.get('version',1)
        oids = t['oids']
        ts = datetime.now().strftime('%H:%M:%S.%f')[:12]
        raw, rid = build_get_request(c, oids, version=v)
        self._commlog(('req_sent', ts, 'GetRequest', c, rid, v, h, p, oids))
        try:
            resp = self._udp(raw, h, p, rid)
            ts2  = datetime.now().strftime('%H:%M:%S.%f')[:12]
            self._commlog(('resp_recv', ts2, resp))
            self._result(resp['varbinds'], Tag.GET_RESPONSE)
        except TimeoutError as e: self._commlog(('err', str(e)))
        except DecodeError  as e: self._commlog(('err', str(e)))

    # ── GETNEXT ───────────────────────────────────────────────────────────────
    def _do_getnext(self, t):
        h,p,c,v = t['host'],t['port'],t['community'],t.get('version',1)
        oids = t['oids']
        ts = datetime.now().strftime('%H:%M:%S.%f')[:12]
        raw, rid = build_get_next_request(c, oids, version=v)
        self._commlog(('req_sent', ts, 'GetNextRequest', c, rid, v, h, p, oids))
        try:
            resp = self._udp(raw, h, p, rid)
            ts2  = datetime.now().strftime('%H:%M:%S.%f')[:12]
            self._commlog(('resp_recv', ts2, resp))
            self._result(resp['varbinds'], Tag.GET_RESPONSE)
        except TimeoutError as e: self._commlog(('err', str(e)))
        except DecodeError  as e: self._commlog(('err', str(e)))

    # ── GETBULK ───────────────────────────────────────────────────────────────
    def _do_getbulk(self, t):
        h,p,c = t['host'],t['port'],t['community']
        nr,mr = t.get('non_repeaters',0), t.get('max_repetitions',10)
        oids  = t['oids']
        ts = datetime.now().strftime('%H:%M:%S.%f')[:12]
        raw, rid = build_get_bulk_request(c, oids, nr, mr)
        self._commlog(('req_sent', ts, f'GetBulkRequest(non_rep={nr},max_rep={mr})',
                       c, rid, 1, h, p, oids))
        try:
            resp = self._udp(raw, h, p, rid)
            ts2  = datetime.now().strftime('%H:%M:%S.%f')[:12]
            self._commlog(('resp_recv', ts2, resp))
            self._result(resp['varbinds'], Tag.GET_RESPONSE)
        except TimeoutError as e: self._commlog(('err', str(e)))
        except DecodeError  as e: self._commlog(('err', str(e)))

    # ── WALK ──────────────────────────────────────────────────────────────────
    def _do_walk(self, t):
        h,p,c   = t['host'],t['port'],t['community']
        start   = t.get('start_oid', ENTERPRISE_OID)
        base    = t.get('base_oid',  ENTERPRISE_OID)
        current = start
        all_binds = []; steps = 0

        self._commlog(('walk_start', start))

        while steps < 50:
            steps += 1
            ts = datetime.now().strftime('%H:%M:%S.%f')[:12]
            raw, rid = build_get_next_request(c, [current], version=1)
            self._commlog(('walk_step', ts, current, rid))
            try: resp = self._udp(raw, h, p, rid)
            except TimeoutError as e:
                self._commlog(('err', f"TIMEOUT in walk step {steps}: {e}"))
                break

            if resp.get('error_status',0) != 0:
                self._commlog(('walk_end', f"error_status={resp['error_status']}", len(all_binds)))
                break
            if not resp['varbinds']:
                self._commlog(('walk_end', 'empty response', len(all_binds))); break

            oid, val, tname = resp['varbinds'][0]
            if tname == 'Exception' or val in ('endOfMibView','noSuchObject','noSuchInstance'):
                self._commlog(('walk_end', 'endOfMibView', len(all_binds))); break
            if not oid_is_prefix(base, oid):
                self._commlog(('walk_end', f'OID {oid} outside base', len(all_binds))); break
            if oid == current:
                self._commlog(('walk_end', 'OID did not advance', len(all_binds))); break

            self._commlog(('walk_row', oid, OID_NAMES.get(oid,oid), val, tname))
            all_binds.append((oid, val, tname)); current = oid

        if all_binds:
            self._result(all_binds, Tag.GET_RESPONSE)
        self._walk_done(all_binds)

    # ── SET ───────────────────────────────────────────────────────────────────
    def _do_set(self, t):
        h,p,c = t['host'],t['port'],t['community']
        ts = datetime.now().strftime('%H:%M:%S.%f')[:12]
        raw, rid = build_set_request(c, t['varbinds'])
        self._commlog(('req_sent', ts, 'SetRequest', c, rid, 0, h, p,
                       [o for o,_ in t['varbinds']]))
        try:
            resp = self._udp(raw, h, p, rid)
            ts2  = datetime.now().strftime('%H:%M:%S.%f')[:12]
            self._commlog(('resp_recv', ts2, resp))
            self._result(resp['varbinds'], Tag.GET_RESPONSE)
        except TimeoutError as e: self._commlog(('err', str(e)))

    # ── TEST ──────────────────────────────────────────────────────────────────
    def _do_test(self, t):
        h,p,c = t['host'],t['port'],t['community']
        self._commlog(('sys', f"Testing connection to {h}:{p} …"))
        raw, rid = build_get_request(c, [OID_TEMPERATURE], version=1)
        try:
            resp = self._udp(raw, h, p, rid)
            val = resp['varbinds'][0][1] if resp['varbinds'] else '?'
            self._commlog(('sys', f"  CONNECTION OK — temperature={val}°C  ({h}:{p} reachable)"))
            self._result(resp['varbinds'], Tag.GET_RESPONSE)
        except TimeoutError as e:
            self._commlog(('err', f"  CONNECTION FAILED:\n  {e}"))


# =============================================================================
# TRAP RECEIVER
# =============================================================================
class TrapReceiver(threading.Thread):
    def __init__(self, trap_q, commlog_cb):
        super().__init__(daemon=True, name='TrapReceiver')
        self._q = trap_q; self._cb = commlog_cb
        self._running=True; self.sock=None

    def stop(self):
        self._running=False
        try:
            if self.sock: self.sock.close()
        except: pass

    def run(self):
        try:
            self.sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
            self.sock.bind((MANAGER_BIND_HOST, MANAGER_TRAP_PORT))
            self._cb(('sys', f"Trap receiver: {MANAGER_BIND_HOST}:{MANAGER_TRAP_PORT}"))
        except OSError as e:
            self._cb(('err', f"Cannot bind trap port {MANAGER_TRAP_PORT}: {e}")); return
        while self._running:
            try:
                self.sock.settimeout(1.0)
                raw,addr = self.sock.recvfrom(SOCKET_BUFFER_SIZE)
                self._handle(raw, addr)
            except socket.timeout: continue
            except OSError: break

    def _handle(self, raw, addr):
        try: msg = parse_message(raw)
        except DecodeError as e:
            self._cb(('err', f"Bad trap from {addr}: {e}")); return
        pdu = msg.get('pdu_type',0)
        if pdu not in (Tag.TRAP_V2C, Tag.TRAP_V1, Tag.INFORM_REQUEST): return
        ts = datetime.now().strftime('%H:%M:%S.%f')[:12]
        vbs = msg.get('varbinds',[])
        trap_oid='?'; trap_name='Unknown'; data={}
        for oid, val, _ in vbs:
            if oid == OID_SNMP_TRAP_OID:
                trap_oid  = str(val)
                trap_name = OID_NAMES.get(trap_oid, trap_oid)
            elif oid == OID_TEMPERATURE:  data['temperature']  = f"{val}°C"
            elif oid == OID_HUMIDITY:     data['humidity']     = f"{val}%"
            elif oid == OID_ALERT_STATUS: data['alertStatus']  = 'ALERT' if val else 'NORMAL'
        self._q.put({'ts':ts,'from':f"{addr[0]}:{addr[1]}",'trap_name':trap_name,
                     'trap_oid':trap_oid,'data':data,'varbinds':vbs,'pdu':msg['pdu_type_name']})
        self._cb(('trap_recv', ts, addr[0], trap_name, trap_oid, data))


# =============================================================================
# MAIN GUI
# =============================================================================
class SnmpManagerApp:
    MIB_DISPLAY = [
        (OID_TEMPERATURE, 'temperature',  '...9999.1.0', '°C',   None,    None),
        (OID_HUMIDITY,    'humidity',     '...9999.2.0', '%',    None,    None),
        (OID_AC_STATUS,   'acStatus',     '...9999.3.0', '',     'ON',    'OFF'),
        (OID_FAN_STATUS,  'fanStatus',    '...9999.4.0', '',     'ON',    'OFF'),
        (OID_ALERT_STATUS,'alertStatus',  '...9999.5.0', '',     'ALERT', 'NORMAL'),
    ]

    def __init__(self, root):
        self.root      = root
        self.trap_q    = queue.Queue()
        self.gui_q     = queue.Queue()
        self._poll_job = None
        self._trap_data= []
        self._stats    = {'sent':0,'received':0,'traps':0}

        self._setup_styles()
        self._build_ui()
        self._start_threads()
        self._schedule_drain()
        self._var_autopoll.set(True)
        self._var_interval.set(30)
        self.root.after(900, self._start_autopoll)

    def _start_autopoll(self):
        if self._var_autopoll.get():
            self._commlog_post(('sys', "Auto-poll ON (30s) — values update automatically."))
            self._schedule_poll()

    # ── Styles ────────────────────────────────────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style(); s.theme_use('clam')
        s.configure('TFrame',            background=C['bg'])
        s.configure('TLabel',            background=C['bg'],    foreground=C['text'], font=('Consolas',10))
        s.configure('TEntry',            fieldbackground=C['entry'], foreground=C['text'], font=('Consolas',10), borderwidth=1, relief='flat')
        s.configure('TButton',           background=C['btn'],   foreground=C['text'],  font=('Consolas',10), borderwidth=0, focusthickness=0)
        s.map('TButton', background=[('active',C['btnhov']),('pressed',C['accent'])])
        s.configure('Accent.TButton',    background=C['accent'],foreground='white', font=('Consolas',10,'bold'))
        s.map('Accent.TButton', background=[('active','#9080f0'),('pressed','#6050c0')])
        s.configure('OK.TButton',        background='#2d7a2d',  foreground='white', font=('Consolas',10,'bold'))
        s.map('OK.TButton', background=[('active','#3a9e3a')])
        s.configure('Treeview',          background=C['card'],  foreground=C['text'], fieldbackground=C['card'], font=('Consolas',10), rowheight=28)
        s.configure('Treeview.Heading',  background=C['panel'], foreground=C['accent'], font=('Consolas',10,'bold'), relief='flat')
        s.map('Treeview', background=[('selected',C['accent'])])
        s.configure('TLabelframe',       background=C['panel'], foreground=C['accent'], borderwidth=1)
        s.configure('TLabelframe.Label', background=C['panel'], foreground=C['accent'], font=('Consolas',10,'bold'))

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        root=self.root
        root.title("SERVER-MONITOR-MIB  |  SNMP Manager")
        root.geometry("1300x920")
        root.configure(bg=C['bg']); root.minsize(1050,700)

        hdr = tk.Frame(root, bg=C['hdr_mgr'], height=50)
        hdr.pack(fill='x'); hdr.pack_propagate(False)
        tk.Label(hdr, text="⬡  SERVER-MONITOR-MIB  |  SNMP Network Manager",
                 bg=C['hdr_mgr'], fg='white', font=('Consolas',14,'bold')).pack(side='left', padx=16, pady=8)
        self._hdr_lbl = tk.Label(hdr, text="● Connecting…", bg=C['hdr_mgr'],
                                  fg='#ffd0d0', font=('Consolas',10))
        self._hdr_lbl.pack(side='right', padx=16)

        body = tk.PanedWindow(root, orient='horizontal', bg=C['bg'], sashwidth=5, sashrelief='flat')
        body.pack(fill='both', expand=True)
        left=tk.Frame(body,bg=C['panel'],width=300); left.pack_propagate(False)
        body.add(left,minsize=275)
        right=tk.Frame(body,bg=C['bg']); body.add(right,minsize=700)
        self._build_left(left); self._build_right(right)

    # ── Left panel ────────────────────────────────────────────────────────────
    def _build_left(self, P):
        pad=dict(padx=10,pady=4)

        cf=ttk.LabelFrame(P,text='  Connection',padding=10); cf.pack(fill='x',**pad)
        def row(fr,lbl,default,width=14):
            r=tk.Frame(fr,bg=C['panel']); r.pack(fill='x',pady=2)
            tk.Label(r,text=f"{lbl}:",bg=C['panel'],fg=C['dim'],font=('Consolas',9),width=10,anchor='w').pack(side='left')
            v=tk.StringVar(value=default)
            ttk.Entry(r,textvariable=v,width=width).pack(side='left',expand=True,fill='x')
            return v
        self._v_host  = row(cf,'Agent IP',  AGENT_HOST,  14)
        self._v_port  = row(cf,'Port',      str(AGENT_PORT), 6)
        self._v_comm  = row(cf,'Community', COMMUNITY_READ, 10)
        vr=tk.Frame(cf,bg=C['panel']); vr.pack(fill='x',pady=2)
        tk.Label(vr,text="Version:",bg=C['panel'],fg=C['dim'],font=('Consolas',9),width=10,anchor='w').pack(side='left')
        self._v_ver=tk.StringVar(value='v2c')
        for vn in ('v1','v2c'):
            tk.Radiobutton(vr,text=vn,variable=self._v_ver,value=vn,
                           bg=C['panel'],fg=C['text'],selectcolor=C['accent'],
                           activebackground=C['panel'],font=('Consolas',9)).pack(side='left',padx=4)
        ttk.Button(cf,text='Test Connection',command=self._op_test,style='OK.TButton').pack(fill='x',pady=(6,2))

        tk.Frame(P,bg=C['border'],height=1).pack(fill='x',padx=10,pady=6)

        ops=ttk.LabelFrame(P,text='  SNMP Operations',padding=10); ops.pack(fill='x',padx=10,pady=4)
        def btn(text,cmd,style='TButton'):
            ttk.Button(ops,text=text,command=cmd,style=style).pack(fill='x',pady=3)
        btn('  GetRequest  (all 5 OIDs)',self._op_get_all,'Accent.TButton')
        btn('  GetNextRequest  (one step)',self._op_getnext)
        btn('  GetBulkRequest  (bulk)',   self._op_getbulk)
        btn('  MIB Walk  (popup tree)',   self._op_walk)
        tk.Frame(ops,bg=C['panel'],height=1).pack(pady=4)
        tk.Label(ops,text='Target OID (GetNext / Bulk / Walk):',bg=C['panel'],fg=C['dim'],font=('Consolas',8)).pack(anchor='w')
        self._v_oid=tk.StringVar(value=ENTERPRISE_OID)
        ttk.Entry(ops,textvariable=self._v_oid,width=28,font=('Consolas',9)).pack(fill='x',pady=2)

        tk.Frame(P,bg=C['border'],height=1).pack(fill='x',padx=10,pady=6)

        pf=ttk.LabelFrame(P,text='  Auto-Poll',padding=10); pf.pack(fill='x',padx=10,pady=4)
        self._var_autopoll=tk.BooleanVar(value=False)
        ttk.Checkbutton(pf,text='Enable auto-poll',variable=self._var_autopoll,
                        command=self._toggle_autopoll).pack(anchor='w')
        ir=tk.Frame(pf,bg=C['panel']); ir.pack(fill='x',pady=4)
        tk.Label(ir,text='Every:',bg=C['panel'],fg=C['dim'],font=('Consolas',9)).pack(side='left')
        self._var_interval=tk.IntVar(value=30)
        ttk.Spinbox(ir,from_=5,to=300,increment=5,textvariable=self._var_interval,width=6).pack(side='left',padx=6)
        tk.Label(ir,text='s',bg=C['panel'],fg=C['dim'],font=('Consolas',9)).pack(side='left')
        tk.Label(pf,text='(starts automatically)',bg=C['panel'],fg=C['teal'],font=('Consolas',8)).pack(anchor='w')

        tk.Frame(P,bg=C['border'],height=1).pack(fill='x',padx=10,pady=6)

        sf=ttk.LabelFrame(P,text='  Statistics',padding=10); sf.pack(fill='x',padx=10,pady=4)
        self._slbls={}
        for k,lbl in [('sent','Requests sent'),('received','Responses recv'),('traps','Traps received')]:
            r=tk.Frame(sf,bg=C['panel']); r.pack(fill='x',pady=1)
            tk.Label(r,text=f"{lbl}:",bg=C['panel'],fg=C['dim'],font=('Consolas',9),width=16,anchor='w').pack(side='left')
            lb=tk.Label(r,text='0',bg=C['panel'],fg=C['teal'],font=('Consolas',10,'bold')); lb.pack(side='left')
            self._slbls[k]=lb

        tk.Frame(P,bg=C['border'],height=1).pack(fill='x',padx=10,pady=6)
        ttk.Button(P,text='Clear Comm Log',  command=self._clear_commlog).pack(padx=10,pady=2,fill='x')
        ttk.Button(P,text='Clear Trap Panel',command=lambda: [self._trap_list.delete(0,'end'), self._trap_data.clear()]).pack(padx=10,pady=(0,4),fill='x')

    # ── Right panel ───────────────────────────────────────────────────────────
    def _build_right(self, P):
        top=tk.Frame(P,bg=C['bg']); top.pack(fill='x',padx=6,pady=6)
        self._build_mib_table(top)
        self._build_trap_panel(top)
        self._build_commlog(P)

    def _build_mib_table(self, P):
        fr=ttk.LabelFrame(P,
            text=f'  MIB Objects  (auto-poll 30s | alert≥{TEMP_ALERT_THRESHOLD}°C | hum-alert≥{HUMIDITY_ALERT_THRESHOLD}%)',
            padding=6)
        fr.pack(side='left',fill='both',expand=True,padx=(0,4))
        cols=('Object','OID','Value','Raw')
        tree=ttk.Treeview(fr,columns=cols,show='headings',height=8)
        widths={'Object':110,'OID':195,'Value':115,'Raw':125}
        for c in cols: tree.heading(c,text=c); tree.column(c,width=widths[c],anchor='center')
        tree.tag_configure('normal', background=C['card'],  foreground=C['text'])
        tree.tag_configure('alert',  background='#3a1515',  foreground=C['red'])
        tree.tag_configure('warning',background='#3a2e10',  foreground=C['warn'])
        tree.tag_configure('on',     background='#153a20',  foreground=C['green'])
        self._tree_iids={}
        for oid,nm,short,unit,_,__ in self.MIB_DISPLAY:
            iid=tree.insert('','end',values=(nm,short,'—','—'),tags=('normal',))
            self._tree_iids[oid]=iid
        sb=ttk.Scrollbar(fr,orient='vertical',command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side='left',fill='both',expand=True); sb.pack(side='right',fill='y')
        self._mib_tree=tree

    def _build_trap_panel(self, P):
        fr=ttk.LabelFrame(P,text='  Trap Notifications',padding=6)
        fr.pack(side='right',fill='both',expand=False,ipadx=4); fr.configure(width=300)
        self._trap_list=tk.Listbox(fr,bg=C['logbg'],fg=C['trap_col'],
            font=('Consolas',9),selectmode='browse',relief='flat',
            borderwidth=0,width=34,height=8,highlightthickness=0)
        sb=ttk.Scrollbar(fr,orient='vertical',command=self._trap_list.yview)
        self._trap_list.configure(yscrollcommand=sb.set)
        self._trap_list.pack(side='left',fill='both',expand=True); sb.pack(side='right',fill='y')
        self._trap_detail=tk.StringVar(value='No traps yet')
        tk.Label(fr,textvariable=self._trap_detail,bg=C['panel'],fg=C['dim'],
                 font=('Consolas',8),wraplength=280,justify='left',anchor='w').pack(fill='x',pady=(4,0))
        self._trap_data=[]
        self._trap_list.bind('<<ListboxSelect>>',self._on_trap_select)

    def _build_commlog(self, P):
        """
        Communication Log — the centrepiece of the Manager GUI.
        Shows every outgoing SNMP request AND every incoming response,
        formatted to match what the Agent's Exchange Monitor displays.
        """
        fr=ttk.LabelFrame(P,
            text='  SNMP Communication Log  (Requests ► sent  |  Responses ◄ received  |  Traps ▲ received)',
            padding=4)
        fr.pack(fill='both',expand=True,padx=6,pady=(0,6))
        self._comm_w=scrolledtext.ScrolledText(
            fr, bg=C['logbg'], fg=C['text'],
            font=('Consolas',9), relief='flat', borderwidth=0,
            state='disabled', wrap='word')
        self._comm_w.pack(fill='both',expand=True)
        # colour tags
        self._comm_w.tag_config('req_hdr',  foreground='#ffffff', background='#0a2a1a', font=('Consolas',9,'bold'))
        self._comm_w.tag_config('req_body', foreground=C['req_col'])
        self._comm_w.tag_config('resp_hdr', foreground='#ffffff', background='#1a2a4a', font=('Consolas',9,'bold'))
        self._comm_w.tag_config('resp_body',foreground=C['resp_col'])
        self._comm_w.tag_config('resp_val', foreground='#a0e8d0', font=('Consolas',9,'bold'))
        self._comm_w.tag_config('walk_hdr', foreground='#ffffff', background='#1a1a3a', font=('Consolas',9,'bold'))
        self._comm_w.tag_config('walk_row', foreground='#b0c4de')
        self._comm_w.tag_config('trap_hdr', foreground='#ffffff', background='#3a2a0a', font=('Consolas',9,'bold'))
        self._comm_w.tag_config('trap_val', foreground=C['trap_col'])
        self._comm_w.tag_config('sys',      foreground=C['sys_col'])
        self._comm_w.tag_config('err',      foreground=C['err_col'])
        self._comm_w.tag_config('sep',      foreground='#3a3a5a')

    # ── Operations ────────────────────────────────────────────────────────────
    def _params(self):
        h=self._v_host.get().strip(); p=int(self._v_port.get().strip())
        c=self._v_comm.get().strip(); v=1 if self._v_ver.get()=='v2c' else 0
        return h,p,c,v

    def _op_test(self):
        h,p,c,_=self._params(); self._stats['sent']+=1; self._upd_stats()
        self.worker.submit('test',host=h,port=p,community=c)

    def _op_get_all(self):
        h,p,c,v=self._params(); self._stats['sent']+=1; self._upd_stats()
        self.worker.submit('get',host=h,port=p,community=c,version=v,oids=ALL_SCALAR_OIDS)

    def _op_getnext(self):
        h,p,c,v=self._params(); oid=self._v_oid.get().strip()
        self._stats['sent']+=1; self._upd_stats()
        self.worker.submit('getnext',host=h,port=p,community=c,version=v,oids=[oid])

    def _op_getbulk(self):
        h,p,c,_=self._params(); oid=self._v_oid.get().strip()
        self._stats['sent']+=1; self._upd_stats()
        self.worker.submit('getbulk',host=h,port=p,community=c,oids=[oid],non_repeaters=0,max_repetitions=10)

    def _op_walk(self):
        h,p,c,_=self._params(); oid=self._v_oid.get().strip()
        self._stats['sent']+=1; self._upd_stats()
        self.worker.submit('walk',host=h,port=p,community=c,start_oid=oid,base_oid=ENTERPRISE_OID)

    def _toggle_autopoll(self):
        if self._var_autopoll.get(): self._schedule_poll()
        else:
            if self._poll_job: self.root.after_cancel(self._poll_job); self._poll_job=None

    def _schedule_poll(self):
        self._op_get_all()
        ms=self._var_interval.get()*1000
        self._poll_job=self.root.after(ms,self._schedule_poll)

    # ── Thread setup ──────────────────────────────────────────────────────────
    def _start_threads(self):
        self.worker=SnmpWorker(
            result_cb   =self._on_result,
            commlog_cb  =self._commlog_post,
            walk_cb     =self._on_walk_done,
        )
        self.worker.start()
        self.trap_rx=TrapReceiver(self.trap_q, self._commlog_post)
        self.trap_rx.start()
        self._commlog_post(('sys',
            f"Manager ready\n"
            f"  Agent target   : {AGENT_HOST}:{AGENT_PORT}\n"
            f"  Trap receiver  : {MANAGER_BIND_HOST}:{MANAGER_TRAP_PORT}\n"
            f"  Auto-poll      : ON every 30s\n"
            f"  Enterprise OID : {ENTERPRISE_OID}\n"))

    def _commlog_post(self, ev): self.gui_q.put(('comm', ev))
    def _on_result(self, vbs, ptype): self.gui_q.put(('result', vbs, ptype))
    def _on_walk_done(self, vbs): self.gui_q.put(('walk_popup', vbs))

    def _schedule_drain(self):
        self._drain(); self.root.after(50,self._schedule_drain)

    def _drain(self):
        try:
            while True:
                item=self.gui_q.get_nowait()
                kind=item[0]
                if kind=='comm':
                    self._render_comm(item[1])
                elif kind=='result':
                    self._stats['received']+=1; self._upd_stats()
                    self._update_mib_table(item[1])
                elif kind=='walk_popup':
                    MibWalkWindow(self.root, item[1])
        except queue.Empty: pass
        try:
            while True:
                trap=self.trap_q.get_nowait()
                self._stats['traps']+=1; self._upd_stats()
                self._show_trap(trap)
        except queue.Empty: pass

    # ── Communication Log renderer ────────────────────────────────────────────
    def _render_comm(self, ev):
        if not isinstance(ev, tuple): return
        kind = ev[0]; w = self._comm_w
        w.configure(state='normal')

        if kind=='req_sent':
            _, ts, ptype, comm, rid, ver, host, port, oids = ev
            vname = 'SNMPv2c' if ver==1 else 'SNMPv1'
            w.insert('end',f"\n{'─'*78}\n",'sep')
            w.insert('end',
                f"  ► REQUEST SENT  ──────────────────────────────────────────────────\n",'req_hdr')
            w.insert('end',
                f"  [{ts}]  {ptype}  →  {host}:{port}\n"
                f"  Community: {comm}   Version: {vname}   Request-ID: {rid}\n"
                f"  OIDs requested ({len(oids)}):\n",'req_body')
            for oid in oids:
                name=OID_NAMES.get(oid,oid)
                w.insert('end',f"      •  {name:<15}  {oid}\n",'req_body')

        elif kind=='resp_recv':
            _, ts, resp = ev
            es  = resp['error_status']; esn=resp['error_status_name']
            rid = resp['request_id']; vbs=resp['varbinds']
            w.insert('end',
                f"\n  ◄ RESPONSE RECEIVED  ──────────────────────────────────────────────\n",'resp_hdr')
            w.insert('end',
                f"  [{ts}]  GetResponse  from Agent\n"
                f"  Request-ID: {rid}   Error-Status: {es} ({esn})   VarBinds: {len(vbs)}\n",'resp_body')
            for oid, val, tname in vbs:
                name=OID_NAMES.get(oid,oid)
                unit=self._fmt_unit(oid,val)
                w.insert('end',f"      •  {name:<15}  {oid}\n",'resp_body')
                w.insert('end',f"            Value = {tname}: {val}  ({unit})\n",'resp_val')

        elif kind=='walk_start':
            _,start=ev
            w.insert('end',f"\n{'─'*78}\n",'sep')
            w.insert('end',"  ► MIB WALK STARTED  ─────────────────────────────────────────────\n",'walk_hdr')
            w.insert('end',f"  Starting from: {start}\n",'walk_row')

        elif kind=='walk_step':
            _,ts,oid,rid=ev
            name=OID_NAMES.get(oid,oid)
            w.insert('end',f"  [{ts}]  GetNextRequest({name} / {oid})  id={rid}\n",'walk_row')

        elif kind=='walk_row':
            _,oid,name,val,tname=ev
            unit=self._fmt_unit(oid,val)
            w.insert('end',f"      ✓  {name:<15}  {oid}  =  {tname}:{val}  ({unit})\n",'resp_val')

        elif kind=='walk_end':
            _,reason,count=ev
            w.insert('end',f"  Walk complete — {reason}.  {count} objects retrieved.\n",'walk_row')

        elif kind=='trap_recv':
            _,ts,from_ip,trap_name,trap_oid,data=ev
            w.insert('end',f"\n{'─'*78}\n",'sep')
            w.insert('end',"  ▲ TRAP RECEIVED  ──────────────────────────────────────────────────\n",'trap_hdr')
            w.insert('end',
                f"  [{ts}]  Trap-v2c  from {from_ip}\n"
                f"  Trap type : {trap_name}\n"
                f"  Trap OID  : {trap_oid}\n",'trap_val')
            for k,v in data.items():
                w.insert('end',f"  {k}: {v}\n",'trap_val')

        elif kind=='sys':
            w.insert('end', f"\n{ev[1]}\n", 'sys')

        elif kind=='err':
            w.insert('end', f"\n  ✗ ERROR: {ev[1]}\n", 'err')

        w.configure(state='disabled'); w.see('end')

    @staticmethod
    def _fmt_unit(oid, val):
        if oid==OID_TEMPERATURE: return f"{val} °C"
        if oid==OID_HUMIDITY:    return f"{val} %"
        if oid==OID_AC_STATUS:   return "ON" if val else "OFF"
        if oid==OID_FAN_STATUS:  return "ON" if val else "OFF"
        if oid==OID_ALERT_STATUS:return "ALERT" if val else "NORMAL"
        return str(val)

    # ── MIB table update ──────────────────────────────────────────────────────
    def _update_mib_table(self, varbinds):
        updated=0
        for oid,val,tname in varbinds:
            iid=self._tree_iids.get(oid)
            if iid is None: continue
            tag='normal'
            if oid==OID_TEMPERATURE:
                disp=f"{val} °C"
                if isinstance(val,int) and val>=TEMP_ALERT_THRESHOLD:   tag='alert'
                elif isinstance(val,int) and val>=TEMP_FAN_ON_THRESHOLD: tag='warning'
            elif oid==OID_HUMIDITY:
                disp=f"{val} %"
                if isinstance(val,int) and val>=HUMIDITY_ALERT_THRESHOLD: tag='alert'
            elif oid==OID_AC_STATUS:
                disp='ON' if val else 'OFF'; tag='on' if val else 'normal'
            elif oid==OID_FAN_STATUS:
                disp='ON' if val else 'OFF'; tag='on' if val else 'normal'
            elif oid==OID_ALERT_STATUS:
                disp='⚠ ALERT' if val else '✓ NORMAL'; tag='alert' if val else 'normal'
            else: disp=str(val)
            short=next((s for o,n,s,u,_,__ in self.MIB_DISPLAY if o==oid),oid)
            self._mib_tree.item(iid,values=(OID_NAMES.get(oid,oid),short,disp,f"{tname}:{val}"),tags=(tag,))
            updated+=1
        if updated:
            is_alert=any(self._mib_tree.item(iid,'tags')[0]=='alert' for iid in self._tree_iids.values())
            if is_alert: self._hdr_lbl.config(text="⚠ ALERT CONDITION",fg='#ffdd00')
            else:        self._hdr_lbl.config(text="● Connected",      fg='#90ff90')

    def _show_trap(self, info):
        name=info['trap_name']
        icon=('🌡' if 'temperature' in name.lower() else
              '💧' if 'humidity'    in name.lower() else
              '✓'  if 'normal'      in name.lower() else '▲')
        self._trap_list.insert('end',f"{info['ts']}  {icon}  {name}")
        self._trap_list.see('end'); self._trap_data.append(info)

    def _on_trap_select(self, event):
        sel=self._trap_list.curselection()
        if not sel: return
        info=self._trap_data[sel[0]]
        parts=[f"Trap : {info['trap_name']}",f"OID  : {info['trap_oid']}",f"From : {info['from']}"]
        for k,v in info['data'].items(): parts.append(f"  {k} : {v}")
        self._trap_detail.set('\n'.join(parts))

    def _upd_stats(self):
        for k,lb in self._slbls.items(): lb.configure(text=str(self._stats.get(k,0)))

    def _clear_commlog(self):
        self._comm_w.configure(state='normal'); self._comm_w.delete('1.0','end')
        self._comm_w.configure(state='disabled')

    def on_close(self):
        if self._poll_job: self.root.after_cancel(self._poll_job)
        self.worker.stop(); self.trap_rx.stop(); self.root.destroy()


# =============================================================================
# ENTRY POINT
# =============================================================================
def _agent_dialog():
    root=tk.Tk(); root.withdraw()
    cur=AGENT_HOST
    ip=simpledialog.askstring(
        "Agent IP Address",
        f"IP address of the machine running agent.py\n\n"
        f"  • Same machine      → press OK  (127.0.0.1)\n"
        f"  • Same WiFi network → enter LAN IP  (192.168.x.x)\n"
        f"  • Different network → enter ZeroTier/Tailscale IP\n"
        f"    (see DEPLOYMENT.md for setup instructions)\n\n"
        f"Current: {cur}",
        initialvalue=cur, parent=root)
    root.destroy()
    if ip and ip.strip():
        _live.AGENT_HOST=ip.strip()
        import config; config.AGENT_HOST=ip.strip()

def main():
    _agent_dialog()
    root=tk.Tk()
    app=SnmpManagerApp(root)
    root.protocol("WM_DELETE_WINDOW",app.on_close)
    root.mainloop()

if __name__=='__main__':
    main()
