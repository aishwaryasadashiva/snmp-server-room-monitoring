#!/usr/bin/env python3
# =============================================================================
# agent.py  —  SNMP Agent GUI  for  SERVER-MONITOR-MIB
#
# Two panels on the right side:
#   TOP  — Live MIB Values table (colour-coded)
#   MID  — SNMP Exchange Monitor (the key panel — shows every request
#           the Manager sends and every response this agent builds & returns,
#           with OID-by-OID value lookup visible in real time)
#   BOT  — Raw Activity Log
#
# Different-network support:
#   python3 agent.py --manager-ip 192.168.193.20   # ZeroTier IP
#   python3 agent.py --manager-ip 10.147.x.x       # any reachable IP
# =============================================================================

import socket, threading, time, math, json, argparse
import urllib.request, urllib.error
import tkinter as tk
from tkinter import ttk, scrolledtext, simpledialog
from datetime import datetime
import queue

# ── CLI args ──────────────────────────────────────────────────────────────────
_ap = argparse.ArgumentParser(description='SNMP Agent GUI')
_ap.add_argument('--simulate',   '-s', action='store_true')
_ap.add_argument('--manager-ip', default=None)
_ap.add_argument('--agent-port', type=int, default=None)
_ap.add_argument('--trap-port',  type=int, default=None)
_args = _ap.parse_args()

import config as _cfg
if _args.manager_ip: _cfg.MANAGER_HOST      = _args.manager_ip
if _args.agent_port: _cfg.AGENT_PORT         = _args.agent_port
if _args.trap_port:  _cfg.MANAGER_TRAP_PORT  = _args.trap_port

from config import (
    AGENT_BIND_HOST, AGENT_PORT, MANAGER_HOST, MANAGER_TRAP_PORT,
    COMMUNITY_READ, COMMUNITY_TRAP,
    OID_TEMPERATURE, OID_HUMIDITY, OID_AC_STATUS, OID_FAN_STATUS, OID_ALERT_STATUS,
    OID_TRAP_TEMP_ALERT, OID_TRAP_HUMIDITY_ALERT, OID_TRAP_NORMAL,
    ALL_SCALAR_OIDS, OID_NAMES, ENTERPRISE_OID,
    TEMP_AC_ON_THRESHOLD, TEMP_FAN_ON_THRESHOLD,
    TEMP_ALERT_THRESHOLD, HUMIDITY_ALERT_THRESHOLD,
    API_POLL_INTERVAL, SOCKET_BUFFER_SIZE, WEATHER_API_URL,
    WEATHER_API_LATITUDE, WEATHER_API_LONGITUDE,
)
from snmp_core import (
    Tag, ErrorStatus, encode_integer, encode_null,
    build_response, build_trap_v2c, parse_message, DecodeError, compare_oids,
)
import config as _live_cfg

# ── Colour palette ────────────────────────────────────────────────────────────
C = {
    'bg'      : '#1e1e2e', 'panel'  : '#2a2a3e', 'card'   : '#313145',
    'entry'   : '#3d3d55', 'accent' : '#7c6fe0', 'teal'   : '#5bbbac',
    'green'   : '#4caf7d', 'warn'   : '#e0a030', 'red'    : '#e05555',
    'text'    : '#e0e0f0', 'dim'    : '#9090b0', 'border' : '#44445a',
    'btn'     : '#5b5b80', 'btnhov' : '#6d6d99', 'logbg'  : '#0a0a18',
    'req_col' : '#7ab8f5',   # incoming request  (blue)
    'lkp_col' : '#b0c4de',   # OID lookup line   (steel blue)
    'resp_col': '#6be5b0',   # outgoing response (green)
    'trap_col': '#f5a623',   # trap sent         (amber)
    'err_col' : '#f55555',   # error             (red)
    'sys_col' : '#9090b0',   # system info       (grey)
    'hdr_ag'  : '#1a4a1a',   # agent window header (dark green)
}


# =============================================================================
# MIB DATA STORE
# =============================================================================
class MibDataStore:
    ORDERED_OIDS = ALL_SCALAR_OIDS

    def __init__(self):
        self._lock  = threading.RLock()
        self._vals  = {
            OID_TEMPERATURE: 22, OID_HUMIDITY: 55,
            OID_AC_STATUS: 0, OID_FAN_STATUS: 0, OID_ALERT_STATUS: 0,
        }
        self._prev_alert = 0
        self._t0 = time.time()

    def get(self, oid):
        with self._lock:
            return self._vals.get(oid)

    def get_next_oid(self, oid):
        with self._lock:
            for c in self.ORDERED_OIDS:
                if compare_oids(c, oid) > 0:
                    return c
            return None

    def get_all(self):
        with self._lock:
            return dict(self._vals)

    def get_uptime_hundredths(self):
        return int((time.time() - self._t0) * 100)

    def uptime_str(self):
        s = int(time.time() - self._t0)
        h, r = divmod(s, 3600); m, s = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def update(self, temp, hum):
        with self._lock:
            self._vals[OID_TEMPERATURE] = int(round(temp))
            self._vals[OID_HUMIDITY]    = int(round(hum))
            self._vals[OID_AC_STATUS]   = 1 if temp >= TEMP_AC_ON_THRESHOLD  else 0
            self._vals[OID_FAN_STATUS]  = 1 if temp >= TEMP_FAN_ON_THRESHOLD else 0
            na, tt = 0, None
            if temp >= TEMP_ALERT_THRESHOLD:
                na, tt = 1, 'temperature'
            elif hum >= HUMIDITY_ALERT_THRESHOLD:
                na, tt = 1, 'humidity'
            changed = (na != self._prev_alert)
            self._prev_alert = na
            self._vals[OID_ALERT_STATUS] = na
            return changed, na, tt


# =============================================================================
# WEATHER FETCHER
# =============================================================================
class WeatherFetcher(threading.Thread):
    def __init__(self, store, trap_cb, update_cb, simulate=False):
        super().__init__(daemon=True, name='WeatherFetcher')
        self.store, self.trap_cb, self.update_cb = store, trap_cb, update_cb
        self.simulate   = simulate
        self._stop      = threading.Event()
        self._n         = 0
        self.last_fetch = None
        self.next_ts    = None

    def stop(self): self._stop.set()

    def run(self):
        while not self._stop.is_set():
            self._n += 1
            temp, hum, src = self._get()
            if temp is not None:
                self.last_fetch = datetime.now().strftime('%H:%M:%S')
                self.next_ts    = time.time() + API_POLL_INTERVAL
                changed, na, tt = self.store.update(temp, hum)
                self.update_cb(temp, hum, src, self._n)
                if changed:
                    self.trap_cb(na, tt, temp, hum)
            self._stop.wait(API_POLL_INTERVAL)

    def secs_to_next(self):
        if self.next_ts is None: return API_POLL_INTERVAL
        return max(0, int(self.next_ts - time.time()))

    def _get(self):
        if not self.simulate:
            t, h = self._api()
            if t is not None: return t, h, 'API'
        t, h = self._sim()
        return t, h, 'SIM'

    def _api(self):
        try:
            req = urllib.request.Request(WEATHER_API_URL,
                  headers={'User-Agent': 'SNMP-Agent/1.0'})
            with urllib.request.urlopen(req, timeout=8) as r:
                d = json.loads(r.read().decode())['current']
                return float(d['temperature_2m']), float(d['relative_humidity_2m'])
        except Exception: return None, None

    def _sim(self):
        t = time.time(); h = (t % 86400)/86400*2*math.pi
        temp = max(15.0, min(50.0, round(30+10*math.sin(h)+2*math.sin(t/47), 1)))
        hum  = max(20.0, min(100.0, round(65-15*math.sin(h)+3*math.cos(t/61), 1)))
        return temp, hum


# =============================================================================
# SNMP RESPONDER  (posts detailed exchange events to the GUI queue)
# =============================================================================
class SnmpResponder(threading.Thread):
    """
    Receives SNMP packets, decodes them, looks up MIB values,
    builds and sends responses.  For every request it posts a
    structured 'exchange' event to the GUI so the Exchange Monitor
    can display exactly what happened.
    """

    def __init__(self, store, trap_cb, gui_q):
        super().__init__(daemon=True, name='SnmpResponder')
        self.store   = store
        self.trap_cb = trap_cb
        self.gui_q   = gui_q
        self.sock    = None
        self._stop   = threading.Event()
        self._stats  = {'get': 0, 'getnext': 0, 'getbulk': 0, 'set': 0}

    def stats(self): return dict(self._stats)

    def stop(self):
        self._stop.set()
        try:
            if self.sock: self.sock.close()
        except: pass

    def bind(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((AGENT_BIND_HOST, AGENT_PORT))

    def run(self):
        while not self._stop.is_set():
            try:
                self.sock.settimeout(1.0)
                raw, addr = self.sock.recvfrom(SOCKET_BUFFER_SIZE)
                self._handle(raw, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    # ── Core handler ──────────────────────────────────────────────────────────

    def _handle(self, raw, addr):
        ts = datetime.now().strftime('%H:%M:%S.%f')[:12]
        try:
            msg = parse_message(raw)
        except DecodeError as e:
            self._post_log(f"[{ts}] Bad packet from {addr[0]}: {e}", 'err')
            return

        if msg['community'] != COMMUNITY_READ:
            self._post_log(f"[{ts}] Rejected bad community '{msg['community']}' from {addr[0]}", 'err')
            return

        pdu  = msg['pdu_type']
        ver  = msg['version']
        rid  = msg['request_id']
        pname = msg['pdu_type_name']

        if   pdu == Tag.GET_REQUEST:
            resp, lookup_rows = self._build_get(msg, ver)
            self._stats['get'] += 1
            etype = 'GetRequest'
        elif pdu == Tag.GET_NEXT_REQUEST:
            resp, lookup_rows = self._build_getnext(msg, ver)
            self._stats['getnext'] += 1
            etype = 'GetNextRequest'
        elif pdu == Tag.GET_BULK_REQUEST:
            resp, lookup_rows = self._build_getbulk(msg)
            self._stats['getbulk'] += 1
            etype = 'GetBulkRequest'
        elif pdu == Tag.SET_REQUEST:
            resp, lookup_rows = self._build_set(msg, ver)
            self._stats['set'] += 1
            etype = 'SetRequest'
        else:
            return

        # ── Post exchange event to GUI ─────────────────────────────────────
        req_oids = [oid for oid, _, _ in msg['varbinds']]
        self.gui_q.put(('exchange', {
            'ts'          : ts,
            'from_ip'     : addr[0],
            'from_port'   : addr[1],
            'pdu_type'    : etype,
            'request_id'  : rid,
            'community'   : msg['community'],
            'version'     : msg['version_name'],
            'req_oids'    : req_oids,
            'lookup_rows' : lookup_rows,   # list of (oid, name, value, unit)
        }))

        if resp:
            self.sock.sendto(resp, addr)

    # ── PDU handlers ──────────────────────────────────────────────────────────

    def _build_get(self, msg, ver):
        out, es, ei, lookups = [], ErrorStatus.NO_ERROR, 0, []
        for i, (oid, _v, _t) in enumerate(msg['varbinds'], 1):
            v = self.store.get(oid)
            name = OID_NAMES.get(oid, oid)
            if v is not None:
                out.append((oid, encode_integer(v)))
                lookups.append((oid, name, v, self._unit(oid, v)))
            elif ver == 0:
                es, ei = ErrorStatus.NO_SUCH_NAME, i
                out.append((oid, encode_null()))
                lookups.append((oid, name, 'N/A', 'noSuchName'))
            else:
                out.append((oid, bytes([Tag.NO_SUCH_INSTANCE, 0x00])))
                lookups.append((oid, name, 'N/A', 'noSuchInstance'))
        return build_response(msg['community'], msg['request_id'], es, ei, out, ver), lookups

    def _build_getnext(self, msg, ver):
        out, es, ei, lookups = [], ErrorStatus.NO_ERROR, 0, []
        for i, (oid, _v, _t) in enumerate(msg['varbinds'], 1):
            nxt = self.store.get_next_oid(oid)
            if nxt:
                v = self.store.get(nxt)
                name = OID_NAMES.get(nxt, nxt)
                out.append((nxt, encode_integer(v)))
                lookups.append((nxt, name, v, self._unit(nxt, v)))
            elif ver == 0:
                es, ei = ErrorStatus.NO_SUCH_NAME, i
                out.append((oid, encode_null()))
                lookups.append((oid, OID_NAMES.get(oid,oid), 'N/A', 'endOfMib'))
            else:
                out.append((oid, bytes([Tag.END_OF_MIB_VIEW, 0x00])))
                lookups.append((oid, OID_NAMES.get(oid,oid), 'N/A', 'endOfMibView'))
        return build_response(msg['community'], msg['request_id'], es, ei, out, ver), lookups

    def _build_getbulk(self, msg):
        nr, mr, vbs = msg['error_status'], max(msg['error_index'], 0), msg['varbinds']
        out, lookups = [], []
        for oid, _v, _t in vbs[:nr]:
            nxt = self.store.get_next_oid(oid)
            if nxt:
                v = self.store.get(nxt)
                out.append((nxt, encode_integer(v)))
                lookups.append((nxt, OID_NAMES.get(nxt,nxt), v, self._unit(nxt,v)))
            else:
                out.append((oid, bytes([Tag.END_OF_MIB_VIEW, 0x00])))
                lookups.append((oid, OID_NAMES.get(oid,oid), 'N/A', 'endOfMibView'))
        reps = [oid for oid, _v, _t in vbs[nr:]]
        for _ in range(mr):
            found = False
            for i, oid in enumerate(reps):
                nxt = self.store.get_next_oid(oid)
                if nxt:
                    v = self.store.get(nxt)
                    out.append((nxt, encode_integer(v)))
                    lookups.append((nxt, OID_NAMES.get(nxt,nxt), v, self._unit(nxt,v)))
                    reps[i] = nxt; found = True
                else:
                    out.append((oid, bytes([Tag.END_OF_MIB_VIEW, 0x00])))
                    lookups.append((oid, OID_NAMES.get(oid,oid), 'N/A', 'endOfMibView'))
            if not found: break
        return build_response(msg['community'], msg['request_id'],
                              ErrorStatus.NO_ERROR, 0, out, version=1), lookups

    def _build_set(self, msg, ver):
        out = [(oid, encode_null()) for oid, _v, _t in msg['varbinds']]
        lookups = [(oid, OID_NAMES.get(oid,oid), 'REJECTED', 'notWritable (read-only MIB)')
                   for oid, _v, _t in msg['varbinds']]
        return build_response(msg['community'], msg['request_id'],
                              ErrorStatus.NOT_WRITABLE, 1, out, ver), lookups

    @staticmethod
    def _unit(oid, val):
        if oid == OID_TEMPERATURE: return f"{val} °C"
        if oid == OID_HUMIDITY:    return f"{val} %"
        if oid == OID_AC_STATUS:   return "ON" if val else "OFF"
        if oid == OID_FAN_STATUS:  return "ON" if val else "OFF"
        if oid == OID_ALERT_STATUS:return "ALERT" if val else "NORMAL"
        return str(val)

    def _post_log(self, text, tag):
        self.gui_q.put(('log', text, tag))


# =============================================================================
# AGENT  GUI  APPLICATION
# =============================================================================
class AgentApp:
    MIB_ROWS = [
        (OID_TEMPERATURE, 'temperature',  '...9999.1.0', 'API',     '°C'),
        (OID_HUMIDITY,    'humidity',     '...9999.2.0', 'API',     '%'),
        (OID_AC_STATUS,   'acStatus',     '...9999.3.0', 'Derived', ''),
        (OID_FAN_STATUS,  'fanStatus',    '...9999.4.0', 'Derived', ''),
        (OID_ALERT_STATUS,'alertStatus',  '...9999.5.0', 'Derived', ''),
    ]

    def __init__(self, root):
        self.root      = root
        self.gui_q     = queue.Queue()
        self.store     = MibDataStore()
        self._running  = False
        self._simulate = _args.simulate
        self._fetcher  = None
        self._responder= None
        self._xcount   = 0   # exchange counter
        self._stats    = {'get':0,'getnext':0,'getbulk':0,'set':0,'traps':0}

        self._setup_styles()
        self._build_ui()
        self._schedule_drain()
        self._schedule_tick()
        self.root.after(500, self._start_agent)

    # ── Styles ────────────────────────────────────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style(); s.theme_use('clam')
        s.configure('TFrame',            background=C['bg'])
        s.configure('TLabel',            background=C['bg'],    foreground=C['text'], font=('Consolas',10))
        s.configure('TEntry',            fieldbackground=C['entry'], foreground=C['text'], font=('Consolas',10), borderwidth=1, relief='flat')
        s.configure('TButton',           background=C['btn'],   foreground=C['text'],  font=('Consolas',10), borderwidth=0, focusthickness=0)
        s.map('TButton', background=[('active',C['btnhov']),('pressed',C['accent'])])
        s.configure('Start.TButton',     background='#2d7a2d', foreground='white', font=('Consolas',10,'bold'))
        s.map('Start.TButton', background=[('active','#3a9e3a')])
        s.configure('Stop.TButton',      background=C['red'],  foreground='white', font=('Consolas',10,'bold'))
        s.map('Stop.TButton',  background=[('active','#cc3333')])
        s.configure('Treeview',          background=C['card'], foreground=C['text'], fieldbackground=C['card'], font=('Consolas',10), rowheight=28)
        s.configure('Treeview.Heading',  background=C['panel'],foreground=C['accent'], font=('Consolas',10,'bold'), relief='flat')
        s.map('Treeview', background=[('selected',C['accent'])])
        s.configure('TLabelframe',       background=C['panel'],foreground=C['accent'], borderwidth=1)
        s.configure('TLabelframe.Label', background=C['panel'],foreground=C['accent'], font=('Consolas',10,'bold'))

    # ── UI build ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        root = self.root
        root.title("SERVER-MONITOR-MIB  |  SNMP Agent")
        root.geometry("1300x900")
        root.configure(bg=C['bg'])
        root.minsize(1100, 700)

        # Header
        hdr = tk.Frame(root, bg=C['hdr_ag'], height=50)
        hdr.pack(fill='x'); hdr.pack_propagate(False)
        tk.Label(hdr, text="⬡  SERVER-MONITOR-MIB  |  SNMP Agent",
                 bg=C['hdr_ag'], fg='white', font=('Consolas',14,'bold')).pack(side='left', padx=16, pady=8)
        self._hdr_status = tk.Label(hdr, text="● Stopped", bg=C['hdr_ag'], fg='#ffd0d0', font=('Consolas',10))
        self._hdr_status.pack(side='right', padx=16)

        # Body: paned left / right
        body = tk.PanedWindow(root, orient='horizontal', bg=C['bg'], sashwidth=5, sashrelief='flat')
        body.pack(fill='both', expand=True)
        left = tk.Frame(body, bg=C['panel'], width=290); left.pack_propagate(False)
        body.add(left, minsize=260)
        right = tk.Frame(body, bg=C['bg'])
        body.add(right, minsize=700)
        self._build_left(left)
        self._build_right(right)

    # ── Left panel ────────────────────────────────────────────────────────────
    def _build_left(self, P):
        pad = dict(padx=10, pady=4)

        # Settings
        cf = ttk.LabelFrame(P, text='  Agent Settings', padding=10)
        cf.pack(fill='x', **pad)

        def row(fr, label, default, width=14):
            r = tk.Frame(fr, bg=C['panel']); r.pack(fill='x', pady=2)
            tk.Label(r, text=f"{label}:", bg=C['panel'], fg=C['dim'],
                     font=('Consolas',9), width=12, anchor='w').pack(side='left')
            v = tk.StringVar(value=default)
            ttk.Entry(r, textvariable=v, width=width).pack(side='left', expand=True, fill='x')
            return v

        self._v_mgrip   = row(cf, 'Manager IP',  MANAGER_HOST,        14)
        self._v_aport   = row(cf, 'Listen Port', str(AGENT_PORT),       6)
        self._v_tport   = row(cf, 'Trap Port',   str(MANAGER_TRAP_PORT),6)

        mr = tk.Frame(cf, bg=C['panel']); mr.pack(fill='x', pady=4)
        tk.Label(mr, text="Mode:", bg=C['panel'], fg=C['dim'], font=('Consolas',9), width=12, anchor='w').pack(side='left')
        self._v_mode = tk.StringVar(value='simulate' if self._simulate else 'api')
        tk.Radiobutton(mr, text='Live API',  variable=self._v_mode, value='api',
                       bg=C['panel'], fg=C['text'], selectcolor=C['accent'],
                       activebackground=C['panel'], font=('Consolas',9)).pack(side='left', padx=4)
        tk.Radiobutton(mr, text='Simulate',  variable=self._v_mode, value='simulate',
                       bg=C['panel'], fg=C['text'], selectcolor=C['accent'],
                       activebackground=C['panel'], font=('Consolas',9)).pack(side='left', padx=2)

        br = tk.Frame(cf, bg=C['panel']); br.pack(fill='x', pady=(6,2))
        self._btn_start = ttk.Button(br, text='▶  Start', command=self._start_agent, style='Start.TButton')
        self._btn_start.pack(side='left', fill='x', expand=True, padx=(0,4))
        self._btn_stop  = ttk.Button(br, text='■  Stop',  command=self._stop_agent,  style='Stop.TButton',  state='disabled')
        self._btn_stop.pack(side='left', fill='x', expand=True)

        tk.Frame(P, bg=C['border'], height=1).pack(fill='x', padx=10, pady=6)

        # Thresholds
        tf = ttk.LabelFrame(P, text='  Thresholds', padding=10)
        tf.pack(fill='x', **pad)
        for lbl, val in [('AC ON ≥', f'{TEMP_AC_ON_THRESHOLD}°C'),
                          ('Fan ON ≥', f'{TEMP_FAN_ON_THRESHOLD}°C'),
                          ('ALERT ≥', f'{TEMP_ALERT_THRESHOLD}°C'),
                          ('Hum ALERT ≥', f'{HUMIDITY_ALERT_THRESHOLD}%'),
                          ('Poll every', f'{API_POLL_INTERVAL}s')]:
            r = tk.Frame(tf, bg=C['panel']); r.pack(fill='x', pady=1)
            tk.Label(r, text=f"{lbl}:", bg=C['panel'], fg=C['dim'],
                     font=('Consolas',9), width=14, anchor='w').pack(side='left')
            tk.Label(r, text=val, bg=C['panel'], fg=C['teal'],
                     font=('Consolas',9,'bold')).pack(side='left')

        tk.Frame(P, bg=C['border'], height=1).pack(fill='x', padx=10, pady=6)

        # Stats
        sf = ttk.LabelFrame(P, text='  Requests Served', padding=10)
        sf.pack(fill='x', **pad)
        self._slbls = {}
        for k, lbl in [('get','GetRequest'),('getnext','GetNext'),
                        ('getbulk','GetBulk'),('set','SetRequest'),('traps','Traps Sent')]:
            r = tk.Frame(sf, bg=C['panel']); r.pack(fill='x', pady=1)
            tk.Label(r, text=f"{lbl}:", bg=C['panel'], fg=C['dim'],
                     font=('Consolas',9), width=14, anchor='w').pack(side='left')
            lb = tk.Label(r, text='0', bg=C['panel'], fg=C['teal'], font=('Consolas',10,'bold'))
            lb.pack(side='left')
            self._slbls[k] = lb

        tk.Frame(P, bg=C['border'], height=1).pack(fill='x', padx=10, pady=6)

        # Data source
        ds = ttk.LabelFrame(P, text='  Data Source', padding=10)
        ds.pack(fill='x', **pad)
        for lbl, val in [('Location', 'Manipal, Udupi'),
                          (f'Lat/Lon', f'{WEATHER_API_LATITUDE},{WEATHER_API_LONGITUDE}')]:
            r = tk.Frame(ds, bg=C['panel']); r.pack(fill='x', pady=1)
            tk.Label(r, text=f"{lbl}:", bg=C['panel'], fg=C['dim'],
                     font=('Consolas',9), width=10, anchor='w').pack(side='left')
            tk.Label(r, text=val, bg=C['panel'], fg=C['teal'],
                     font=('Consolas',9)).pack(side='left')

        r2 = tk.Frame(ds, bg=C['panel']); r2.pack(fill='x', pady=1)
        tk.Label(r2, text="Last fetch:", bg=C['panel'], fg=C['dim'],
                 font=('Consolas',9), width=10, anchor='w').pack(side='left')
        self._lbl_last = tk.Label(r2, text='—', bg=C['panel'], fg=C['text'], font=('Consolas',9))
        self._lbl_last.pack(side='left')

        r3 = tk.Frame(ds, bg=C['panel']); r3.pack(fill='x', pady=1)
        tk.Label(r3, text="Next fetch:", bg=C['panel'], fg=C['dim'],
                 font=('Consolas',9), width=10, anchor='w').pack(side='left')
        self._lbl_next = tk.Label(r3, text='—', bg=C['panel'], fg=C['text'], font=('Consolas',9))
        self._lbl_next.pack(side='left')

        tk.Frame(P, bg=C['border'], height=1).pack(fill='x', padx=10, pady=6)
        ttk.Button(P, text='Clear Exchange Log', command=self._clear_exchange).pack(padx=10, pady=2, fill='x')
        ttk.Button(P, text='Clear Activity Log', command=self._clear_log).pack(padx=10, pady=(0,4), fill='x')

    # ── Right panel ───────────────────────────────────────────────────────────
    def _build_right(self, P):
        # Top row: MIB table + Agent Info sidebar
        top = tk.Frame(P, bg=C['bg']); top.pack(fill='x', padx=6, pady=(6,4))
        self._build_mib_table(top)
        self._build_info_sidebar(top)

        # Middle: SNMP Exchange Monitor (THE KEY PANEL)
        self._build_exchange_monitor(P)

        # Bottom: raw log
        self._build_raw_log(P)

    def _build_mib_table(self, P):
        fr = ttk.LabelFrame(P, text='  Live MIB Object Values', padding=6)
        fr.pack(side='left', fill='both', expand=True, padx=(0,4))
        cols = ('Object','OID','Value','Source','Status')
        tree = ttk.Treeview(fr, columns=cols, show='headings', height=6)
        widths = {'Object':100,'OID':185,'Value':100,'Source':65,'Status':90}
        for c in cols:
            tree.heading(c, text=c); tree.column(c, width=widths[c], anchor='center')
        tree.tag_configure('normal',  background=C['card'],  foreground=C['text'])
        tree.tag_configure('alert',   background='#3a1515',  foreground=C['red'])
        tree.tag_configure('warning', background='#3a2e10',  foreground=C['warn'])
        tree.tag_configure('on',      background='#153a20',  foreground=C['green'])
        self._tree_iids = {}
        for oid, nm, short, src, unit in self.MIB_ROWS:
            iid = tree.insert('', 'end', values=(nm, short, '—', src, '—'), tags=('normal',))
            self._tree_iids[oid] = iid
        sb = ttk.Scrollbar(fr, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side='left', fill='both', expand=True); sb.pack(side='right', fill='y')
        self._mib_tree = tree

    def _build_info_sidebar(self, P):
        fr = ttk.LabelFrame(P, text='  Agent Info', padding=8)
        fr.pack(side='right', fill='y', expand=False)
        fr.configure(width=160)

        def irow(lbl, init, col=None):
            tk.Label(fr, text=lbl, bg=C['panel'], fg=C['dim'], font=('Consolas',8), anchor='w').pack(anchor='w', pady=(4,0))
            lb = tk.Label(fr, text=init, bg=C['panel'], fg=col or C['teal'], font=('Consolas',12,'bold'))
            lb.pack(anchor='w'); return lb

        self._lbl_uptime  = irow("Uptime",       "00:00:00")
        self._lbl_temp_b  = irow("Temperature",  "—", C['warn'])
        self._lbl_hum_b   = irow("Humidity",     "—", '#7ab8f5')
        self._lbl_ac_b    = irow("AC Status",    "—", C['green'])
        self._lbl_fan_b   = irow("Fan Status",   "—", C['green'])
        self._lbl_alert_b = irow("Alert Status", "—", C['red'])
        self._lbl_port_b  = irow("Port",         f":{AGENT_PORT}", C['dim'])
        self._lbl_xcount  = irow("Exchanges",    "0", C['dim'])

    def _build_exchange_monitor(self, P):
        """
        SNMP Exchange Monitor — shows every request received + response sent.
        Each exchange is rendered as a structured block:

          ┌─ REQUEST ◄ ─────────────────────────────────
          │  [time] GetRequest from 192.168.x.x:port
          │  Community: public   Version: SNMPv2c   Req-ID: 1042
          │  Requested OIDs (5):
          │    • temperature  1.3.6.1.4.1.9999.1.0
          │    • humidity     1.3.6.1.4.1.9999.2.0
          │    ...
          ├─ OID LOOKUP ─────────────────────────────────
          │    temperature  1.3.6.1.4.1.9999.1.0  →  28 °C
          │    humidity     1.3.6.1.4.1.9999.2.0  →  65 %
          │    ...
          └─ RESPONSE ► ─────────────────────────────────
             GetResponse sent → 192.168.x.x   Error: 0 (NO_ERROR)
             VarBinds (5): temperature=28°C  humidity=65%  ...
        """
        fr = ttk.LabelFrame(P, text='  SNMP Exchange Monitor  (Manager → Agent → Response)', padding=4)
        fr.pack(fill='both', expand=True, padx=6, pady=(0,4))

        self._exch_w = scrolledtext.ScrolledText(
            fr, bg=C['logbg'], fg=C['text'],
            font=('Consolas', 9), relief='flat', borderwidth=0,
            state='disabled', wrap='word', height=14)
        self._exch_w.pack(fill='both', expand=True)

        # Colour tags
        self._exch_w.tag_config('req_hdr',  foreground='#ffffff',  background='#1a2a4a', font=('Consolas',9,'bold'))
        self._exch_w.tag_config('req_body', foreground=C['req_col'])
        self._exch_w.tag_config('lkp_hdr',  foreground='#ffffff',  background='#1a3a2a', font=('Consolas',9,'bold'))
        self._exch_w.tag_config('lkp_row',  foreground=C['lkp_col'])
        self._exch_w.tag_config('resp_hdr', foreground='#ffffff',  background='#0a2a1a', font=('Consolas',9,'bold'))
        self._exch_w.tag_config('resp_val', foreground=C['resp_col'], font=('Consolas',9,'bold'))
        self._exch_w.tag_config('trap_hdr', foreground='#ffffff',  background='#3a2a0a', font=('Consolas',9,'bold'))
        self._exch_w.tag_config('trap_val', foreground=C['trap_col'])
        self._exch_w.tag_config('err_col',  foreground=C['err_col'])
        self._exch_w.tag_config('sep',      foreground='#3a3a5a')

    def _build_raw_log(self, P):
        fr = ttk.LabelFrame(P, text='  Activity Log  (API fetches / system events)', padding=4)
        fr.pack(fill='x', padx=6, pady=(0,6))
        self._log_w = scrolledtext.ScrolledText(
            fr, bg=C['logbg'], fg=C['text'],
            font=('Consolas', 9), relief='flat', borderwidth=0,
            state='disabled', wrap='word', height=5)
        self._log_w.pack(fill='both', expand=True)
        self._log_w.tag_config('sys',  foreground=C['sys_col'])
        self._log_w.tag_config('ok',   foreground=C['green'])
        self._log_w.tag_config('err',  foreground=C['err_col'])
        self._log_w.tag_config('trap', foreground=C['trap_col'])

    # ── Agent start/stop ──────────────────────────────────────────────────────
    def _start_agent(self):
        if self._running: return
        try:
            _live_cfg.MANAGER_HOST      = self._v_mgrip.get().strip()
            _live_cfg.AGENT_PORT         = int(self._v_aport.get().strip())
            _live_cfg.MANAGER_TRAP_PORT  = int(self._v_tport.get().strip())
        except ValueError:
            self._log("Invalid port.", 'err'); return

        sim = (self._v_mode.get() == 'simulate')
        self._fetcher = WeatherFetcher(self.store, self._on_trap,
                                       self._on_data_update, simulate=sim)
        self._responder = SnmpResponder(self.store, self._on_trap, self.gui_q)
        try:
            self._responder.bind()
        except OSError as e:
            self._log(f"Cannot bind port {AGENT_PORT}: {e}", 'err'); return

        self._fetcher.start()
        self._responder.start()
        self._running = True
        self._btn_start.configure(state='disabled')
        self._btn_stop.configure(state='normal')
        self._hdr_status.config(text="● Running", fg='#90ff90')
        self._log_mode = 'Simulate' if sim else 'Live API'

        mgr = _live_cfg.MANAGER_HOST
        self._log(
            f"Agent started\n"
            f"  Listen   : {AGENT_BIND_HOST}:{_live_cfg.AGENT_PORT}  (all interfaces)\n"
            f"  Traps  → : {mgr}:{_live_cfg.MANAGER_TRAP_PORT}\n"
            f"  Mode     : {'SIMULATE' if sim else 'API — Manipal, Udupi'}\n"
            f"  Alert ≥  : {TEMP_ALERT_THRESHOLD}°C | Hum ≥ {HUMIDITY_ALERT_THRESHOLD}%\n", 'sys')

    def _stop_agent(self):
        if not self._running: return
        if self._fetcher:    self._fetcher.stop()
        if self._responder:  self._responder.stop()
        self._running = False
        self._btn_start.configure(state='normal')
        self._btn_stop.configure(state='disabled')
        self._hdr_status.config(text="● Stopped", fg='#ffd0d0')
        self._log("Agent stopped.", 'sys')

    # ── Callbacks from background threads ────────────────────────────────────
    def _on_data_update(self, temp, hum, src, n):
        self.gui_q.put(('data', temp, hum, src, n))

    def _on_trap(self, alert, trap_type, temp, hum):
        mgr = _live_cfg.MANAGER_HOST
        oid   = (OID_TRAP_TEMP_ALERT if trap_type == 'temperature'
                 else OID_TRAP_HUMIDITY_ALERT) if alert else OID_TRAP_NORMAL
        label = (f"{trap_type.upper()} ALERT" if alert else "NORMAL (cleared)")
        vbs = [(OID_TEMPERATURE,  encode_integer(int(temp))),
               (OID_HUMIDITY,     encode_integer(int(hum))),
               (OID_ALERT_STATUS, encode_integer(alert))]
        raw = build_trap_v2c(COMMUNITY_TRAP, oid, vbs, self.store.get_uptime_hundredths())
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(raw, (mgr, _live_cfg.MANAGER_TRAP_PORT))
            s.close()
            self.gui_q.put(('trap', datetime.now().strftime('%H:%M:%S'),
                            label, oid, temp, hum, alert, mgr))
        except Exception as e:
            self.gui_q.put(('log', f"Trap failed: {e}", 'err'))

    # ── Queue drain ───────────────────────────────────────────────────────────
    def _schedule_drain(self):
        self._drain()
        self.root.after(50, self._schedule_drain)

    def _drain(self):
        try:
            while True:
                item = self.gui_q.get_nowait()
                kind = item[0]
                if kind == 'data':
                    _, temp, hum, src, n = item
                    self._update_mib_table()
                    self._update_sidebar(temp, hum)
                    self._lbl_xcount.config(text=str(self._xcount))
                    if self._fetcher:
                        self._lbl_last.config(text=self._fetcher.last_fetch or '—')
                    self._log(f"[{datetime.now().strftime('%H:%M:%S')}] Data fetch #{n} "
                              f"src={src}  temp={temp}°C  hum={hum}%", 'ok')
                elif kind == 'exchange':
                    self._render_exchange(item[1])
                elif kind == 'trap':
                    _, ts, label, oid, temp, hum, alert, mgr = item
                    self._stats['traps'] += 1; self._update_stats()
                    self._render_trap(ts, label, oid, temp, hum, alert, mgr)
                elif kind == 'log':
                    self._log(item[1], item[2])
        except queue.Empty:
            pass
        # sync responder stats
        if self._responder and self._running:
            rs = self._responder.stats()
            for k in ('get','getnext','getbulk','set'):
                self._stats[k] = rs[k]
            self._update_stats()

    # ── Tick (uptime + countdown) ─────────────────────────────────────────────
    def _schedule_tick(self):
        self._tick()
        self.root.after(1000, self._schedule_tick)

    def _tick(self):
        if self._running:
            self._lbl_uptime.config(text=self.store.uptime_str())
            if self._fetcher:
                self._lbl_next.config(text=f"in {self._fetcher.secs_to_next()}s")

    # ── Exchange Monitor renderer ─────────────────────────────────────────────
    def _render_exchange(self, ev):
        """Render one full SNMP exchange (request + lookup + response)."""
        self._xcount += 1
        self._lbl_xcount.config(text=str(self._xcount))

        ts       = ev['ts']
        from_ip  = ev['from_ip']
        from_port= ev['from_port']
        ptype    = ev['pdu_type']
        rid      = ev['request_id']
        comm     = ev['community']
        ver      = ev['version']
        req_oids = ev['req_oids']
        lookups  = ev['lookup_rows']

        w = self._exch_w
        w.configure(state='normal')

        # separator
        w.insert('end', f"\n{'─'*78}\n", 'sep')

        # ── REQUEST block ────────────────────────────────────────────────────
        w.insert('end',
            f"  ◄ REQUEST #{self._xcount}  ─────────────────────────────────────────────\n",
            'req_hdr')
        w.insert('end',
            f"  [{ts}]  {ptype}  from {from_ip}:{from_port}\n"
            f"  Community: {comm}   Version: {ver}   Request-ID: {rid}\n"
            f"  Requested OIDs ({len(req_oids)}):\n",
            'req_body')
        for oid in req_oids:
            name = OID_NAMES.get(oid, oid)
            w.insert('end', f"      •  {name:<15}  {oid}\n", 'req_body')

        # ── LOOKUP block ─────────────────────────────────────────────────────
        w.insert('end',
            f"\n  ↳ OID LOOKUP  ──────────────────────────────────────────────────────\n",
            'lkp_hdr')
        for oid, name, val, display in lookups:
            arrow = '✓' if str(val) not in ('N/A','REJECTED') else '✗'
            w.insert('end',
                f"      {arrow}  {name:<15}  {oid}\n"
                f"            MIB store  →  {display}\n",
                'lkp_row')

        # ── RESPONSE block ───────────────────────────────────────────────────
        resp_vals = "  ".join(f"{n}={d}" for _, n, v, d in lookups if str(v) not in ('N/A','REJECTED'))
        w.insert('end',
            f"\n  ► RESPONSE  ────────────────────────────────────────────────────────\n",
            'resp_hdr')
        w.insert('end',
            f"  GetResponse sent → {from_ip}:{from_port}   Error: 0 (NO_ERROR)\n"
            f"  VarBinds: {resp_vals}\n",
            'resp_val')

        w.configure(state='disabled')
        w.see('end')

    def _render_trap(self, ts, label, oid, temp, hum, alert, mgr):
        w = self._exch_w
        w.configure(state='normal')
        w.insert('end', f"\n{'─'*78}\n", 'sep')
        w.insert('end',
            f"  ▲ TRAP SENT  ──────────────────────────────────────────────────────\n",
            'trap_hdr')
        w.insert('end',
            f"  [{ts}]  Trap-v2c → {mgr}:{_live_cfg.MANAGER_TRAP_PORT}\n"
            f"  Trap type : {label}\n"
            f"  Trap OID  : {oid}\n"
            f"  Payload   : temperature={temp}°C   humidity={hum}%   "
            f"alertStatus={'ALERT' if alert else 'NORMAL'}\n",
            'trap_val')
        w.configure(state='disabled')
        w.see('end')

    # ── MIB table & sidebar update ────────────────────────────────────────────
    def _update_mib_table(self):
        d = self.store.get_all()
        for oid, nm, short, src, unit in self.MIB_ROWS:
            iid = self._tree_iids[oid]; v = d.get(oid)
            if v is None: continue
            tag = 'normal'
            if oid == OID_TEMPERATURE:
                disp = f"{v} °C"; stat = 'OK'
                if v >= TEMP_ALERT_THRESHOLD:    tag, stat = 'alert',   'ALERT'
                elif v >= TEMP_FAN_ON_THRESHOLD: tag, stat = 'warning', 'WARNING'
            elif oid == OID_HUMIDITY:
                disp = f"{v} %"; stat = 'OK'
                if v >= HUMIDITY_ALERT_THRESHOLD: tag, stat = 'alert', 'ALERT'
            elif oid == OID_AC_STATUS:
                disp = 'ON' if v else 'OFF'; stat = disp; tag = 'on' if v else 'normal'
            elif oid == OID_FAN_STATUS:
                disp = 'ON' if v else 'OFF'; stat = disp; tag = 'on' if v else 'normal'
            elif oid == OID_ALERT_STATUS:
                disp = '⚠ ALERT' if v else '✓ NORMAL'
                stat = 'ALERT' if v else 'NORMAL'; tag = 'alert' if v else 'normal'
            else:
                disp = str(v); stat = '—'
            self._mib_tree.item(iid, values=(nm, short, disp, src, stat), tags=(tag,))
        alert_active = any(
            self._mib_tree.item(iid,'tags')[0] == 'alert'
            for iid in self._tree_iids.values())
        if alert_active:
            self._hdr_status.config(text="⚠ Running — ALERT", fg='#ffdd00')
        elif self._running:
            self._hdr_status.config(text="● Running", fg='#90ff90')

    def _update_sidebar(self, temp, hum):
        d = self.store.get_all()
        col_t = C['red'] if temp >= TEMP_ALERT_THRESHOLD else (
                C['warn'] if temp >= TEMP_FAN_ON_THRESHOLD else C['teal'])
        self._lbl_temp_b.config(text=f"{temp}°C",  fg=col_t)
        self._lbl_hum_b.config( text=f"{hum}%",    fg='#7ab8f5')
        self._lbl_ac_b.config(  text='ON'  if d[OID_AC_STATUS]  else 'OFF',
                                fg=C['green'] if d[OID_AC_STATUS]  else C['dim'])
        self._lbl_fan_b.config( text='ON'  if d[OID_FAN_STATUS] else 'OFF',
                                fg=C['green'] if d[OID_FAN_STATUS] else C['dim'])
        col_a = C['red'] if d[OID_ALERT_STATUS] else C['green']
        self._lbl_alert_b.config(
            text='⚠ ALERT'  if d[OID_ALERT_STATUS] else '✓ NORMAL', fg=col_a)

    def _update_stats(self):
        for k, lb in self._slbls.items():
            lb.configure(text=str(self._stats.get(k, 0)))

    # ── Logging helpers ───────────────────────────────────────────────────────
    def _log(self, text, tag='sys'):
        w = self._log_w; w.configure(state='normal')
        w.insert('end', text)
        if not text.endswith('\n'): w.insert('end', '\n')
        w.configure(state='disabled'); w.see('end')

    def _clear_exchange(self):
        self._exch_w.configure(state='normal')
        self._exch_w.delete('1.0', 'end')
        self._exch_w.configure(state='disabled')

    def _clear_log(self):
        self._log_w.configure(state='normal')
        self._log_w.delete('1.0', 'end')
        self._log_w.configure(state='disabled')

    def on_close(self):
        self._stop_agent()
        self.root.destroy()


# =============================================================================
# ENTRY POINT
# =============================================================================
def _mgr_dialog():
    root = tk.Tk(); root.withdraw()
    cur = MANAGER_HOST
    ip = simpledialog.askstring(
        "Manager IP Address",
        f"IP address of the machine running manager.py\n"
        f"(Traps will be sent to this IP)\n\n"
        f"  • Same machine       → press OK  (127.0.0.1)\n"
        f"  • Different network  → enter the Manager's\n"
        f"    IP address (ZeroTier or direct IP)\n\n"
        f"Current: {cur}",
        initialvalue=cur, parent=root)
    root.destroy()
    if ip and ip.strip():
        _live_cfg.MANAGER_HOST = ip.strip()
        import config; config.MANAGER_HOST = ip.strip()

def main():
    _mgr_dialog()
    root = tk.Tk()
    app  = AgentApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

if __name__ == '__main__':
    main()
