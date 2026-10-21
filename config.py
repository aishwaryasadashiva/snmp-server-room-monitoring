# =============================================================================
# config.py  —  Shared Configuration  SERVER-MONITOR-MIB
#
# ┌────────────────────────────────────────────────────────────────────────┐
# │  TWO-SYSTEM  /  DIFFERENT-NETWORK  SETUP  (Professor requirement)      │
# │                                                                         │
# │  OPTION A — ZeroTier (Recommended — 5 minutes, free, zero config)     │
# │  ─────────────────────────────────────────────────────────────────     │
# │  1. Install ZeroTier on BOTH machines:  https://www.zerotier.com       │
# │  2. Create a free network at my.zerotier.com (copy the Network ID)     │
# │  3. On each machine: zerotier-cli join <NETWORK_ID>                    │
# │  4. Authorize both machines in the ZeroTier web portal                 │
# │  5. Each machine gets a ZeroTier virtual IP (e.g. 192.168.193.x)      │
# │  6. Machine A can be on home WiFi, Machine B on phone hotspot —        │
# │     they still communicate over ZeroTier regardless of physical net.   │
# │                                                                         │
# │  OPTION B — Phone Hotspot (no extra software)                          │
# │  ─────────────────────────────────────────────────────────────────     │
# │  1. Machine A (Agent/Mac): connect to home WiFi or college WiFi        │
# │  2. Machine B (Manager): turn on phone hotspot, connect laptop to it  │
# │  3. Mac shares its internet via "System Settings → Sharing →           │
# │     Internet Sharing" → share via WiFi to create a third network      │
# │     OR use Mac's IP on its main WiFi as the Agent address              │
# │  4. The two machines are now on physically different networks           │
# │  5. Use ZeroTier or a direct public IP + port forward to connect       │
# │                                                                         │
# │  OPTION C — Same network, different subnets (lab demo shortcut)        │
# │  Both machines same WiFi but different assigned IP ranges              │
# └────────────────────────────────────────────────────────────────────────┘
#
# HOW TO RUN (after IPs are set up):
#   Agent machine:   python3 agent.py   --manager-ip <MANAGER_IP>
#   Manager machine: python3 manager.py --agent-ip   <AGENT_IP>
# =============================================================================

import os

# ── Bind addresses  (NEVER change — 0.0.0.0 = accept from any network) ───────
AGENT_BIND_HOST   = '0.0.0.0'    # Agent listens on ALL interfaces
MANAGER_BIND_HOST = '0.0.0.0'    # Trap receiver listens on ALL interfaces

# ── Remote addresses  (override via --flag at launch) ─────────────────────────
AGENT_HOST    = os.environ.get('AGENT_HOST',   '127.0.0.1')
MANAGER_HOST  = os.environ.get('MANAGER_HOST', '127.0.0.1')

# ── Ports  (non-privileged; standard SNMP uses 161/162 which needs root) ──────
AGENT_PORT        = 16100
MANAGER_TRAP_PORT = 16200

# ── SNMP community strings ────────────────────────────────────────────────────
COMMUNITY_READ    = 'public'
COMMUNITY_WRITE   = 'private'
COMMUNITY_TRAP    = 'public'

# ── SNMP versions ─────────────────────────────────────────────────────────────
SNMP_V1  = 0
SNMP_V2C = 1

# ── OID definitions ───────────────────────────────────────────────────────────
ENTERPRISE_BASE = '1.3.6.1.4.1'
ENTERPRISE_OID  = '1.3.6.1.4.1.9999'

OID_TEMPERATURE  = '1.3.6.1.4.1.9999.1.0'
OID_HUMIDITY     = '1.3.6.1.4.1.9999.2.0'
OID_AC_STATUS    = '1.3.6.1.4.1.9999.3.0'
OID_FAN_STATUS   = '1.3.6.1.4.1.9999.4.0'
OID_ALERT_STATUS = '1.3.6.1.4.1.9999.5.0'

OID_TRAP_BASE           = '1.3.6.1.4.1.9999.0'
OID_TRAP_TEMP_ALERT     = '1.3.6.1.4.1.9999.0.1'
OID_TRAP_HUMIDITY_ALERT = '1.3.6.1.4.1.9999.0.2'
OID_TRAP_NORMAL         = '1.3.6.1.4.1.9999.0.3'

OID_SYS_UPTIME    = '1.3.6.1.2.1.1.3.0'
OID_SNMP_TRAP_OID = '1.3.6.1.6.3.1.1.4.1.0'

ALL_SCALAR_OIDS = [
    OID_TEMPERATURE,
    OID_HUMIDITY,
    OID_AC_STATUS,
    OID_FAN_STATUS,
    OID_ALERT_STATUS,
]

OID_NAMES = {
    OID_TEMPERATURE         : 'temperature',
    OID_HUMIDITY            : 'humidity',
    OID_AC_STATUS           : 'acStatus',
    OID_FAN_STATUS          : 'fanStatus',
    OID_ALERT_STATUS        : 'alertStatus',
    OID_TRAP_TEMP_ALERT     : 'temperatureAlertTrap',
    OID_TRAP_HUMIDITY_ALERT : 'humidityAlertTrap',
    OID_TRAP_NORMAL         : 'normalStatusTrap',
}

# ── Thresholds ────────────────────────────────────────────────────────────────
# Tuned for 9–11 AM Manipal, Udupi (Open-Meteo reports ~28–31°C in that window)
TEMP_AC_ON_THRESHOLD     = 22   # AC turns ON  when temp >= this
TEMP_FAN_ON_THRESHOLD    = 24   # Fan turns ON when temp >= this
TEMP_ALERT_THRESHOLD     = 35   # ALERT fires  when temp >= this (fires at 9 AM)
HUMIDITY_ALERT_THRESHOLD = 90   # ALERT fires  when humidity >= this

# ── Poll / buffer ─────────────────────────────────────────────────────────────
API_POLL_INTERVAL  = 30        # seconds between weather API fetches
SOCKET_BUFFER_SIZE = 65535

# ── Weather API  (Open-Meteo, free, no key — Manipal coords) ─────────────────
WEATHER_API_LATITUDE  = 13.3528
WEATHER_API_LONGITUDE = 74.7901
WEATHER_API_TIMEZONE  = 'Asia/Kolkata'
WEATHER_API_URL = (
    "https://api.open-meteo.com/v1/forecast"
    f"?latitude={WEATHER_API_LATITUDE}"
    f"&longitude={WEATHER_API_LONGITUDE}"
    f"&current=temperature_2m,relative_humidity_2m"
    f"&timezone={WEATHER_API_TIMEZONE}"
)
