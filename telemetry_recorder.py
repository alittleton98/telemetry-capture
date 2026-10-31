# Records game telemetry to CSV and MySQL, using a format described in a JSON file.
# The file's capture block says how the game publishes its data: see CAPTURE_METHODS.
#
#   python telemetry_recorder.py
#
# Asks for the format file and MySQL login on startup.
# Commands while running: start <name> | end | status | quit
import codecs
import csv
import ctypes
import getpass
import ipaddress
import json
import math
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from datetime import datetime

import mysql.connector

DB_HOST = "10.76.5.220"
DB_PORT = 3306

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FLUSH_INTERVAL = 0.5  # seconds between batched inserts; a per-packet commit over ZeroTier would drop packets
MAX_TABLE_NAME = 64  # MySQL limit
ACCESS_DENIED = 1045  # MySQL error for a wrong username or password

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
FIELD_STRUCT = re.compile(r"^(?:[bBhHiIlLqQfd?]|[1-9][0-9]*s)$")
BYTE_ORDERS = set("=<>!")
REQUIRED_KEYS = ("database", "csv_dir", "working_table", "byte_order", "capture", "fields")

MEMORY_PAGE = 4096
BLOCK_GAP = 256  # fields closer than this are read as one block, so they come from the same moment
STALE_SECONDS = 5  # with no new data for this long, let go of the mapping so a closed game can release it
TORN_READ_RETRIES = 5


class FormatError(Exception):
    pass


class PacketFormat:
    """A telemetry format loaded from JSON: how to decode a packet, write it to CSV and store it in SQL."""

    def __init__(self, path):
        try:
            with open(path, encoding="utf-8") as f:
                spec = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            raise FormatError(f"Could not read {path}: {e}")

        missing = [key for key in REQUIRED_KEYS if key not in spec]
        if missing:
            raise FormatError(f"Missing keys: {', '.join(missing)}")

        self.name = spec.get("name", os.path.basename(path))
        self.database = spec["database"]
        self.csv_dir = os.path.normpath(os.path.join(SCRIPT_DIR, spec["csv_dir"]))  # relative to this script
        self.working_table = spec["working_table"]
        self.active_field = spec.get("active_field")
        self.active_value = spec.get("active_value")
        self.primary_key = spec.get("primary_key")
        self.extra_columns = spec.get("extra_sql_columns", [])
        self.fields = spec["fields"]
        self.byte_order = spec["byte_order"]

        if not self.fields:
            raise FormatError("No fields defined")
        for field in self.fields:
            for key in ("name", "struct", "sql"):
                if key not in field:
                    raise FormatError(f"Field {field} is missing '{key}'")
            if not FIELD_STRUCT.match(field["struct"]):
                raise FormatError(f"Field {field['name']}: unsupported struct code '{field['struct']}'")
            if field["struct"].endswith("s"):
                try:
                    codecs.lookup(field.get("encoding", ""))
                except LookupError:
                    raise FormatError(f"Field {field['name']}: text fields need a valid encoding")
            if "csv" in field:
                try:
                    format(1 if field["struct"] not in "fd" else 1.0, field["csv"])
                except ValueError:
                    raise FormatError(f"Field {field['name']}: invalid csv format '{field['csv']}'")

        self.names = [field["name"] for field in self.fields]
        all_names = self.names + [column["name"] for column in self.extra_columns]
        for name in all_names + [self.database, self.working_table]:
            if not IDENTIFIER.match(name):
                raise FormatError(f"Invalid SQL identifier: '{name}'")
        lowered = [name.lower() for name in all_names]  # MySQL column names ignore case
        duplicates = {name for name in all_names if lowered.count(name.lower()) > 1}
        if duplicates:
            raise FormatError(f"Duplicate column names: {', '.join(sorted(duplicates))}")
        for key, value in (("active_field", self.active_field), ("primary_key", self.primary_key)):
            if value is not None and value not in self.names:
                raise FormatError(f"{key} '{value}' is not one of the fields")
        if self.byte_order not in BYTE_ORDERS:
            raise FormatError(f"byte_order must be one of {' '.join(sorted(BYTE_ORDERS))}")

        self.active_index = self.names.index(self.active_field) if self.active_field else None
        self.float_indexes = [i for i, field in enumerate(self.fields) if field["struct"] in "fd"]
        self.bool_indexes = [i for i, field in enumerate(self.fields) if field["struct"] == "?"]
        self.text_fields = [(i, field["encoding"]) for i, field in enumerate(self.fields)
                            if field["struct"].endswith("s")]
        self.csv_specs = [field.get("csv") for field in self.fields]

        capture = spec["capture"]
        method = capture.get("method") if isinstance(capture, dict) else None
        if method not in CAPTURE_METHODS:
            raise FormatError(f"capture.method must be one of {', '.join(CAPTURE_METHODS)}")
        self.capture = CAPTURE_METHODS[method](self, capture)

    def finish_row(self, raw):
        """Turns unpacked values into a row: text cut at its terminator, booleans as 0 or 1."""
        row = list(raw)
        for i, encoding in self.text_fields:
            if row[i] is not None:
                row[i] = row[i].decode(encoding, "replace").split("\0")[0]
        for i in self.bool_indexes:
            if row[i] is not None:
                row[i] = int(row[i])
        return row

    def is_active(self, values):
        if self.active_index is None:
            return True
        if self.active_value is not None:
            return values[self.active_index] == self.active_value
        return bool(values[self.active_index])

    def csv_row(self, values):
        return [format(v, spec) if spec and v is not None else v for v, spec in zip(values, self.csv_specs)]

    def sql_row(self, values):
        # MySQL rejects NaN and infinity, and one bad value would fail the whole batch
        row = list(values)
        for i in self.float_indexes:
            if row[i] is not None and not math.isfinite(row[i]):
                row[i] = None
        return tuple(row)

    def create_table_sql(self, table):
        columns = [f"`{c['name']}` {c['sql']}" for c in self.extra_columns]
        columns += [f"`{f['name']}` {f['sql']}" for f in self.fields]
        if self.primary_key:
            columns.append(f"PRIMARY KEY (`{self.primary_key}`)")
        return f"CREATE TABLE `{table}` (\n  " + ",\n  ".join(columns) + "\n)"

    def insert_sql(self, table):
        columns = ", ".join(f"`{name}`" for name in self.names)
        placeholders = ", ".join(["%s"] * len(self.names))
        sql = f"INSERT INTO `{table}` ({columns}) VALUES ({placeholders})"
        if self.primary_key:
            updates = ", ".join(f"`{name}`=VALUES(`{name}`)" for name in self.names)
            sql += f" ON DUPLICATE KEY UPDATE {updates}"
        return sql


class UdpCapture:
    """capture.method "udp": the game sends one fixed-size packet per update to a port."""

    def __init__(self, packet_format, spec):
        self.format = packet_format
        for key in ("listen_address", "listen_port", "packet_size"):
            if key not in spec:
                raise FormatError(f"capture is missing '{key}'")
        self.address = spec["listen_address"]
        self.port = spec["listen_port"]
        self.packet_size = spec["packet_size"]
        self.struct = struct.Struct(packet_format.byte_order + "".join(f["struct"] for f in packet_format.fields))
        if self.struct.size != self.packet_size:
            raise FormatError(f"Fields add up to {self.struct.size} bytes but packet_size is {self.packet_size}")
        self.server = None
        self.seen_sender = False
        self.bad_sizes = {}

    def describe(self):
        return f"UDP on {self.address}:{self.port}, {self.packet_size} byte packets"

    def open(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        self.server.bind((self.address, self.port))
        self.server.settimeout(0.5)

    def read(self):
        try:
            message, sender = self.server.recvfrom(65535)
        except (socket.timeout, ConnectionError):
            return None
        if not self.seen_sender:
            print(f"Receiving packets from {sender[0]}:{sender[1]}, {len(message)} bytes")
            self.seen_sender = True
        if len(message) != self.packet_size:
            size = len(message)
            if size not in self.bad_sizes:
                print(f"Ignoring packet of {size} bytes from {sender[0]}: format expects {self.packet_size}")
            self.bad_sizes[size] = self.bad_sizes.get(size, 0) + 1
            return None
        return self.format.finish_row(self.struct.unpack(message))

    def status(self):
        return f"Wrong-size packets ignored: {self.bad_sizes}" if self.bad_sizes else None

    def close(self):
        if self.server:
            self.server.close()


class MemoryBasicInformation(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
                ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenFileMappingW.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR)
kernel32.OpenFileMappingW.restype = wintypes.HANDLE
kernel32.MapViewOfFile.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t)
kernel32.MapViewOfFile.restype = ctypes.c_void_p
kernel32.UnmapViewOfFile.argtypes = (ctypes.c_void_p,)
kernel32.VirtualQuery.argtypes = (ctypes.c_void_p, ctypes.POINTER(MemoryBasicInformation), ctypes.c_size_t)
kernel32.VirtualQuery.restype = ctypes.c_size_t
kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
FILE_MAP_READ = 0x0004


class MappedView:
    """A read-only view of a game's named shared memory."""

    def __init__(self, name):
        # mmap.mmap(tagname=...) would create the mapping when the game isn't running, so this only opens one
        self.handle = kernel32.OpenFileMappingW(FILE_MAP_READ, False, name)
        self.base = None
        self.size = 0
        if not self.handle:
            return
        self.base = kernel32.MapViewOfFile(self.handle, FILE_MAP_READ, 0, 0, 0)
        if self.base:
            info = MemoryBasicInformation()
            kernel32.VirtualQuery(self.base, ctypes.byref(info), ctypes.sizeof(info))
            self.size = info.RegionSize

    def __bool__(self):
        return bool(self.base)

    def read(self, offset, length):
        if offset < 0 or offset + length > self.size:
            raise ValueError(f"read of {length} bytes at {offset} is outside the {self.size} byte mapping")
        return ctypes.string_at(self.base + offset, length)

    def close(self):
        if self.base:
            kernel32.UnmapViewOfFile(self.base)
        if self.handle:
            kernel32.CloseHandle(self.handle)
        self.base = self.handle = None
        self.size = 0


class SharedMemoryCapture:
    """capture.method "shared_memory": named mappings with a fixed layout, polled until update_field changes.

    Reads never touch the game's lock or events: taking the lock from Python could stall the game, and waiting
    on its events could take updates from other telemetry apps. Instead each block is read twice until both match.
    """

    def __init__(self, packet_format, spec):
        self.format = packet_format
        pages = spec.get("pages")
        if not pages:
            raise FormatError("capture is missing 'pages'")
        for name, page in pages.items():
            if "mapping" not in page or "size_bytes" not in page:
                raise FormatError(f"capture page '{name}' needs mapping and size_bytes")
        self.pages = pages
        self.poll = spec.get("poll_interval_ms", 2) / 1000
        self.record = spec.get("player_record")
        if self.record:
            if self.record.get("page") not in pages:
                raise FormatError("player_record.page is not one of the capture pages")
            for key in ("array_offset", "stride", "index_offset", "max_records"):
                if key not in self.record:
                    raise FormatError(f"player_record is missing '{key}'")
            size = pages[self.record["page"]]["size_bytes"]
            if self.record["array_offset"] + self.record["stride"] * self.record["max_records"] > size:
                raise FormatError("player_record runs past the end of its page")

        absolute = {name: [] for name in pages}
        in_record = []
        self.plans = {}
        for index, field in enumerate(packet_format.fields):
            page = field.get("page") or (next(iter(pages)) if len(pages) == 1 else None)
            if page not in pages:
                raise FormatError(f"Field {field['name']}: page '{page}' is not one of the capture pages")
            if "offset" not in field:
                raise FormatError(f"Field {field['name']} needs an offset for this capture method")
            layout = struct.Struct(packet_format.byte_order + field["struct"])
            is_record = bool(self.record) and not field.get("absolute")
            limit = self.record["stride"] if is_record else pages[page]["size_bytes"]
            if field["offset"] < 0 or field["offset"] + layout.size > limit:
                raise FormatError(f"Field {field['name']} ends past its limit of {limit} bytes")
            (in_record if is_record else absolute[page]).append((field["offset"], layout, index))
            self.plans[field["name"]] = (page, field["offset"], layout, is_record)

        self.update_field = spec.get("update_field")
        if self.update_field not in self.plans:
            raise FormatError(f"capture.update_field '{self.update_field}' is not one of the fields")

        self.blocks = []
        for page, members in absolute.items():
            members.sort(key=lambda m: m[0])
            current = None
            for member in members:
                if current and member[0] <= current["end"] + BLOCK_GAP:
                    current["members"].append(member)
                    current["end"] = max(current["end"], member[0] + member[1].size)
                else:
                    current = {"page": page, "start": member[0], "end": member[0] + member[1].size,
                               "members": [member], "record": False}
                    self.blocks.append(current)
        if in_record:
            self.blocks.append({"page": self.record["page"], "start": 0,
                                "end": max(m[0] + m[1].size for m in in_record),
                                "members": in_record, "record": True})

        self.views = {}
        self.connected = False
        self.reported_error = None
        self.warned_size = False
        self.last_update = None
        self.last_change = 0
        self.torn_reads = 0

    def describe(self):
        mappings = ", ".join(page["mapping"] for page in self.pages.values())
        return f"shared memory {mappings}"

    def open(self):
        pass

    def open_views(self):
        views = {}
        for name, page in self.pages.items():
            view = MappedView(page["mapping"])
            views[name] = view
            problem = None
            if not view:
                problem = "absent"
            elif view.size < page["size_bytes"]:
                problem = (f"{page['mapping']} is {view.size} bytes but the format needs {page['size_bytes']}. "
                           "The game's layout has changed, so nothing will be captured until the format is updated.")
            if problem:
                for opened in views.values():
                    opened.close()
                if problem != "absent" and problem != self.reported_error:
                    print(problem)
                    self.reported_error = problem
                if problem == "absent" and self.connected:
                    print("Game closed. Waiting for it to come back.")
                    self.connected = False
                return False
            rounded = -(-page["size_bytes"] // MEMORY_PAGE) * MEMORY_PAGE
            if view.size > rounded and not self.warned_size:
                print(f"Warning: {page['mapping']} is {view.size} bytes, larger than the {page['size_bytes']} in the "
                      "format. The game may have changed its layout, so check the captured values.")
                self.warned_size = True
        self.views = views
        self.reported_error = None
        self.last_change = time.monotonic()
        if not self.connected:
            print(f"Connected to {self.describe()}")
            self.connected = True
        return True

    def close_views(self):
        for view in self.views.values():
            view.close()
        self.views = {}

    def record_start(self):
        index = self.views[self.record["page"]].read(self.record["index_offset"], 1)[0]
        if index >= self.record["max_records"]:
            return None
        return self.record["array_offset"] + self.record["stride"] * index

    def read(self):
        if not self.views and not self.open_views():
            time.sleep(1)
            return None
        record_start = self.record_start() if self.record else 0
        if record_start is None:
            time.sleep(self.poll)
            return None

        page, offset, layout, is_record = self.plans[self.update_field]
        at = offset + record_start if is_record else offset
        update = self.views[page].read(at, layout.size)
        if update == self.last_update:
            if time.monotonic() - self.last_change > STALE_SECONDS:
                self.close_views()
            time.sleep(self.poll)
            return None
        self.last_update = update
        self.last_change = time.monotonic()

        def snapshot():
            return [self.views[b["page"]].read(b["start"] + (record_start if b["record"] else 0),
                                               b["end"] - b["start"]) for b in self.blocks]

        data = snapshot()
        for _ in range(TORN_READ_RETRIES):
            again = snapshot()
            if again == data:
                break
            self.torn_reads += 1
            data = again
        row = [None] * len(self.format.fields)
        for block, raw in zip(self.blocks, data):
            for member_offset, member_layout, index in block["members"]:
                row[index] = member_layout.unpack_from(raw, member_offset - block["start"])[0]
        return self.format.finish_row(row)

    def status(self):
        state = "connected" if self.connected else "waiting for the game"
        return f"Shared memory: {state}. Reads retried because the game was mid-write: {self.torn_reads}"

    def close(self):
        self.close_views()


class SelfDescribedMemoryCapture:
    """capture.method "self_described_memory": iRacing's mapping, which lists each variable's location at runtime.

    Layout: a header, a variable table, and up to 4 buffers the sim cycles through. Fields are matched by name.
    """

    HEADER = struct.Struct("<10i")  # ver, status, tickRate, sessionInfo x3, numVars, varHeaderOffset, numBuf, bufLen
    VAR_HEADER_SIZE = 144
    BUFFER_TABLE_OFFSET = 48
    BUFFER_ENTRY_SIZE = 16
    MAX_BUFFERS = 4
    STATUS_CONNECTED = 1
    TYPE_CODES = {0: "c", 1: "?", 2: "i", 3: "I", 4: "f", 5: "d"}

    def __init__(self, packet_format, spec):
        self.format = packet_format
        self.mapping = spec.get("mapping")
        if not self.mapping:
            raise FormatError("capture is missing 'mapping'")
        self.poll = spec.get("poll_interval_ms", 2) / 1000
        for field in packet_format.fields:
            if field["struct"] not in ("?", "i", "I", "f", "d"):
                raise FormatError(f"Field {field['name']}: this capture method only reads ? i I f d values")
        self.view = None
        self.connected = False
        self.table_key = None
        self.plan = []
        self.blocked = None
        self.last_report = None
        self.last_tick = None
        self.last_change = 0
        self.missing = []

    def describe(self):
        return f"shared memory {self.mapping}"

    def open(self):
        pass

    def open_view(self):
        view = MappedView(self.mapping)
        if not view or view.size < self.BUFFER_TABLE_OFFSET + self.MAX_BUFFERS * self.BUFFER_ENTRY_SIZE:
            view.close()
            if self.connected:
                print("Game closed. Waiting for it to come back.")
                self.connected = False
            return False
        self.view = view
        self.table_key = None
        self.last_change = time.monotonic()
        if not self.connected:
            print(f"Connected to {self.describe()}")
            self.connected = True
        return True

    def close_view(self):
        if self.view:
            self.view.close()
        self.view = None

    def load_table(self, num_vars, table_offset):
        """Matches the format's fields against the sim's variable table."""
        available = {}
        for i in range(num_vars):
            raw = self.view.read(table_offset + i * self.VAR_HEADER_SIZE, 48)
            var_type, offset, _ = struct.unpack_from("<3i", raw)
            name = raw[16:48].split(b"\0")[0].decode("ascii", "replace")
            available[name] = (self.TYPE_CODES.get(var_type), offset)

        plan, missing, wrong_type = [], [], []
        for index, field in enumerate(self.format.fields):
            found = available.get(field["name"])
            if not found:
                missing.append(field)
            elif found[0] != field["struct"]:
                wrong_type.append(field)
            else:
                plan.append((index, found[1], struct.Struct("<" + field["struct"])))
        required = [f["name"] for f in missing + wrong_type if f.get("required")]
        if required:
            message = f"Not capturing: the sim does not provide required fields {', '.join(required)}"
            if message != self.blocked:
                print(message)
            self.blocked = message
            return
        report = f"{len(plan)} of {len(self.format.fields)} variables available from the sim; the rest will be NULL."
        if wrong_type:
            report += " Different type than the format says: " + ", ".join(f["name"] for f in wrong_type)
        if report != self.last_report:  # the table is reloaded each time an idle sim's mapping is reopened
            print(report)
            self.last_report = report
        self.missing = [f["name"] for f in missing + wrong_type]
        self.plan = plan
        self.blocked = None

    def read(self):
        if not self.view and not self.open_view():
            time.sleep(1)
            return None
        if time.monotonic() - self.last_change > STALE_SECONDS:
            self.close_view()
            time.sleep(self.poll)
            return None
        header = self.HEADER.unpack(self.view.read(0, self.HEADER.size))
        status, num_vars, table_offset, num_buffers, buffer_length = header[1], *header[6:]
        if not status & self.STATUS_CONNECTED or not 0 < num_buffers <= self.MAX_BUFFERS:
            time.sleep(self.poll)
            return None

        key = (num_vars, table_offset, num_buffers, buffer_length)
        if key != self.table_key:
            self.table_key = key
            self.load_table(num_vars, table_offset)
        if self.blocked:
            time.sleep(self.poll)
            return None

        def buffer_entry(i):
            return struct.unpack("<2i", self.view.read(self.BUFFER_TABLE_OFFSET + i * self.BUFFER_ENTRY_SIZE, 8))

        newest = max(range(num_buffers), key=lambda i: buffer_entry(i)[0])
        tick, buffer_offset = buffer_entry(newest)
        if tick == self.last_tick:
            time.sleep(self.poll)
            return None
        raw = self.view.read(buffer_offset, buffer_length)
        if buffer_entry(newest)[0] != tick:  # the sim reused this buffer during the read
            return None
        self.last_tick = tick
        self.last_change = time.monotonic()
        row = [None] * len(self.format.fields)
        for index, offset, layout in self.plan:
            if offset + layout.size <= buffer_length:
                row[index] = layout.unpack_from(raw, offset)[0]
        return self.format.finish_row(row)

    def status(self):
        if self.blocked:
            return self.blocked
        state = "connected" if self.connected else "waiting for the sim"
        return f"Shared memory: {state}. Fields not provided by the sim: {len(self.missing)}"

    def close(self):
        self.close_view()


CAPTURE_METHODS = {
    "udp": UdpCapture,
    "shared_memory": SharedMemoryCapture,
    "self_described_memory": SelfDescribedMemoryCapture,
}


def prompt_format():
    """Ask for a format file until a valid one is given. A bare filename also looks next to this script."""
    while True:
        path = input("Format JSON file: ").strip().strip('"')
        if not path:
            continue
        if not os.path.isfile(path) and os.path.isfile(os.path.join(SCRIPT_DIR, path)):
            path = os.path.join(SCRIPT_DIR, path)
        try:
            return PacketFormat(path)
        except FormatError as e:
            print(f"Bad format file {path}: {e}")


def check_zerotier(server_ip):
    """Exit unless the ZeroTier service is running and an adapter is up on the server's subnet."""
    # zerotier-cli needs admin rights, so this reads the service and adapter state instead
    script = (
        "$service = (Get-Service ZeroTierOneService -ErrorAction SilentlyContinue).Status;"
        "$adapters = @(Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*ZeroTier*' } | ForEach-Object {"
        " $ips = @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |"
        " ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength });"
        " [pscustomobject]@{ name = $_.Name; status = [string]$_.Status; ips = $ips } });"
        "ConvertTo-Json -Depth 3 -Compress -InputObject @{ service = [string]$service; adapters = $adapters }"
    )
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, text=True, timeout=30)
        state = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as e:
        sys.exit(f"Could not read ZeroTier state: {e}")

    if state["service"] != "Running":
        sys.exit(f"ZeroTier is not connected: the service is {state['service'] or 'not installed'}.")
    adapters = state["adapters"] or []
    up = [adapter for adapter in adapters if adapter["status"] == "Up"]
    if not up:
        sys.exit("ZeroTier is not connected: no ZeroTier network adapter is up. Join the network and try again.")

    server = ipaddress.ip_address(server_ip)
    for adapter in up:
        for ip in adapter["ips"] or []:
            if server in ipaddress.ip_interface(ip).network:
                print(f"ZeroTier connected: {adapter['name']} at {ip}")
                return
    sys.exit(f"ZeroTier is running, but no adapter has an address on the same network as {server_ip}.")


def connect_database(database):
    """Ask for a login until the server accepts one. Exit with the reason on any other failure."""
    try:
        socket.create_connection((DB_HOST, DB_PORT), timeout=5).close()
    except OSError as e:
        sys.exit(f"Can't reach MySQL at {DB_HOST}:{DB_PORT} ({e}). Check that the server is on, listening on "
                 f"its ZeroTier address (bind-address), and that its firewall allows port {DB_PORT}.")
    while True:
        user = input("MySQL username: ").strip()
        if not user:
            continue
        password = getpass.getpass("MySQL password: ")
        try:
            db = mysql.connector.connect(host=DB_HOST, port=DB_PORT, user=user, password=password,
                                         database=database, connection_timeout=5)
        except mysql.connector.Error as e:
            if e.errno == ACCESS_DENIED:
                print(f"Login rejected: {e.msg}")
                continue
            sys.exit(f"MySQL at {DB_HOST}:{DB_PORT} refused the connection: {e}")
        print(f"Connected to MySQL at {DB_HOST}:{DB_PORT}, database {database}")
        return db


def clean_session_name(raw):
    return re.sub(r"[^A-Za-z0-9_]+", "_", raw.strip()).strip("_")


class Session:
    def __init__(self, name, table, csv_path, outfile, writer):
        self.name = name
        self.table = table
        self.csv_path = csv_path
        self.outfile = outfile
        self.writer = writer
        self.started = time.time()
        self.rows = 0
        self.announced = False


class Recorder:
    def __init__(self, packet_format, db):
        self.format = packet_format
        self.db = db
        self.session = None
        self.pending = []
        self.state_lock = threading.Lock()  # guards session and pending
        self.db_lock = threading.Lock()  # guards the database connection
        self.stop_event = threading.Event()
        self.last_db_error = None
        self.last_capture_error = None

        self.capture = packet_format.capture
        self.capture.open()
        self.threads = [threading.Thread(target=self.capture_loop, daemon=True),
                        threading.Thread(target=self.flush_loop, daemon=True)]

    def run(self):
        for thread in self.threads:
            thread.start()
        print(f"Capturing {self.format.name} from {self.capture.describe()} ({len(self.format.names)} fields)")
        print("Commands: start <name> | end | status | quit")
        try:
            self.command_loop()
        except (KeyboardInterrupt, EOFError):
            # Not a quit command, so the session is left in the working table rather than saved
            if self.session:
                print(f"\nStopped without quit. Data stays in {self.format.working_table} until the next session "
                      f"starts; the CSV is at {self.session.csv_path}")
        self.shutdown()

    def command_loop(self):
        while True:
            parts = input("> ").strip().split(None, 1)
            if not parts:
                continue
            command, argument = parts[0].lower(), parts[1] if len(parts) > 1 else ""
            if command == "start":
                self.start_session(argument)
            elif command == "end":
                self.end_session()
            elif command == "status":
                self.print_status()
            elif command in ("quit", "exit"):
                if self.session:
                    self.end_session()
                return
            else:
                print("Commands: start <name> | end | status | quit")

    def start_session(self, raw_name):
        if self.session:
            print(f"Session '{self.session.name}' is still running. Enter end first.")
            return
        name = clean_session_name(raw_name or input("Session name: "))
        if not name:
            print("A session needs a name made of letters or numbers.")
            return

        prefix = f"session_{datetime.now().strftime('%y%m%d_%H%M%S')}_"
        name = name[:MAX_TABLE_NAME - len(prefix)].rstrip("_")
        table = prefix + name
        working = self.format.working_table
        try:
            with self.db_lock:
                self.db.ping(reconnect=True, attempts=1, delay=0)
                with self.db.cursor() as cursor:
                    cursor.execute(f"DROP TABLE IF EXISTS `{working}`")
                    cursor.execute(self.format.create_table_sql(working))
                self.db.commit()
        except mysql.connector.Error as e:
            print(f"Could not create {working}: {e}")
            return

        csv_path = os.path.join(self.format.csv_dir, table + ".csv")
        try:
            os.makedirs(self.format.csv_dir, exist_ok=True)
            outfile = open(csv_path, "w", buffering=1, newline="")
        except OSError as e:
            print(f"Could not create the CSV: {e}")
            return
        writer = csv.writer(outfile)
        writer.writerow(self.format.names)

        with self.state_lock:
            self.pending = []
            self.session = Session(name, table, csv_path, outfile, writer)
        print(f"Session '{name}' started. Waiting for telemetry. Enter end to finish it.")

    def end_session(self):
        with self.state_lock:
            session, self.session = self.session, None
        if not session:
            print("No session is running.")
            return
        session.outfile.close()

        for _ in range(3):
            if self.flush():
                break
            time.sleep(1)
        with self.state_lock:
            unsaved = len(self.pending)
            self.pending = []
        if unsaved:
            print(f"Session '{session.name}' could not be saved to MySQL: {unsaved} rows were not inserted and the "
                  f"table was not renamed. Every row is in the CSV: {session.csv_path}")
            return

        working = self.format.working_table
        try:
            with self.db_lock:
                self.db.ping(reconnect=True, attempts=1, delay=0)
                with self.db.cursor() as cursor:
                    cursor.execute(f"SELECT COUNT(*) FROM `{working}`")
                    table_rows = cursor.fetchone()[0]
                    cursor.execute(f"RENAME TABLE `{working}` TO `{session.table}`")
                self.db.commit()
        except mysql.connector.Error as e:
            print(f"Could not rename {working} to {session.table}: {e}. The data stays in {working} until the next "
                  f"session starts. Every row is in the CSV: {session.csv_path}")
            return
        print(f"Session '{session.name}' saved: {session.rows} CSV rows at {session.csv_path}, "
              f"{table_rows} rows in table {session.table}")

    def print_status(self):
        session = self.session
        if session:
            print(f"Session '{session.name}': {session.rows} rows in {time.time() - session.started:.0f}s")
        else:
            print("No session is running.")
        capture_status = self.capture.status()
        if capture_status:
            print(capture_status)

    def capture_loop(self):
        while not self.stop_event.is_set():
            try:
                values = self.capture.read()
            except (OSError, ValueError, struct.error) as e:
                if str(e) != self.last_capture_error:
                    print(f"Capture error, will keep trying: {e}")
                    self.last_capture_error = str(e)
                time.sleep(1)
                continue
            if values is None:
                continue
            if not self.format.is_active(values):
                continue
            with self.state_lock:
                session = self.session
                if not session:
                    continue
                session.writer.writerow(self.format.csv_row(values))
                session.rows += 1
                self.pending.append(self.format.sql_row(values))
                if not session.announced:
                    session.announced = True
                    print(f"Capturing telemetry for session '{session.name}'")

    def flush_loop(self):
        while not self.stop_event.wait(FLUSH_INTERVAL):
            self.flush()

    def flush(self):
        """Insert buffered rows. Returns False if they're still waiting because the connection is down."""
        with self.db_lock:
            with self.state_lock:
                rows, self.pending = self.pending, []
            if not rows:
                return True
            try:
                self.db.ping(reconnect=True, attempts=1, delay=0)
                with self.db.cursor() as cursor:
                    cursor.executemany(self.format.insert_sql(self.format.working_table), rows)
                self.db.commit()
            except mysql.connector.Error as e:
                if self.db.is_connected():
                    # The server rejected the data, so retrying would fail forever
                    print(f"MySQL rejected {len(rows)} rows, which are only in the CSV: {e}")
                    self.db.rollback()
                    return True
                if str(e) != self.last_db_error:
                    print(f"Lost connection to MySQL, will keep retrying: {e}")
                    self.last_db_error = str(e)
                with self.state_lock:
                    self.pending = rows + self.pending
                return False
            if self.last_db_error:
                print("MySQL connection restored.")
                self.last_db_error = None
            return True

    def shutdown(self):
        session = self.session
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=2)
        if session:  # stopped without quit: keep what was captured in the working table
            self.flush()
            session.outfile.close()
        self.capture.close()
        self.db.close()


def main():
    try:
        packet_format = prompt_format()
        check_zerotier(DB_HOST)
        db = connect_database(packet_format.database)
    except (KeyboardInterrupt, EOFError):
        sys.exit("\nCancelled.")
    try:
        recorder = Recorder(packet_format, db)
    except OSError as e:
        db.close()
        sys.exit(f"Could not start capture from {packet_format.capture.describe()}: {e}")
    recorder.run()


if __name__ == "__main__":
    main()
