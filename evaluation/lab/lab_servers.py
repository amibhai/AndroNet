#!/usr/bin/env python3
"""Throwaway protocol endpoints for generating labelled traffic. Binds to loopback only."""
import http.server
import socket
import socketserver
import threading
import urllib.parse

PAGE = (b"<!DOCTYPE html>\n<html><head><title>Inventory</title></head>"
        b"<body><h1>Inventory</h1><p>Item list</p><a href='/item.php?id=1'>item 1</a></body></html>\n")


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41"
    sys_version = ""

    def log_message(self, *args):
        pass

    def _reply(self, code=200, body=PAGE, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(path.query)
        if path.path.endswith((".exe", ".scr", ".ps1", ".bat", ".dll", ".jar")):
            self._reply(200, b"MZ" + bytes(range(256)) * 4, "application/octet-stream")
        elif path.path.startswith("/item.php"):
            value = (query.get("id") or ["1"])[0]
            if "'" in value:
                self._reply(500, b"<html><b>Warning</b>: You have an error in your SQL syntax near '" + value[:40].encode("latin-1", "replace") + b"'</html>")
            else:
                self._reply(200, b"<!DOCTYPE html><html><body>item " + value[:40].encode("latin-1", "replace") + b"</body></html>")
        elif path.path in ("/", "/index.html", "/activity", "/__utm.gif"):
            self._reply()
        else:
            self._reply(404, b"<html><body>not found</body></html>")

    do_HEAD = do_GET
    do_OPTIONS = do_GET
    do_DELETE = do_GET
    do_PUT = do_GET
    do_TRACE = do_GET

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._reply()


class ReuseHTTP(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_http(port):
    srv = ReuseHTTP(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class LineHandler(socketserver.StreamRequestHandler):
    """One banner, then a canned reply per received line."""
    banner = b""
    replies = {}
    default = b""

    def handle(self):
        if self.banner:
            self.wfile.write(self.banner)
        for line in self.rfile:
            for key, reply in self.replies.items():
                if key in line:
                    self.wfile.write(reply)
                    break
            else:
                if self.default:
                    self.wfile.write(self.default)


class ReuseTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_lines(port, banner=b"", replies=None, default=b""):
    cls = type("H%d" % port, (LineHandler,), {"banner": banner, "replies": replies or {}, "default": default})
    srv = ReuseTCP(("127.0.0.1", port), cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class SinkHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while self.request.recv(65536):
                pass
        except OSError:
            pass


def start_sink(port):
    srv = ReuseTCP(("127.0.0.1", port), SinkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def try_port(preferred, fallback):
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            return fallback
