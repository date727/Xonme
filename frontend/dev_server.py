"""Local development server for the static frontend.

Disables HTTP caching so a normal browser refresh always retrieves the latest
HTML, CSS, and JavaScript after local edits.
"""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class NoCacheRequestHandler(SimpleHTTPRequestHandler):
    """Serve static files without allowing the browser to cache them."""

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, max-age=0, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 5500), NoCacheRequestHandler)
    print("Frontend development server: http://127.0.0.1:5500")
    print("Caching is disabled; refresh the browser after saving a file.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()
