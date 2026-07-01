import http.server
import socketserver
import json
import os
import sys
import subprocess

PORT = 8000
DIRECTORY = "."

# Global state to track background triage pipeline execution
triage_process = None

class DashboardHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        global triage_process
        if self.path == '/api/verdicts':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            verdicts = []
            verdicts_dir = "verdicts"
            if os.path.exists(verdicts_dir):
                for filename in os.listdir(verdicts_dir):
                    if filename.endswith(".json"):
                        filepath = os.path.join(verdicts_dir, filename)
                        try:
                            with open(filepath, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                                verdicts.append(data)
                        except Exception as e:
                            print(f"Error reading {filepath}: {e}", file=sys.stderr)
            
            # Sort verdicts by processed_at or event_id
            verdicts.sort(key=lambda x: x.get("processed_at", ""), reverse=True)
            self.wfile.write(json.dumps(verdicts).encode('utf-8'))
            
        elif self.path == '/api/triage/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            status_data = {"status": "idle"}
            if triage_process is not None:
                poll = triage_process.poll()
                if poll is None:
                    status_data = {"status": "running"}
                else:
                    status_data = {"status": "completed", "exit_code": poll}
                    triage_process = None # Reset
            
            self.wfile.write(json.dumps(status_data).encode('utf-8'))
            
        elif self.path == '/' or self.path == '':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            try:
                with open('dashboard.html', 'r', encoding='utf-8') as f:
                    self.wfile.write(f.read().encode('utf-8'))
            except Exception as e:
                self.wfile.write(f"<h3>Error loading dashboard.html: {e}</h3>".encode('utf-8'))
        else:
            super().do_GET()

    def do_POST(self):
        global triage_process
        if self.path == '/api/triage':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            if triage_process is not None and triage_process.poll() is None:
                self.wfile.write(json.dumps({"status": "already_running"}).encode('utf-8'))
                return
            
            try:
                # Trigger the triage pipeline subprocess in the background
                triage_process = subprocess.Popen(
                    [sys.executable, "triage_pipeline.py", "--input", "complex_test_alerts.json", "--mock-enrichment"]
                )
                self.wfile.write(json.dumps({"status": "started"}).encode('utf-8'))
            except Exception as e:
                self.wfile.write(json.dumps({"status": "failed", "error": str(e)}).encode('utf-8'))
                
        elif self.path == '/api/remediate':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            try:
                params = json.loads(post_data)
                event_id = params.get("event_id")
                if not event_id:
                    self.wfile.write(json.dumps({"status": "error", "message": "Missing event_id"}).encode('utf-8'))
                    return
                
                # Locate and modify the local verdict JSON file
                verdicts_dir = "verdicts"
                found = False
                for filename in os.listdir(verdicts_dir):
                    if filename.endswith(".json"):
                        filepath = os.path.join(verdicts_dir, filename)
                        with open(filepath, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        if data.get("event_id") == event_id:
                            # Add remediation status tag
                            data["remediation_status"] = "applied"
                            with open(filepath, 'w', encoding='utf-8') as f:
                                json.dump(data, f, indent=2)
                            found = True
                            break
                
                if found:
                    self.wfile.write(json.dumps({"status": "remediated"}).encode('utf-8'))
                else:
                    self.wfile.write(json.dumps({"status": "error", "message": "Alert JSON not found"}).encode('utf-8'))
            except Exception as e:
                self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", PORT), DashboardHTTPHandler) as httpd:
        print(f"============================================================")
        print(f" Dashboard server running at: http://localhost:{PORT}")
        print(f" Press Ctrl+C to terminate.")
        print(f"============================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard server...")
            httpd.server_close()

if __name__ == "__main__":
    main()
