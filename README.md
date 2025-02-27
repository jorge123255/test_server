# Security Test Server for Palo Alto NGFW

A comprehensive testing suite for Palo Alto Next-Generation Firewall (NGFW) security features. This server provides safe simulations of various security threats and attack patterns to verify NGFW configurations and policies.

## Features

### Basic Security Tests
- EICAR test file download (antivirus testing)
- Fake spyware simulation
- Ransomware behavior patterns
- File upload/download testing

### Web Attack Tests
- SQL injection patterns
- Cross-site scripting (XSS)
- Command injection
- Web shell simulation

### Advanced Threat Tests
- DNS tunneling simulation
- Command & Control (C2) patterns
- SSL/TLS vulnerability testing
- Protocol abuse detection

### Traffic Tests
- DoS/DDoS simulation
- Port scanning patterns
- Large file transfers
- Data exfiltration tests

## Setup

1. **Prerequisites**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. **Run the Server**
```bash
python app.py
```
Server will be available at `http://0.0.0.0:5000`

## Usage

### Network Setup
```
[Client] -> [Palo Alto NGFW] -> [This Test Server]
```

### Testing Methods

1. **Manual Testing**
   - Visit `http://[server-ip]:5000`
   - Use individual test links
   - Monitor NGFW logs for each test

2. **Automated Testing**
   - Click "Run All Tests"
   - View results in real-time
   - Check test logs

3. **Verification**
   - Use "Expected Alerts" page
   - Compare with NGFW logs
   - Check test logs in `test_logs/test_server.log`

## Test Categories

### 🛡️ Basic Security Tests
- Antivirus detection (EICAR)
- Spyware patterns
- Ransomware behavior
- Malicious file types

### 🌐 Web Attack Tests
- SQL injection payloads
- XSS detection
- Command injection
- Web shell patterns

### 🔬 Advanced Threats
- DNS tunneling
- C2 communication
- SSL vulnerabilities
- Protocol violations

### 🔄 Traffic Tests
- DoS simulation
- Port scanning
- Large file transfers
- Data filtering

## Expected NGFW Alerts

### High Severity
- EICAR virus detection
- SQL/Command injection
- Web shell detection
- C2 communication

### Medium Severity
- Suspicious JavaScript
- DNS tunneling
- Port scanning
- DoS patterns

### Low Severity
- Large file transfers
- Protocol anomalies
- Policy violations

## Logging

- All tests are logged to `test_logs/test_server.log`
- Includes timestamp, client IP, and results
- Automated test results are JSON-formatted

## Security Note

All tests are completely safe simulations:
- No actual malware
- No real exploits
- No system modifications
- Safe for testing environments

## Best Practices

1. **Testing Environment**
   - Use in isolated network
   - Test with production NGFW policies
   - Monitor all security logs

2. **Verification Process**
   - Run complete test suite
   - Check all alert categories
   - Verify policy enforcement
   - Document results

3. **Regular Testing**
   - After policy changes
   - During security audits
   - Periodic verification

## Troubleshooting

### Common Issues
1. **Connection Refused**
   - Check NGFW rules
   - Verify network routing
   - Check server is running

2. **Missing Alerts**
   - Verify NGFW policies
   - Check logging settings
   - Confirm test execution

3. **Failed Tests**
   - Check server logs
   - Verify network connectivity
   - Review NGFW configuration

## Contributing

Feel free to submit issues and enhancement requests. 