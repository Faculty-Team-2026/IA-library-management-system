# Security Testing Guide - Updated December 5, 2025

## Quick Start

### Run All Security Tests
```powershell
cd d:\2-Mozakra\Projects\IA-library-management-system\scripts
.\security-tests.ps1
```

**Prerequisites:**
1. Backend must be running: `cd BackEnd && dotnet run`
2. Running on port 5205 (default)
3. PowerShell 5.0+ (Windows)

---

## Test Coverage

### 1. SQL Injection Tests (4 tests)
Tests various SQL injection payloads to verify input sanitization:
- `admin' OR '1'='1` (OR clause injection)
- `admin' --` (Comment bypass)
- `' UNION SELECT 1,2,3,4,5 --` (UNION-based injection)
- `admin' /*` (Comment variation)

**Expected Result:** All return `400 Bad Request` (PROTECTED ✅)

---

### 2. Dual-Layer Rate Limiting (1 test)
Tests both IP-based and username-based rate limiting:
- Makes 8 failed login attempts from same IP
- Expected: `429 Too Many Requests` on attempt 5+

**Configuration:**
- Max attempts per IP: 5
- Max attempts per username: 5
- Lockout duration: 15 minutes
- Returns minimum of both limits (stricter applies)

**Expected Result:** 429 response after 5 failed attempts (PROTECTED ✅)

---

### 3. Exponential Backoff Protection (1 test) **NEW**
Tests progressive login delays to slow down brute force:

**Expected Delay Sequence:**
```
Attempt 1: 0 seconds
Attempt 2: 0 seconds
Attempt 3: 1 second
Attempt 4: 2 seconds
Attempt 5: 4 seconds
Attempt 6: 8 seconds
Attempt 7+: 15 seconds (maximum)
```

**Purpose:** Makes rapid-fire brute force attacks extremely slow (7+ seconds for 5 attempts)

**Expected Result:** Progressive delays detected (PROTECTED ✅)

---

### 4. Multi-IP Account Support (1 test)
Tests that legitimate users can login from multiple locations:
- Same account successfully logs in from multiple IPs
- Each IP tracked independently
- Threat detection for suspicious patterns (10+ IPs = alert)

**Expected Result:** Both logins succeed (PROTECTED ✅)

---

### 5. Request Size Limit (1 test)
Tests protection against large payload DoS attacks:
- Sends 2MB JSON payload
- Expected: Rejection with `400` or `413` status

**Expected Result:** Large request blocked (PROTECTED ✅)

---

### 6. Input Validation (5 tests)
Tests XSS and injection attack prevention:
- `<script>alert('xss')</script>` (XSS Script Tag)
- `<img src=x onerror='alert(1)'>` (HTML Injection)
- `test@#$%^&*()` (Special Characters)
- `test' OR 1=1--` (SQL-like input)
- `javascript:alert(1)` (JavaScript URI)

**Expected Result:** All return `400` or `401` (PROTECTED ✅)

---

### 7. Null Safety / Input Validation (3 tests)
Tests handling of missing or invalid parameters:
- Empty username
- Empty password
- Null request body

**Expected Result:** All return `400 Bad Request` (PROTECTED ✅)

---

### 8. Admin Security Endpoints (4 tests) **NEW**
Tests authorization on monitoring endpoints:
- `GET /api/security/login-attempts/{username}` - Requires admin role
- `GET /api/security/active-ips/{username}` - Requires admin role
- `GET /api/security/login-delay` - Requires admin role
- `POST /api/security/reset-attempts/{username}` - Requires admin role

**Expected Result:** All return `401 Unauthorized` or `403 Forbidden` without valid admin token (PROTECTED ✅)

---

### 9. Concurrent Request Handling (1 test)
Tests server stability with 10 simultaneous requests:
- Verifies no crashes or race conditions
- Validates thread-safe rate limiting

**Expected Result:** All requests handled without errors (PROTECTED ✅)

---

## Test Results Interpretation

### Success Indicators
```
PROTECTED    = Security feature working correctly ✅
VULNERABLE   = Security issue detected ⚠️
WARNING      = Requires manual verification ⚠️
```

### Sample Output
```
Total Tests: 24
PROTECTED: 20 ✅
VULNERABLE: 0
WARNINGS: 4 ⚠️

All security tests passed!
```

---

## Manual Testing - Rate Limiting

### Test IP-Based Rate Limiting
```powershell
# Make 5 failed attempts from localhost
for ($i = 1; $i -le 8; $i++) {
    $body = @{username = "testuser"; password = "wrong"} | ConvertTo-Json
    
    try {
        Invoke-WebRequest -Uri "http://localhost:5205/api/auth/login" `
            -Method POST -ContentType "application/json" -Body $body -ErrorAction Stop
    } catch {
        Write-Host "Attempt $i: Status $($_.Exception.Response.StatusCode.value__)"
    }
    
    Start-Sleep -Milliseconds 300
}

# Expected Output:
# Attempt 1: Status 400 (Bad Request - Auth Failed)
# Attempt 2: Status 400 (Bad Request - Auth Failed)
# Attempt 3: Status 400 (Bad Request - Auth Failed)
# Attempt 4: Status 400 (Bad Request - Auth Failed)
# Attempt 5: Status 429 (Too Many Requests - RATE LIMIT!)
# Attempt 6: Status 429 (Too Many Requests - RATE LIMIT!)
# Attempt 7: Status 429 (Too Many Requests - RATE LIMIT!)
# Attempt 8: Status 429 (Too Many Requests - RATE LIMIT!)
```

---

## Manual Testing - Admin Endpoints with Token

### Get Admin Token
```powershell
$loginBody = @{
    username = "admin"
    password = "Admin@123456"
} | ConvertTo-Json

$loginResponse = Invoke-WebRequest -Uri "http://localhost:5205/api/auth/login" `
    -Method POST -ContentType "application/json" -Body $loginBody

$token = ($loginResponse.Content | ConvertFrom-Json).token
Write-Host "Token: $token"
```

### Check Login Attempts for User
```powershell
$headers = @{Authorization = "Bearer $token"}
Invoke-WebRequest -Uri "http://localhost:5205/api/security/login-attempts/testuser" `
    -Headers $headers -Method GET | Select-Object -ExpandProperty Content | ConvertFrom-Json | Format-List
```

**Sample Response:**
```json
{
    "username": "testuser",
    "ipAddress": "127.0.0.1",
    "remainingAttempts": 2,
    "isLockedOut": false,
    "timestamp": "2025-12-05T14:37:30Z"
}
```

### Check Active IPs for Account
```powershell
Invoke-WebRequest -Uri "http://localhost:5205/api/security/active-ips/admin" `
    -Headers $headers -Method GET | Select-Object -ExpandProperty Content | ConvertFrom-Json | Format-List
```

**Sample Response:**
```json
{
    "username": "admin",
    "activeIPCount": 2,
    "activeIPs": ["127.0.0.1", "192.168.1.1"],
    "hasCompromiseRisk": false,
    "maxConcurrentIPs": 10
}
```

### Reset Login Attempts (Emergency Admin Action)
```powershell
Invoke-WebRequest -Uri "http://localhost:5205/api/security/reset-attempts/testuser" `
    -Headers $headers -Method POST | Select-Object -ExpandProperty Content | ConvertFrom-Json | Format-List
```

---

## Logging Location

Security events are logged to the console output when backend runs:

```
WARN: Failed login attempt for user 'admin' from IP 127.0.0.1. IP attempts: 3/5, Username attempts: 3/5
ERROR: ⚠️ SECURITY ALERT: Multiple failed login attempts detected! Username: admin, IP: 127.0.0.1, IP attempts: 3, Username attempts: 3
WARN: IP 127.0.0.1 locked out - 5 attempts in 15 minutes
ERROR: ⚠️ SECURITY ALERT: Account 'admin' accessed from 11 different IPs in 24 hours...
CRITICAL: ⚠️ ADMIN ACTION: Login attempts reset for user 'admin' (IP: 127.0.0.1)...
```

---

## Performance Notes

- **Rate Limiting:** Checked before password validation (protects against username enumeration)
- **Exponential Backoff:** Applied progressively to slow down attacks
- **Thread Safety:** All operations protected with locks for concurrent request safety
- **Memory:** In-memory tracking (resets if service restarts)

---

## Next Steps

1. ✅ Run `./security-tests.ps1` to validate all protections
2. ✅ Review console logs for security events
3. ✅ Test admin endpoints with valid token (see examples above)
4. ✅ Monitor for account compromise alerts (10+ IPs)
5. ✅ Configure production logging destination

---

## Test Results File

After running tests, results are saved to:
```
scripts/security-test-results-YYYYMMDD-HHMMSS.json
```

Example:
```
scripts/security-test-results-20251205-143736.json
```

This file contains detailed results for each test including timestamp and status.

