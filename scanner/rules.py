import re


def check_file(file_path):
    issues = []

    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return issues

    for line_no, line in enumerate(lines, start=1):
        code = line.strip()

        # 1. Hardcoded password
        if re.search(r'password\s*=\s*["\'].+["\']', code, re.IGNORECASE):
            issues.append(("HARDCODED_PASSWORD", line_no, code))

        # 2. Hardcoded secrets
        if re.search(r'(api_key|secret|token)\s*=\s*["\'].+["\']', code, re.IGNORECASE):
            issues.append(("HARDCODED_SECRET", line_no, code))

        # 3. eval usage
        if "eval(" in code:
            issues.append(("DANGEROUS_EVAL", line_no, code))

        # 4. exec usage
        if "exec(" in code:
            issues.append(("DANGEROUS_EXEC", line_no, code))

        # 5. SQL Injection risk
        if "execute(" in code and "+" in code:
            issues.append(("SQL_INJECTION_RISK", line_no, code))

        # 6. Command Injection
        if "os.system(" in code:
            issues.append(("COMMAND_INJECTION", line_no, code))

        # 7. Unsafe subprocess
        if "subprocess.Popen(" in code or "subprocess.call(" in code:
            issues.append(("UNSAFE_SUBPROCESS", line_no, code))

        # 8. Unsafe deserialization
        if "pickle.load(" in code:
            issues.append(("UNSAFE_DESERIALIZATION", line_no, code))

        # 9. Debug mode
        if "debug=True" in code or "debug = True" in code:
            issues.append(("DEBUG_MODE_ON", line_no, code))

        # 10. Insecure HTTP
        if "http://" in code:
            issues.append(("INSECURE_HTTP", line_no, code))

        # 11. Hidden exception
        if re.search(r'except\s*:.*pass', code):
            issues.append(("HIDDEN_EXCEPTION", line_no, code))

        # 12. Weak random
        if "random.random(" in code:
            issues.append(("WEAK_RANDOM_USAGE", line_no, code))

    return issues