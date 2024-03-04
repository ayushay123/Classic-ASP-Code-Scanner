import os
import re

class NoVulnerabilitiesFoundError(Exception):
    pass

class ASPCodeScanner:
    def __init__(self, directory, output_file):
        self.directory = directory
        self.output_file = output_file
        self.vulnerabilities_found = False

    def scan(self):
        with open(self.output_file, 'w') as output:
            for filename in os.listdir(self.directory):
                if filename.endswith(".asp"):
                    filepath = os.path.join(self.directory, filename)
                    with open(filepath, 'r') as file:
                        asp_code = file.read()
                        output.write(f"Scanning file: {filename}\n")
                        self.check_sql_injection(asp_code, filename, output)
                        self.check_xss(asp_code, filename, output)
                        self.check_sensitive_data_exposure(asp_code, filename, output)
                        self.check_command_injection(asp_code, filename, output)
                        self.check_insecure_authentication(asp_code, filename, output)
                        self.check_security_misconfiguration(asp_code, filename, output)
                        self.check_cross_site_tracing(asp_code, filename, output)
                        self.check_no_sql_injection(asp_code, filename, output)
                        # Add more vulnerability checks and remediation suggestions
        
        if not self.vulnerabilities_found:
            raise NoVulnerabilitiesFoundError("No vulnerabilities found in the scanned ASP files.")

    def check_sql_injection(self, code, filename, output):
        if re.search(r'(\bselect\b|\bupdate\b|\bdelete\b|\binsert\b).*(\bfrom\b|\bwhere\b).*', code, re.IGNORECASE):
            output.write(f"Potential SQL Injection found in file: {filename}\n")
            self.vulnerabilities_found = True
            vulnerable_code = self.get_vulnerable_code(code)
            output.write("===== Vulnerable Code Snippet =====\n")
            output.write(vulnerable_code + "\n")
            output.write("===== Remediation =====\n")
            output.write("# Use parameterized queries to prevent SQL injection.\n")
            output.write("# Sanitize and validate user inputs.\n")
            output.write("=" * 80 + "\n")

    def check_xss(self, code, filename, output):
        if re.search(r'<\s*script.*?>', code, re.IGNORECASE):
            output.write(f"Potential Cross-Site Scripting found in file: {filename}\n")
            self.vulnerabilities_found = True
            vulnerable_code = self.get_vulnerable_code(code)
            output.write("===== Vulnerable Code Snippet =====\n")
            output.write(vulnerable_code + "\n")
            output.write("===== Remediation =====\n")
            output.write("# Encode user inputs before displaying them in the HTML context.\n")
            output.write("# Use Content Security Policy (CSP) to mitigate XSS attacks.\n")
            output.write("=" * 80 + "\n")

    def check_sensitive_data_exposure(self, code, filename, output):
        if re.search(r'\bpassword\b|\bsecret\b', code, re.IGNORECASE):
            output.write(f"Potential Sensitive Data Exposure found in file: {filename}\n")
            self.vulnerabilities_found = True
            vulnerable_code = self.get_vulnerable_code(code)
            output.write("===== Vulnerable Code Snippet =====\n")
            output.write(vulnerable_code + "\n")
            output.write("===== Remediation =====\n")
            output.write("# Avoid storing sensitive data in plaintext.\n")
            output.write("# Encrypt sensitive data before storage.\n")
            output.write("=" * 80 + "\n")

    def check_command_injection(self, code, filename, output):
        if re.search(r'\bshell\b|\bexec\b|\bsystem\b', code, re.IGNORECASE):
            output.write(f"Potential OS Command Injection found in file: {filename}\n")
            self.vulnerabilities_found = True
            vulnerable_code = self.get_vulnerable_code(code)
            output.write("===== Vulnerable Code Snippet =====\n")
            output.write(vulnerable_code + "\n")
            output.write("===== Remediation =====\n")
            output.write("# Avoid using system/exec/shell commands with user input.\n")
            output.write("# If necessary, use secure APIs provided by the language/framework.\n")
            output.write("=" * 80 + "\n")

    def check_insecure_authentication(self, code, filename, output):
        if re.search(r'\blogin\b|\busername\b|\bpassword\b', code, re.IGNORECASE):
            output.write(f"Potential Insecure Authentication found in file: {filename}\n")
            self.vulnerabilities_found = True
            vulnerable_code = self.get_vulnerable_code(code)
            output.write("===== Vulnerable Code Snippet =====\n")
            output.write(vulnerable_code + "\n")
            output.write("===== Remediation =====\n")
            output.write("# Use strong encryption algorithms for storing passwords.\n")
            output.write("# Implement multi-factor authentication.\n")
            output.write("=" * 80 + "\n")

    def check_security_misconfiguration(self, code, filename, output):
        if re.search(r'\bdebug\b|\btrace\b|\berror\b', code, re.IGNORECASE):
            output.write(f"Potential Security Misconfiguration found in file: {filename}\n")
            self.vulnerabilities_found = True
            vulnerable_code = self.get_vulnerable_code(code)
            output.write("===== Vulnerable Code Snippet =====\n")
            output.write(vulnerable_code + "\n")
            output.write("===== Remediation =====\n")
            output.write("# Disable debugging and tracing in production environments.\n")
            output.write("# Properly handle errors and exceptions.\n")
            output.write("=" * 80 + "\n")

    def check_cross_site_tracing(self, code, filename, output):
        if re.search(r'trace\b.*?\=.*', code, re.IGNORECASE):
            output.write(f"Potential Cross-Site Tracing found in file: {filename}\n")
            self.vulnerabilities_found = True
            vulnerable_code = self.get_vulnerable_code(code)
            output.write("===== Vulnerable Code Snippet =====\n")
            output.write(vulnerable_code + "\n")
            output.write("===== Remediation =====\n")
            output.write("# Disable HTTP TRACE method.\n")
            output.write("# Use appropriate security headers to mitigate cross-site tracing attacks.\n")
            output.write("=" * 80 + "\n")

    def check_no_sql_injection(self, code, filename, output):
        if re.search(r'nosql\b\s*(?:where|and)\s*\b[^"]*\b[^"]*', code, re.IGNORECASE):
            output.write(f"Potential NoSQL Injection found in file: {filename}\n")
            self.vulnerabilities_found = True
            vulnerable_code = self.get_vulnerable_code(code)
            output.write("===== Vulnerable Code Snippet =====\n")
            output.write(vulnerable_code + "\n")
            output.write("===== Remediation =====\n")
            output.write("# Use parameterized queries or ORM libraries to interact with NoSQL databases.\n")
            output.write("# Sanitize and validate user inputs.\n")
            output.write("=" * 80 + "\n")

    def get_vulnerable_code(self, code):
        vulnerable_code = ""
        lines = code.split('\n')
        for line in lines:
            vulnerable_code += line + "\n"
        return vulnerable_code

# Example usage
if __name__ == "__main__":
    directory_path = r"D:\10.60.5.149\ecgc"
    output_file_path = r"D:\10.60.5.149\ecgc.txt"
    scanner = ASPCodeScanner(directory_path, output_file_path)
    try:
        scanner.scan()
    except NoVulnerabilitiesFoundError as e:
        print(e)
