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
                        self.check_host_header_injection(asp_code, filename, output)
                        self.check_referer_based_injection(asp_code, filename, output)
                        self.check_missing_security_header(asp_code, filename, output)
                        self.check_insecure_http_method(asp_code, filename, output)
                        self.check_xxe(asp_code, filename, output)
                        self.check_nosql_injection(asp_code, filename, output)
                        self.check_cross_site_tracing(asp_code, filename, output)
                        # Add more checks as needed
        
        if not self.vulnerabilities_found:
            raise NoVulnerabilitiesFoundError("No vulnerabilities found in the scanned ASP files.")

    def check_sql_injection(self, code, filename, output):
        if re.search(r'(\bselect\b|\bupdate\b|\bdelete\b|\binsert\b).*(\bfrom\b|\bwhere\b).*', code, re.IGNORECASE):
            output.write(f"Potential SQL Injection found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "SQL Injection", "# Use parameterized queries to prevent SQL injection.\n# Sanitize and validate user inputs.\n")

    def check_xss(self, code, filename, output):
        if re.search(r'<\s*script.*?>', code, re.IGNORECASE):
            output.write(f"Potential Cross-Site Scripting found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "Cross-Site Scripting", "# Encode user inputs before displaying them in the HTML context.\n# Use Content Security Policy (CSP) to mitigate XSS attacks.\n")

    def check_sensitive_data_exposure(self, code, filename, output):
        if re.search(r'\bpassword\b|\bsecret\b', code, re.IGNORECASE):
            output.write(f"Potential Sensitive Data Exposure found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "Sensitive Data Exposure", "# Avoid storing sensitive data in plaintext.\n# Encrypt sensitive data before storage.\n")

    def check_command_injection(self, code, filename, output):
        if re.search(r'\bshell\b|\bexec\b|\bsystem\b', code, re.IGNORECASE):
            output.write(f"Potential Command Injection found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "Command Injection", "# Avoid using system/exec/shell commands with user input.\n# If necessary, use secure APIs provided by the language/framework.\n")

    def check_insecure_authentication(self, code, filename, output):
        if re.search(r'\blogin\b|\busername\b|\bpassword\b', code, re.IGNORECASE):
            output.write(f"Potential Insecure Authentication found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "Insecure Authentication", "# Use strong encryption algorithms for storing passwords.\n# Implement multi-factor authentication.\n")

    def check_security_misconfiguration(self, code, filename, output):
        if re.search(r'\bdebug\b|\btrace\b|\berror\b', code, re.IGNORECASE):
            output.write(f"Potential Security Misconfiguration found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "Security Misconfiguration", "# Disable debugging and tracing in production environments.\n# Properly handle errors and exceptions.\n")

    def check_host_header_injection(self, code, filename, output):
        if re.search(r'host:\s*<', code, re.IGNORECASE):
            output.write(f"Potential Host Header Injection found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "Host Header Injection", "# Validate and sanitize all incoming HTTP headers.\n# Avoid passing unsanitized user input to sensitive functions.\n")

    def check_referer_based_injection(self, code, filename, output):
        if re.search(r'referer:\s*<', code, re.IGNORECASE):
            output.write(f"Potential Referer-Based Injection found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "Referer-Based Injection", "# Validate and sanitize all incoming HTTP headers.\n# Avoid passing unsanitized user input to sensitive functions.\n")

    def check_missing_security_header(self, code, filename, output):
        if not re.search(r'strict-transport-security', code, re.IGNORECASE):
            output.write(f"Missing Security Header found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "Missing Security Header", "# Implement proper security headers including Strict-Transport-Security.\n# Use Content Security Policy (CSP) to mitigate XSS attacks.\n")

    def check_insecure_http_method(self, code, filename, output):
        if re.search(r'<\s*(?:form|a|area)\b.*\bmethod=["\']?\bget\b', code, re.IGNORECASE):
            output.write(f"Insecure HTTP Method found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "Insecure HTTP Method", "# Avoid using HTTP GET method for sensitive operations.\n# Use HTTP POST method with CSRF protection.\n")

    def check_xxe(self, code, filename, output):
        if re.search(r'<\s*\!DOCTYPE\s+[^>]*[\[\><"]+[^>]*\[\><"\']+', code, re.IGNORECASE):
            output.write(f"Potential XML External Entity (XXE) Injection found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "XML External Entity (XXE) Injection", "# Disable external entity parsing in XML parsers.\n# Use libraries or frameworks that provide protection against XXE attacks.\n")

    def check_nosql_injection(self, code, filename, output):
        if re.search(r'nosql\b\s*(?:where|and)\s*\b[^"]*\b[^"]*', code, re.IGNORECASE):
            output.write(f"Potential NoSQL Injection found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "NoSQL Injection", "# Use parameterized queries or ORM libraries to interact with NoSQL databases.\n# Sanitize and validate user inputs.\n")

    def check_cross_site_tracing(self, code, filename, output):
        if re.search(r'trace\b.*?\=.*', code, re.IGNORECASE):
            output.write(f"Potential Cross-Site Tracing found in file: {filename}\n")
            self.vulnerabilities_found = True
            self.save_vulnerable_code(code, output, "Cross-Site Tracing", "# Disable HTTP TRACE method.\n# Use appropriate security headers to mitigate cross-site tracing attacks.\n")

    def save_vulnerable_code(self, code, output, vulnerability_name, remediation):
        lines = code.split('\n')
        output.write(f"===== Vulnerable Code Snippet ({vulnerability_name}) =====\n")
        for line in lines:
            if re.search(r'(\bselect\b|\bupdate\b|\bdelete\b|\binsert\b).*(\bfrom\b|\bwhere\b).*', line, re.IGNORECASE):
                output.write(f"{line}  # Remediation: {remediation}\n")
        output.write("=" * 80 + "\n")

# Example usage
if __name__ == "__main__":
    directory_path = r"D:\10.60.5.149\ecgc"
    output_file_path = r"D:\10.60.5.149\ecgcoutput_file.txt"
    scanner = ASPCodeScanner(directory_path, output_file_path)
    try:
        scanner.scan()
    except NoVulnerabilitiesFoundError as e:
        print(e)
