# Common Web Vulnerabilities to Check on a DAST Scan

As part of the Application Security Team, identifying and remediating common vulnerabilities is critical to ensuring the security of our web applications. Below is a list of common web vulnerabilities that may be detected during a DAST (Dynamic Application Security Testing) scan, with details on how they manifest, their potential risks, and guidance for remediation.

## 1. SQL Injection (SQLi)

- **Description:** SQL Injection occurs when unsanitized user input is included in SQL queries. This allows attackers to manipulate queries, gain unauthorized access to databases, or alter database content.
- **Example:**
    ```sql
    SELECT * FROM users WHERE username = 'admin' AND password = 'password';
    ```
    In a vulnerable app, an attacker could input `' OR '1'='1` to bypass authentication:
    ```sql
    SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1';
    ```
- **Risks:** Unauthorized access to sensitive data, modification of data, and even full database compromise.
- **Remediation:** 
    - Always use parameterized queries or prepared statements.
    - Use ORM frameworks that abstract away direct SQL queries.
    - Validate and sanitize user inputs.

## 2. Cross-Site Scripting (XSS)

- **Description:** XSS allows attackers to inject malicious JavaScript into web pages viewed by other users. There are three types of XSS: 
  - **Reflected:** Malicious script is reflected off a web application and executed immediately.
  - **Stored:** Malicious script is stored on the server and executed when a victim views the page.
  - **DOM-based:** The vulnerability exists within the client-side code itself.
- **Example:**
    ```html
    <input type="text" name="comment" value="<?php echo $_GET['comment']; ?>">
    ```
    If user input is not properly sanitized, attackers can inject a script like this:
    ```html
    <script>alert('XSS');</script>
    ```
- **Risks:** Stealing user sessions, performing unauthorized actions on behalf of the user, redirecting users to malicious sites.
- **Remediation:**
    - Escape or sanitize user inputs properly.
    - Use content security policies (CSP) to restrict which scripts can run.
    - Validate inputs on both the client and server side.

## 3. Cross-Site Request Forgery (CSRF)

- **Description:** CSRF attacks force a user to execute unwanted actions on a web application in which they’re authenticated, such as changing account settings or performing transactions.
- **Example:**
    ```html
    <img src="http://example.com/change_email?new_email=hacker@example.com">
    ```
    When a logged-in user loads this image, it triggers the email change request.
- **Risks:** Malicious actions performed on behalf of an authenticated user.
- **Remediation:**
    - Use anti-CSRF tokens in forms.
    - Require re-authentication for sensitive actions.
    - Validate the `Referer` or `Origin` headers.

## 4. Security Misconfiguration

- **Description:** Misconfiguration of security settings can leave an application exposed to a wide range of attacks, such as directory listings, default passwords, or unnecessary services.
- **Risks:** Unauthorized access, data leaks, and unauthorized changes.
- **Remediation:**
    - Regularly review and harden server configurations.
    - Disable unnecessary services, ports, and permissions.
    - Enforce strong passwords and remove default accounts.

## 5. Insecure Direct Object References (IDOR)

- **Description:** IDOR occurs when an application exposes internal objects (files, database entries) through user inputs without proper authorization checks.
- **Example:**
    ```http
    GET /users/12345
    ```
    An attacker can modify the user ID to access data for another user:
    ```http
    GET /users/12346
    ```
- **Risks:** Data exposure, unauthorized access to sensitive information.
- **Remediation:**
    - Enforce strong access control checks on the server side.
    - Do not rely solely on user-controlled inputs for object access.

## 6. Sensitive Data Exposure

- **Description:** Sensitive data such as passwords, credit card details, or health information can be exposed due to improper encryption or lack of encryption.
- **Example:** Storing passwords in plain text or over a non-HTTPS connection.
- **Risks:** Compromise of sensitive user data, leading to identity theft or financial fraud.
- **Remediation:**
    - Use HTTPS to encrypt data in transit.
    - Encrypt sensitive data at rest using strong encryption algorithms.
    - Implement strong password hashing (e.g., bcrypt, Argon2).

## 7. Broken Authentication and Session Management

- **Description:** Flaws in authentication or session management can lead to account hijacking, such as weak password policies or session IDs exposed in URLs.
- **Example:** Exposing session tokens in URLs, making them vulnerable to interception.
    ```http
    http://example.com/account?sessionid=abc123
    ```
- **Risks:** Account compromise, privilege escalation, or impersonation.
- **Remediation:**
    - Implement strong password policies (min length, complexity).
    - Ensure session IDs are securely stored (e.g., in cookies with secure flags).
    - Use multi-factor authentication (MFA) for critical accounts.

## 8. Insufficient Logging and Monitoring

- **Description:** A lack of logging and monitoring can delay the detection of attacks, leaving the system vulnerable to repeated exploitation.
- **Risks:** Failure to detect and respond to breaches or attacks in a timely manner.
- **Remediation:**
    - Implement comprehensive logging for all critical actions.
    - Regularly review logs and integrate with a SIEM system for alerting.
    - Set up monitoring for anomalies or suspicious behavior.

## 9. XML External Entities (XXE)

- **Description:** This occurs when an XML parser processes external entities within an XML document, potentially allowing attackers to extract local files or perform SSRF (Server-Side Request Forgery) attacks.
- **Example:**
    ```xml
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    ```
    An attacker can read sensitive files by exploiting XXE.
- **Risks:** Exfiltration of sensitive data, server compromise.
- **Remediation:**
    - Disable external entity processing in XML parsers.
    - Validate incoming XML input.
    - Use safer data formats like JSON if possible.

## 10. Server-Side Request Forgery (SSRF)

- **Description:** SSRF occurs when a server-side application makes HTTP requests to arbitrary domains, potentially allowing attackers to access internal services.
- **Example:**
    ```http
    http://example.com/fetch?url=http://internal-server/admin
    ```
    An attacker can manipulate this request to access internal resources.
- **Risks:** Unauthorized access to internal systems or services.
- **Remediation:**
    - Restrict outbound HTTP requests to allowed domains.
    - Validate and sanitize user inputs that result in outbound requests.

---

### Conclusion:
These vulnerabilities are commonly identified in DAST scans. It’s important to remediate them as soon as they are discovered. Implementing secure coding practices, using appropriate frameworks, and ensuring consistent input validation can significantly reduce the risk of such vulnerabilities.
