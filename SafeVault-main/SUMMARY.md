# SafeVault — Capstone Project Summary

## Project Overview
SafeVault is a secure ASP.NET Core Web API application that demonstrates best practices in secure coding, authentication, authorization, and data protection. The project was developed with the assistance of Microsoft Copilot to identify, fix, and prevent common security vulnerabilities.

---

## Vulnerabilities Identified

1. **SQL Injection**: Raw SQL queries using string concatenation allowed attackers to manipulate database queries through user input fields.
2. **Cross-Site Scripting (XSS)**: User input was rendered without sanitization, enabling malicious scripts to be injected into responses.
3. **Weak Authentication**: The application initially lacked proper authentication, allowing unrestricted access to sensitive API endpoints.
4. **Missing Role-Based Access Control**: All authenticated users had equal access to all resources, including administrative functions.
5. **Insecure Password Storage**: Passwords were stored without hashing, exposing them in case of a data breach.

---

## Fixes Applied

| Vulnerability | Fix Applied |
|---|---|
| SQL Injection | Replaced raw SQL with Entity Framework Core parameterized queries. Added SQL injection detection middleware. |
| XSS | Implemented InputValidator class that strips HTML and script tags from all user input before processing. |
| Weak Authentication | Implemented JWT-based authentication with secure token generation, signing keys stored in configuration, and token expiration. |
| Missing RBAC | Configured ASP.NET Identity with "Admin" and "User" roles. Protected endpoints using `[Authorize(Roles = "Admin")]` attributes. |
| Insecure Passwords | Used ASP.NET Identity's built-in password hashing (PBKDF2) with configurable complexity requirements. |

---

## How Microsoft Copilot Assisted

- **Secure Code Generation**: Copilot generated input validation methods for email, password, and general input sanitization, following OWASP guidelines.
- **Authentication & Authorization**: Copilot helped scaffold JWT token generation, middleware configuration, and role-based access control setup.
- **Vulnerability Detection**: Copilot identified insecure patterns in the codebase (such as string concatenation in queries) and suggested parameterized alternatives.
- **Test Generation**: Copilot generated xUnit security tests to verify SQL injection prevention, XSS sanitization, and authentication enforcement.
- **Debugging**: Copilot assisted in resolving issues with middleware ordering, token validation configuration, and role assignment logic.

---

## Technologies Used
- ASP.NET Core 8 Web API
- ASP.NET Identity
- Entity Framework Core (SQLite)
- JWT Authentication
- xUnit (Testing)
- Microsoft Copilot (AI Assistant)
