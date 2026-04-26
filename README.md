[README.md](https://github.com/user-attachments/files/27103039/README.md)
# SafeVault

A security-focused ASP.NET Core Web API demonstrating secure coding practices including input validation, SQL injection prevention, XSS sanitization, JWT authentication, and role-based access control.

## Tech Stack

- **Framework**: ASP.NET Core 8 Web API
- **Authentication**: JWT Bearer Tokens + ASP.NET Identity
- **Database**: SQLite via Entity Framework Core
- **Testing**: xUnit
- **Authorization**: Role-Based Access Control (Admin / User)

## How to Run

```bash
# Navigate to the project directory
cd SafeVault

# Restore NuGet packages
dotnet restore

# Run the application (database is created automatically on first run)
dotnet run
```

The API will start at `https://localhost:5001` (or `http://localhost:5000`). Swagger UI is available at `/swagger`.

## Run Tests

```bash
cd Tests
dotnet test
```

## API Endpoints

| Method | Endpoint | Access | Description |
|--------|----------|--------|-------------|
| POST | `/api/auth/register` | Public | Register a new user |
| POST | `/api/auth/login` | Public | Login and receive JWT token |
| GET | `/api/vault` | Authenticated | Get vault items for current user |
| POST | `/api/vault` | Admin Only | Create a new vault item |
| DELETE | `/api/vault/{id}` | Admin Only | Delete a vault item |

## Security Features

- **Input Sanitization**: All user input is sanitized to strip HTML/script tags (XSS prevention)
- **Parameterized Queries**: EF Core LINQ prevents SQL injection (no raw SQL)
- **SQL Injection Middleware**: Defense-in-depth request inspection for SQL patterns
- **JWT Authentication**: Secure token-based auth with 1-hour expiration
- **RBAC**: Admin and User roles with attribute-based endpoint protection
- **Password Hashing**: ASP.NET Identity PBKDF2 hashing with complexity requirements

## Project Structure

```
SafeVault/
├── Controllers/
│   ├── AuthController.cs      # Login and registration endpoints
│   └── VaultController.cs     # CRUD for vault items (role-protected)
├── Models/
│   ├── User.cs                # Identity user model
│   ├── VaultItem.cs           # Vault item entity
│   ├── LoginModel.cs          # Login request DTO
│   └── RegisterModel.cs       # Registration request DTO
├── Data/
│   └── AppDbContext.cs        # EF Core context with Identity
├── Helpers/
│   ├── JwtHelper.cs           # JWT token generation
│   └── InputValidator.cs      # Input validation and sanitization
├── Middleware/
│   └── SqlInjectionMiddleware.cs  # SQL injection detection
├── Tests/
│   └── SecurityTests.cs       # xUnit security tests
├── Program.cs                 # App configuration and startup
├── appsettings.json           # Configuration settings
├── SUMMARY.md                 # Project summary and findings
└── README.md                  # This file
```
