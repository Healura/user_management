# Voice Biomarker User Management Service

A secure, HIPAA-compliant user management and authentication microservice for the Voice Biomarker Healthcare Application.

## 🚀 Features

### Authentication & Security
- **JWT-based authentication** with RS256 algorithm
- **Multi-factor authentication (MFA)** with TOTP support
- **Email verification** for new registrations
- **Password policy enforcement** with strength requirements
- **Session management** with device tracking
- **Rate limiting** to prevent brute force attacks
- **Account lockout** after failed login attempts
- **HIPAA-compliant audit logging**

### User Management
- User registration with email verification
- Profile management (view/update)
- Password reset via email
- Session management (view/revoke)
- Role-based access control (RBAC)
- Soft delete with data retention policies

### Security Features
- CORS protection
- SQL injection prevention
- XSS protection
- CSRF protection
- Security headers (CSP, HSTS, etc.)
- IP whitelisting (optional)
- Request/response logging

## 📋 Prerequisites

- Python 3.11+
- PostgreSQL 14+ (or AWS RDS)
- Redis (optional, for distributed rate limiting)
- SMTP server for email functionality

## 🛠️ Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd user-management-service
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. **Generate JWT keys**
```bash
python scripts/generate_jwt_keys.py
```

6. **Initialize database**
```bash
# Run migrations
alembic upgrade head

# Create default roles
python scripts/init_roles.py
```

## 🏃‍♂️ Running the Service

### Development
```bash
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

### Production
```bash
uvicorn src.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Docker
```bash
docker-compose up -d
```

## 📚 API Documentation

Once running, access the interactive API documentation at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Key Endpoints

#### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - Login with email/password
- `POST /auth/logout` - Logout and invalidate tokens
- `POST /auth/refresh` - Refresh access token
- `POST /auth/verify-email` - Verify email address
- `POST /auth/forgot-password` - Request password reset
- `POST /auth/reset-password` - Reset password with token

#### User Management
- `GET /users/profile` - Get current user profile
- `PUT /users/profile` - Update user profile
- `DELETE /users/account` - Delete user account
- `GET /users/sessions` - List active sessions
- `DELETE /users/sessions/{id}` - Revoke specific session

#### Admin (requires admin role)
- `GET /users` - List all users
- `PUT /users/{id}/status` - Activate/deactivate user
- `GET /users/{id}/audit` - Get user audit log

## 🔒 Security Configuration

### JWT Configuration
The service uses RS256 (RSA with SHA-256) for JWT signing:
- Access tokens expire in 15 minutes
- Refresh tokens expire in 7 days
- Tokens include user ID and roles

### Password Requirements
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character
- Cannot contain user's email
- No common patterns allowed

### Rate Limiting
Default limits:
- 100 requests per minute per user
- 10 login attempts per minute per IP
- 3 password reset requests per hour

## 🏗️ Architecture

### Project Structure
```
user-management-service/
├── src/
│   ├── api/                # API endpoints
│   ├── auth/              # Authentication logic
│   ├── database/          # Database models and repositories
│   ├── security/          # Security middleware and utilities
│   ├── utils/             # Utility functions
│   └── main.py           # Application entry point
├── tests/                 # Test suite
├── scripts/              # Utility scripts
├── config/               # Configuration modules
└── keys/                 # JWT keys (git-ignored)
```

### Database Schema
- **users** - User accounts
- **user_roles** - Available roles
- **user_role_assignments** - User-role mappings
- **user_sessions** - Active sessions
- **audio_files** - Voice recordings (Phase 3)
- **voice_analyses** - Analysis results (Phase 3)
- **notification_preferences** - User preferences
- **notification_history** - Sent notifications
- **audit_logs** - HIPAA audit trail

## 🧪 Testing

Run the test suite:
```bash
pytest
```

With coverage:
```bash
pytest --cov=src tests/
```

## 📊 Monitoring

### Health Checks
- `/health` - Basic health check
- `/health/live` - Kubernetes liveness probe
- `/health/ready` - Kubernetes readiness probe
- `/health/detailed` - Detailed component status

### Metrics
Prometheus metrics available at `/metrics`

## 🚀 Deployment

### AWS ECS Deployment
1. Build Docker image
2. Push to ECR
3. Update ECS task definition
4. Deploy new service revision

### Environment Variables
See `.env.example` for all required environment variables.

## 🤝 Contributing

1. Create a feature branch
2. Make your changes
3. Write/update tests
4. Submit a pull request

## 📄 License

[License information]

## 🔮 Next Steps (Phase 3)

The next phase will add:
- File upload/storage for voice recordings
- Integration with S3 for audio file storage
- Voice analysis result management
- Enhanced notification system