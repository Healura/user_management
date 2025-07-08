import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.main import app
from src.database.database import Base, get_db
from src.database.models import User, UserRole
from src.auth import hash_password, create_access_token, verify_token
from src.utils import create_email_verification_token

# Test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture
def test_db():
    """Create a fresh database for each test."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def test_user(test_db):
    """Create a test user."""
    db = TestingSessionLocal()
    user = User(
        email="test@example.com",
        password_hash=hash_password("TestPassword123!"),
        first_name="Test",
        last_name="User",
        email_verified=True,
        is_active=True,
        privacy_consent=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return user


@pytest.fixture
def test_roles(test_db):
    """Create test roles."""
    db = TestingSessionLocal()
    roles = []
    for role_name in ["admin", "healthcare_provider", "patient"]:
        role = UserRole(name=role_name, description=f"{role_name} role")
        db.add(role)
        roles.append(role)
    db.commit()
    db.close()
    return roles


class TestRegistration:
    """Test user registration."""
    
    def test_successful_registration(self, test_db, test_roles):
        """Test successful user registration."""
        response = client.post("/auth/register", json={
            "email": "newuser@example.com",
            "password": "SecurePassword123!",
            "first_name": "New",
            "last_name": "User",
            "privacy_consent": True
        })
        
        assert response.status_code == 201
        assert "Registration successful" in response.json()["message"]
    
    def test_registration_duplicate_email(self, test_db, test_user):
        """Test registration with existing email."""
        response = client.post("/auth/register", json={
            "email": "test@example.com",
            "password": "SecurePassword123!",
            "first_name": "Another",
            "last_name": "User",
            "privacy_consent": True
        })
        
        assert response.status_code == 400
        assert "Email already registered" in response.json()["detail"]
    
    def test_registration_weak_password(self, test_db):
        """Test registration with weak password."""
        response = client.post("/auth/register", json={
            "email": "newuser@example.com",
            "password": "weak",
            "first_name": "New",
            "last_name": "User",
            "privacy_consent": True
        })
        
        assert response.status_code == 400
        assert "Password does not meet requirements" in response.json()["detail"]["message"]
    
    def test_registration_no_consent(self, test_db):
        """Test registration without privacy consent."""
        response = client.post("/auth/register", json={
            "email": "newuser@example.com",
            "password": "SecurePassword123!",
            "first_name": "New",
            "last_name": "User",
            "privacy_consent": False
        })
        
        assert response.status_code == 400
        assert "Privacy consent is required" in response.json()["detail"]


class TestLogin:
    """Test user login."""
    
    def test_successful_login(self, test_db, test_user):
        """Test successful login."""
        response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "TestPassword123!"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
    
    def test_login_invalid_password(self, test_db, test_user):
        """Test login with wrong password."""
        response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "WrongPassword123!"
        })
        
        assert response.status_code == 401
    
    def test_login_nonexistent_user(self, test_db):
        """Test login with non-existent user."""
        response = client.post("/auth/login", json={
            "email": "nonexistent@example.com",
            "password": "AnyPassword123!"
        })
        
        assert response.status_code == 401
    
    def test_login_unverified_email(self, test_db):
        """Test login with unverified email."""
        db = TestingSessionLocal()
        user = User(
            email="unverified@example.com",
            password_hash=hash_password("TestPassword123!"),
            first_name="Test",
            last_name="User",
            email_verified=False,
            is_active=True,
            privacy_consent=True
        )
        db.add(user)
        db.commit()
        db.close()
        
        response = client.post("/auth/login", json={
            "email": "unverified@example.com",
            "password": "TestPassword123!"
        })
        
        assert response.status_code == 401
        assert "verify your email" in response.json()["detail"].lower()


class TestTokens:
    """Test JWT token functionality."""
    
    def test_access_token_creation(self, test_user):
        """Test access token creation."""
        token = create_access_token(test_user)
        assert token is not None
        
        # Verify token
        payload = verify_token(token, token_type="access")
        assert payload["sub"] == str(test_user.id)
        assert payload["email"] == test_user.email
    
    def test_refresh_token_flow(self, test_db, test_user):
        """Test refresh token flow."""
        # Login to get tokens
        login_response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "TestPassword123!"
        })
        
        refresh_token = login_response.json()["refresh_token"]
        
        # Use refresh token
        response = client.post("/auth/refresh", json={
            "refresh_token": refresh_token
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
    
    def test_invalid_token(self):
        """Test invalid token handling."""
        with pytest.raises(Exception):
            verify_token("invalid_token", token_type="access")


class TestPasswordReset:
    """Test password reset functionality."""
    
    def test_forgot_password(self, test_db, test_user):
        """Test forgot password request."""
        response = client.post("/auth/forgot-password", json={
            "email": "test@example.com"
        })
        
        assert response.status_code == 200
        assert "If an account exists" in response.json()["message"]
    
    def test_forgot_password_nonexistent(self, test_db):
        """Test forgot password with non-existent email."""
        response = client.post("/auth/forgot-password", json={
            "email": "nonexistent@example.com"
        })
        
        # Should still return 200 to prevent email enumeration
        assert response.status_code == 200
        assert "If an account exists" in response.json()["message"]
    
    def test_reset_password_with_token(self, test_db, test_user):
        """Test password reset with valid token."""
        from src.utils.jwt_utils import create_password_reset_token
        
        # Create reset token
        reset_token = create_password_reset_token(str(test_user.id))
        
        # Reset password
        response = client.post("/auth/reset-password", json={
            "token": reset_token,
            "new_password": "NewSecurePassword123!"
        })
        
        assert response.status_code == 200
        assert "Password reset successfully" in response.json()["message"]
        
        # Try logging in with new password
        login_response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "NewSecurePassword123!"
        })
        
        assert login_response.status_code == 200


class TestEmailVerification:
    """Test email verification."""
    
    def test_verify_email(self, test_db):
        """Test email verification with valid token."""
        # Create unverified user
        db = TestingSessionLocal()
        user = User(
            email="toverify@example.com",
            password_hash=hash_password("TestPassword123!"),
            first_name="Test",
            last_name="User",
            email_verified=False,
            is_active=True,
            privacy_consent=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        user_id = user.id
        db.close()
        
        # Create verification token
        token = create_email_verification_token(str(user_id))
        
        # Verify email
        response = client.post("/auth/verify-email", json={
            "token": token
        })
        
        assert response.status_code == 200
        assert "Email verified successfully" in response.json()["message"]
        
        # Check user is verified
        db = TestingSessionLocal()
        user = db.query(User).filter(User.id == user_id).first()
        assert user.email_verified is True
        db.close()


class TestProtectedEndpoints:
    """Test authentication requirements for protected endpoints."""
    
    def test_profile_without_auth(self):
        """Test accessing profile without authentication."""
        response = client.get("/users/profile")
        assert response.status_code == 403  # No auth header
    
    def test_profile_with_auth(self, test_db, test_user):
        """Test accessing profile with authentication."""
        # Get token
        token = create_access_token(test_user)
        
        # Access profile
        response = client.get(
            "/users/profile",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == test_user.email
    
    def test_invalid_token_access(self):
        """Test accessing protected endpoint with invalid token."""
        response = client.get(
            "/users/profile",
            headers={"Authorization": "Bearer invalid_token"}
        )
        
        assert response.status_code == 401


class TestSessionManagement:
    """Test session management."""
    
    def test_logout(self, test_db, test_user):
        """Test logout functionality."""
        # Login first
        login_response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "TestPassword123!"
        })
        
        token = login_response.json()["access_token"]
        
        # Logout
        response = client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        assert "Logged out successfully" in response.json()["message"]
    
    def test_get_sessions(self, test_db, test_user):
        """Test getting user sessions."""
        # Login to create session
        login_response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "TestPassword123!"
        })
        
        token = login_response.json()["access_token"]
        
        # Get sessions
        response = client.get(
            "/users/sessions",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        sessions = response.json()
        assert len(sessions) > 0
        assert sessions[0]["is_active"] is True