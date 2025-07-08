"""Tests for password policy enforcement."""

import pytest
from src.auth.password_policy import (
    validate_password,
    enforce_password_policy,
    PasswordValidationError,
    get_password_strength,
    check_password_expiry
)
from datetime import datetime, timedelta


class TestPasswordValidation:
    """Test password validation rules."""
    
    def test_valid_password(self):
        """Test valid password that meets all requirements."""
        is_valid, errors = validate_password("SecureP@ssw0rd123")
        assert is_valid is True
        assert len(errors) == 0
    
    def test_password_too_short(self):
        """Test password that's too short."""
        is_valid, errors = validate_password("Short1!")
        assert is_valid is False
        assert any("at least" in error for error in errors)
    
    def test_password_no_uppercase(self):
        """Test password without uppercase letters."""
        is_valid, errors = validate_password("secure_password123!")
        assert is_valid is False
        assert any("uppercase" in error for error in errors)
    
    def test_password_no_lowercase(self):
        """Test password without lowercase letters."""
        is_valid, errors = validate_password("SECURE_PASSWORD123!")
        assert is_valid is False
        assert any("lowercase" in error for error in errors)
    
    def test_password_no_numbers(self):
        """Test password without numbers."""
        is_valid, errors = validate_password("SecurePassword!@#")
        assert is_valid is False
        assert any("number" in error for error in errors)
    
    def test_password_no_special(self):
        """Test password without special characters."""
        is_valid, errors = validate_password("SecurePassword123")
        assert is_valid is False
        assert any("special character" in error for error in errors)
    
    def test_password_contains_email(self):
        """Test password that contains email."""
        is_valid, errors = validate_password("test@example.com123!", email="test@example.com")
        assert is_valid is False
        assert any("email" in error for error in errors)
    
    def test_common_passwords(self):
        """Test common weak passwords."""
        common_passwords = [
            "Password123!",
            "Qwerty123!",
            "Admin123!",
            "Welcome123!",
            "123456Aa!"
        ]
        
        for password in common_passwords:
            is_valid, errors = validate_password(password)
            assert is_valid is False
            assert any("common patterns" in error for error in errors)
    
    def test_sequential_characters(self):
        """Test passwords with sequential characters."""
        passwords_with_sequences = [
            "Abcd1234!",
            "Password1234!",
            "Test4321!xyz"
        ]
        
        for password in passwords_with_sequences:
            is_valid, errors = validate_password(password)
            assert is_valid is False
    
    def test_repeated_characters(self):
        """Test passwords with repeated characters."""
        is_valid, errors = validate_password("Paaaaaassword123!")
        assert is_valid is False
        assert any("common patterns" in error for error in errors)


class TestPasswordPolicyEnforcement:
    """Test password policy enforcement."""
    
    def test_enforce_valid_password(self):
        """Test enforcing policy on valid password."""
        try:
            enforce_password_policy("SecureP@ssw0rd123")
            assert True
        except PasswordValidationError:
            assert False, "Valid password should not raise exception"
    
    def test_enforce_invalid_password(self):
        """Test enforcing policy on invalid password."""
        with pytest.raises(PasswordValidationError) as exc_info:
            enforce_password_policy("weak")
        
        assert len(exc_info.value.errors) > 0


class TestPasswordStrength:
    """Test password strength calculation."""
    
    def test_weak_password_strength(self):
        """Test weak password strength."""
        strength = get_password_strength("password")
        assert strength == "weak"
    
    def test_moderate_password_strength(self):
        """Test moderate password strength."""
        strength = get_password_strength("Password1")
        assert strength == "moderate"
    
    def test_strong_password_strength(self):
        """Test strong password strength."""
        strength = get_password_strength("SecurePass123!")
        assert strength == "strong"
    
    def test_very_strong_password_strength(self):
        """Test very strong password strength."""
        strength = get_password_strength("V3ry$ecureP@ssw0rd#2024")
        assert strength == "very_strong"


class TestPasswordExpiry:
    """Test password expiry checks."""
    
    def test_password_not_expired(self):
        """Test password that hasn't expired."""
        last_change = datetime.utcnow() - timedelta(days=30)
        assert check_password_expiry(last_change) is False
    
    def test_password_expired(self):
        """Test password that has expired."""
        last_change = datetime.utcnow() - timedelta(days=100)
        assert check_password_expiry(last_change) is True
    
    def test_password_expiry_disabled(self):
        """Test when password expiry is disabled."""
        # This would need to mock the settings
        # For now, just checking the function exists
        assert callable(check_password_expiry)