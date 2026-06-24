"""
Secure Login Module - Best Practices Implementation

This module implements a secure authentication system following:
- OWASP security guidelines
- SOLID principles
- Clean architecture patterns
"""

import hashlib
import secrets
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from database.db_manager import DatabaseManager
from utils.validators import InputValidator
from auth.session import SessionManager


# esto es una prueba..

class LoginError(Exception):
    """Custom exception for login-related errors"""
    pass


class AuthenticationService:
    """
    Handles user authentication with security best practices.
    
    Follows Single Responsibility Principle - only handles authentication logic.
    Uses Dependency Injection for database and session management.
    """
    
    def __init__(
        self, 
        db_manager: DatabaseManager,
        session_manager: SessionManager,
        validator: InputValidator
    ):
        """
        Initialize authentication service with dependencies.
        
        Args:
            db_manager: Database manager instance
            session_manager: Session manager instance
            validator: Input validator instance
        """
        self._db = db_manager
        self._session_manager = session_manager
        self._validator = validator
        self._max_login_attempts = 5
        self._lockout_duration = timedelta(minutes=15)
    
    def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate user with username and password.
        
        Args:
            username: User's username
            password: User's password (plain text, will be hashed)
            
        Returns:
            Dict containing session token and user info
            
        Raises:
            LoginError: If authentication fails
        """
        # Validate inputs
        if not self._validator.validate_username(username):
            raise LoginError("Invalid username format")
        
        if not self._validator.validate_password_strength(password):
            raise LoginError("Invalid password format")
        
        # Check if account is locked
        if self._is_account_locked(username):
            raise LoginError("Account is temporarily locked due to multiple failed attempts")
        
        # Get user from database using prepared statement
        user = self._get_user_by_username(username)
        
        if not user:
            self._record_failed_attempt(username)
            raise LoginError("Invalid credentials")
        
        # Verify password using secure hash comparison
        if not self._verify_password(password, user['password_hash']):
            self._record_failed_attempt(username)
            raise LoginError("Invalid credentials")
        
        # Reset failed attempts on successful login
        self._reset_failed_attempts(username)
        
        # Create secure session
        session_token = self._session_manager.create_session(
            user_id=user['id'],
            username=user['username']
        )
        
        return {
            'session_token': session_token,
            'user_id': user['id'],
            'username': user['username'],
            'expires_at': (datetime.now() + timedelta(hours=2)).isoformat()
        }
    
    def _get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve user from database using parameterized query.
        
        Args:
            username: Username to search for
            
        Returns:
            User dict if found, None otherwise
        """
        # Using parameterized query to prevent SQL injection
        query = "SELECT id, username, password_hash FROM users WHERE username = ?"
        result = self._db.execute_query(query, (username,))
        
        if result:
            return {
                'id': result[0][0],
                'username': result[0][1],
                'password_hash': result[0][2]
            }
        return None
    
    def _verify_password(self, plain_password: str, password_hash: str) -> bool:
        """
        Verify password against stored hash using secure comparison.
        
        Args:
            plain_password: Plain text password from user
            password_hash: Stored password hash
            
        Returns:
            True if password matches, False otherwise
        """
        # Hash the provided password
        computed_hash = self._hash_password(plain_password)
        
        # Use secrets.compare_digest for timing-attack resistant comparison
        return secrets.compare_digest(computed_hash, password_hash)
    
    def _hash_password(self, password: str) -> str:
        """
        Hash password using SHA-256 with salt.
        
        Note: In production, use bcrypt or Argon2 instead of SHA-256
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password string
        """
        # In production, use bcrypt.hashpw() or argon2.hash_password()
        salt = "secure_random_salt_from_config"  # Should be from secure config
        return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
    
    def _is_account_locked(self, username: str) -> bool:
        """
        Check if account is locked due to failed login attempts.
        
        Args:
            username: Username to check
            
        Returns:
            True if account is locked, False otherwise
        """
        query = """
            SELECT failed_attempts, last_failed_attempt 
            FROM login_attempts 
            WHERE username = ?
        """
        result = self._db.execute_query(query, (username,))
        
        if not result:
            return False
        
        failed_attempts, last_failed = result[0]
        
        if failed_attempts >= self._max_login_attempts:
            # Check if lockout period has expired
            last_failed_time = datetime.fromisoformat(last_failed)
            if datetime.now() - last_failed_time < self._lockout_duration:
                return True
        
        return False
    
    def _record_failed_attempt(self, username: str) -> None:
        """
        Record a failed login attempt.
        
        Args:
            username: Username that failed to login
        """
        query = """
            INSERT INTO login_attempts (username, failed_attempts, last_failed_attempt)
            VALUES (?, 1, ?)
            ON CONFLICT(username) DO UPDATE SET
                failed_attempts = failed_attempts + 1,
                last_failed_attempt = ?
        """
        now = datetime.now().isoformat()
        self._db.execute_query(query, (username, now, now))
    
    def _reset_failed_attempts(self, username: str) -> None:
        """
        Reset failed login attempts after successful login.
        
        Args:
            username: Username to reset attempts for
        """
        query = "DELETE FROM login_attempts WHERE username = ?"
        self._db.execute_query(query, (username,))
    
    def logout(self, session_token: str) -> bool:
        """
        Logout user by invalidating session.
        
        Args:
            session_token: Session token to invalidate
            
        Returns:
            True if logout successful
        """
        return self._session_manager.invalidate_session(session_token)

# Made with Bob
