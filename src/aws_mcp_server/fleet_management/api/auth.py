"""
Authentication Manager for API Layer.

This module handles user authentication, token management, and
permission checking for the API layer.
"""

import os
import json
import logging
import asyncio
import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Set
from pathlib import Path
import jwt

logger = logging.getLogger(__name__)


class Permission(Enum):
    """Permissions for API access."""
    READ_RESOURCES = "read:resources"
    WRITE_RESOURCES = "write:resources"
    DELETE_RESOURCES = "delete:resources"
    
    READ_CONFIGURATIONS = "read:configurations"
    WRITE_CONFIGURATIONS = "write:configurations"
    DELETE_CONFIGURATIONS = "delete:configurations"
    
    READ_DEPLOYMENTS = "read:deployments"
    WRITE_DEPLOYMENTS = "write:deployments"
    DELETE_DEPLOYMENTS = "delete:deployments"
    
    READ_METRICS = "read:metrics"
    WRITE_METRICS = "write:metrics"
    DELETE_METRICS = "delete:metrics"
    
    READ_ALERTS = "read:alerts"
    WRITE_ALERTS = "write:alerts"
    DELETE_ALERTS = "delete:alerts"
    
    READ_LOGS = "read:logs"
    WRITE_LOGS = "write:logs"
    DELETE_LOGS = "delete:logs"
    
    ADMIN = "admin"


@dataclass
class Role:
    """Role definition with associated permissions."""
    name: str
    description: str
    permissions: List[Permission] = field(default_factory=list)


@dataclass
class User:
    """User record for authentication and authorization."""
    id: str
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: bool = False
    roles: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    

@dataclass
class AuthConfig:
    """Configuration for authentication manager."""
    secret_key: str = field(default_factory=lambda: os.urandom(32).hex())
    token_expiration: int = 3600  # 1 hour
    token_algorithm: str = "HS256"
    password_hash_iterations: int = 100000
    users_file: Optional[str] = None
    roles_file: Optional[str] = None


class AuthManager:
    """
    Authentication Manager for the API layer.
    
    Handles user authentication, token generation and validation,
    and permission checking based on user roles.
    """
    
    def __init__(self, config: Optional[AuthConfig] = None):
        """Initialize the authentication manager."""
        self.config = config or AuthConfig()
        self.users: Dict[str, Dict] = {}
        self.roles: Dict[str, Role] = {}
        self._token_blacklist: Set[str] = set()
        
        # Initialize default roles
        self._init_default_roles()
        
        # Load users and roles from files if configured
        self._load_users()
        self._load_roles()
    
    def _init_default_roles(self):
        """Initialize default roles with permissions."""
        self.roles = {
            "admin": Role(
                name="admin",
                description="Administrator with full access",
                permissions=list(Permission)
            ),
            "operator": Role(
                name="operator",
                description="System operator with operational access",
                permissions=[
                    Permission.READ_RESOURCES,
                    Permission.READ_CONFIGURATIONS,
                    Permission.WRITE_CONFIGURATIONS,
                    Permission.READ_DEPLOYMENTS,
                    Permission.WRITE_DEPLOYMENTS,
                    Permission.READ_METRICS,
                    Permission.READ_ALERTS,
                    Permission.WRITE_ALERTS,
                    Permission.READ_LOGS,
                ]
            ),
            "readonly": Role(
                name="readonly",
                description="Read-only access to all resources",
                permissions=[
                    Permission.READ_RESOURCES,
                    Permission.READ_CONFIGURATIONS,
                    Permission.READ_DEPLOYMENTS,
                    Permission.READ_METRICS,
                    Permission.READ_ALERTS,
                    Permission.READ_LOGS,
                ]
            ),
        }
    
    def _load_users(self):
        """Load users from file if configured."""
        if not self.config.users_file:
            # Add a default admin user if no users file is configured
            self._add_default_user()
            return
        
        file_path = Path(self.config.users_file)
        if not file_path.exists():
            logger.warning(f"Users file {file_path} not found, creating default user")
            self._add_default_user()
            return
        
        try:
            with open(file_path, "r") as f:
                users_data = json.load(f)
                
            for user_data in users_data:
                user_id = user_data.get("id")
                if not user_id:
                    continue
                    
                self.users[user_id] = user_data
            
            if not self.users:
                logger.warning("No users found in users file, creating default user")
                self._add_default_user()
        except Exception as e:
            logger.error(f"Error loading users from file: {e}")
            self._add_default_user()
    
    def _load_roles(self):
        """Load roles from file if configured."""
        if not self.config.roles_file:
            return
            
        file_path = Path(self.config.roles_file)
        if not file_path.exists():
            logger.warning(f"Roles file {file_path} not found, using default roles")
            return
            
        try:
            with open(file_path, "r") as f:
                roles_data = json.load(f)
                
            for role_data in roles_data:
                role_name = role_data.get("name")
                if not role_name:
                    continue
                    
                permissions = []
                for perm_name in role_data.get("permissions", []):
                    try:
                        perm = Permission(perm_name)
                        permissions.append(perm)
                    except ValueError:
                        logger.warning(f"Invalid permission name: {perm_name}")
                
                self.roles[role_name] = Role(
                    name=role_name,
                    description=role_data.get("description", ""),
                    permissions=permissions
                )
        except Exception as e:
            logger.error(f"Error loading roles from file: {e}")
    
    def _add_default_user(self):
        """Add a default admin user."""
        # Generate a secure random password
        default_password = os.urandom(8).hex()
        password_hash, salt = self._hash_password(default_password)
        
        user_id = "admin"
        self.users[user_id] = {
            "id": user_id,
            "username": "admin",
            "password_hash": password_hash,
            "password_salt": salt,
            "roles": ["admin"],
            "created_at": datetime.utcnow().isoformat(),
        }
        
        logger.info(f"Created default admin user with password: {default_password}")
        logger.info("Please change this password immediately in a production environment!")
    
    def _hash_password(self, password: str, salt: Optional[str] = None) -> tuple[str, str]:
        """
        Hash a password with PBKDF2 and a random salt.
        
        Args:
            password: The plaintext password to hash
            salt: Optional salt to use, generates a new one if not provided
            
        Returns:
            Tuple of (password_hash, salt)
        """
        if not salt:
            salt = os.urandom(16).hex()
            
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt.encode(),
            self.config.password_hash_iterations,
            dklen=32
        ).hex()
        
        return key, salt
    
    async def authenticate(self, username: str, password: str) -> Optional[str]:
        """
        Authenticate a user with username and password.
        
        Args:
            username: The username to authenticate
            password: The password to verify
            
        Returns:
            JWT token if authentication successful, None otherwise
        """
        # Find user by username
        user_id = None
        user_data = None
        
        for uid, data in self.users.items():
            if data.get("username") == username:
                user_id = uid
                user_data = data
                break
                
        if not user_id or not user_data:
            logger.warning(f"Authentication failed: User {username} not found")
            return None
            
        # Check if user is disabled
        if user_data.get("disabled", False):
            logger.warning(f"Authentication failed: User {username} is disabled")
            return None
            
        # Verify password
        stored_hash = user_data.get("password_hash")
        salt = user_data.get("password_salt")
        
        if not stored_hash or not salt:
            logger.warning(f"Authentication failed: User {username} has no password hash or salt")
            return None
            
        calculated_hash, _ = self._hash_password(password, salt)
        
        if calculated_hash != stored_hash:
            logger.warning(f"Authentication failed: Invalid password for user {username}")
            return None
            
        # Update last login time
        user_data["last_login"] = datetime.utcnow().isoformat()
        
        # Generate JWT token
        return self._generate_token(user_id)
    
    def _generate_token(self, user_id: str) -> str:
        """
        Generate a JWT token for a user.
        
        Args:
            user_id: The user ID to generate token for
            
        Returns:
            JWT token string
        """
        user_data = self.users.get(user_id)
        if not user_data:
            raise ValueError(f"User with ID {user_id} not found")
            
        expiration = datetime.utcnow() + timedelta(seconds=self.config.token_expiration)
        
        payload = {
            "sub": user_id,
            "username": user_data.get("username"),
            "roles": user_data.get("roles", []),
            "exp": expiration.timestamp(),
            "iat": datetime.utcnow().timestamp()
        }
        
        token = jwt.encode(
            payload,
            self.config.secret_key,
            algorithm=self.config.token_algorithm
        )
        
        return token
    
    async def validate_token(self, token: str) -> Optional[User]:
        """
        Validate a JWT token and return the associated user.
        
        Args:
            token: The JWT token to validate
            
        Returns:
            User object if token is valid, None otherwise
        """
        if token in self._token_blacklist:
            logger.warning("Token validation failed: Token is blacklisted")
            return None
            
        try:
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=[self.config.token_algorithm]
            )
            
            user_id = payload.get("sub")
            if not user_id:
                logger.warning("Token validation failed: No subject claim in token")
                return None
                
            user_data = self.users.get(user_id)
            if not user_data:
                logger.warning(f"Token validation failed: User with ID {user_id} not found")
                return None
                
            if user_data.get("disabled", False):
                logger.warning(f"Token validation failed: User with ID {user_id} is disabled")
                return None
                
            # Construct User object
            user = User(
                id=user_id,
                username=user_data.get("username"),
                email=user_data.get("email"),
                full_name=user_data.get("full_name"),
                disabled=user_data.get("disabled", False),
                roles=user_data.get("roles", []),
                created_at=datetime.fromisoformat(user_data.get("created_at")),
                last_login=datetime.fromisoformat(user_data.get("last_login")) if user_data.get("last_login") else None
            )
            
            return user
        except jwt.ExpiredSignatureError:
            logger.warning("Token validation failed: Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token validation failed: {str(e)}")
            return None
    
    async def invalidate_token(self, token: str) -> bool:
        """
        Invalidate a JWT token by adding it to the blacklist.
        
        Args:
            token: The JWT token to invalidate
            
        Returns:
            True if successful, False otherwise
        """
        try:
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=[self.config.token_algorithm]
            )
            
            # Add token to blacklist
            self._token_blacklist.add(token)
            
            # Schedule cleanup of expired tokens
            asyncio.create_task(self._cleanup_blacklist())
            
            return True
        except jwt.InvalidTokenError:
            return False
    
    async def _cleanup_blacklist(self):
        """Clean up expired tokens from the blacklist."""
        to_remove = set()
        
        for token in self._token_blacklist:
            try:
                jwt.decode(
                    token,
                    self.config.secret_key,
                    algorithms=[self.config.token_algorithm]
                )
            except jwt.ExpiredSignatureError:
                # Token has expired, can be removed from blacklist
                to_remove.add(token)
            except jwt.InvalidTokenError:
                # Keep invalid tokens in blacklist
                pass
                
        # Remove expired tokens
        self._token_blacklist -= to_remove
    
    async def check_permission(self, user: User, permission: Permission) -> bool:
        """
        Check if a user has a specific permission.
        
        Args:
            user: The user to check permissions for
            permission: The permission to check
            
        Returns:
            True if user has the permission, False otherwise
        """
        # Get user roles
        user_roles = user.roles
        
        # Check each role for the permission
        for role_name in user_roles:
            role = self.roles.get(role_name)
            if not role:
                continue
                
            # Admin role has all permissions
            if role_name == "admin" or Permission.ADMIN in role.permissions:
                return True
                
            # Check if role has the specific permission
            if permission in role.permissions:
                return True
                
        return False
    
    async def create_user(self, user_data: Dict[str, Any]) -> str:
        """
        Create a new user.
        
        Args:
            user_data: Dictionary with user data
            
        Returns:
            ID of the created user
            
        Raises:
            ValueError: If username already exists or data is invalid
        """
        # Validate required fields
        username = user_data.get("username")
        password = user_data.get("password")
        
        if not username or not password:
            raise ValueError("Username and password are required")
            
        # Check if username already exists
        for uid, data in self.users.items():
            if data.get("username") == username:
                raise ValueError(f"Username {username} already exists")
                
        # Generate user ID
        user_id = os.urandom(8).hex()
        
        # Hash password
        password_hash, salt = self._hash_password(password)
        
        # Create user record
        self.users[user_id] = {
            "id": user_id,
            "username": username,
            "email": user_data.get("email"),
            "full_name": user_data.get("full_name"),
            "password_hash": password_hash,
            "password_salt": salt,
            "roles": user_data.get("roles", ["readonly"]),
            "disabled": user_data.get("disabled", False),
            "created_at": datetime.utcnow().isoformat(),
        }
        
        # Save users to file if configured
        if self.config.users_file:
            self._save_users()
            
        return user_id
    
    async def update_user(self, user_id: str, user_data: Dict[str, Any]) -> bool:
        """
        Update an existing user.
        
        Args:
            user_id: ID of the user to update
            user_data: Dictionary with user data to update
            
        Returns:
            True if successful, False if user not found
            
        Raises:
            ValueError: If data is invalid or operation not allowed
        """
        if user_id not in self.users:
            return False
            
        # Get current user data
        current_data = self.users[user_id]
        
        # Update user data
        if "username" in user_data:
            # Check if new username already exists
            new_username = user_data["username"]
            for uid, data in self.users.items():
                if uid != user_id and data.get("username") == new_username:
                    raise ValueError(f"Username {new_username} already exists")
            current_data["username"] = new_username
            
        if "password" in user_data:
            password_hash, salt = self._hash_password(user_data["password"])
            current_data["password_hash"] = password_hash
            current_data["password_salt"] = salt
            
        if "email" in user_data:
            current_data["email"] = user_data["email"]
            
        if "full_name" in user_data:
            current_data["full_name"] = user_data["full_name"]
            
        if "roles" in user_data:
            # Validate roles
            for role in user_data["roles"]:
                if role not in self.roles:
                    raise ValueError(f"Role {role} does not exist")
            current_data["roles"] = user_data["roles"]
            
        if "disabled" in user_data:
            current_data["disabled"] = user_data["disabled"]
            
        # Save users to file if configured
        if self.config.users_file:
            self._save_users()
            
        return True
    
    async def delete_user(self, user_id: str) -> bool:
        """
        Delete a user.
        
        Args:
            user_id: ID of the user to delete
            
        Returns:
            True if successful, False if user not found
        """
        if user_id not in self.users:
            return False
            
        # Delete user
        del self.users[user_id]
        
        # Save users to file if configured
        if self.config.users_file:
            self._save_users()
            
        return True
    
    async def create_role(self, role_data: Dict[str, Any]) -> str:
        """
        Create a new role.
        
        Args:
            role_data: Dictionary with role data
            
        Returns:
            Name of the created role
            
        Raises:
            ValueError: If role already exists or data is invalid
        """
        # Validate required fields
        name = role_data.get("name")
        description = role_data.get("description", "")
        
        if not name:
            raise ValueError("Role name is required")
            
        # Check if role already exists
        if name in self.roles:
            raise ValueError(f"Role {name} already exists")
            
        # Parse permissions
        permissions = []
        for perm_name in role_data.get("permissions", []):
            try:
                perm = Permission(perm_name)
                permissions.append(perm)
            except ValueError:
                raise ValueError(f"Invalid permission name: {perm_name}")
                
        # Create role
        self.roles[name] = Role(
            name=name,
            description=description,
            permissions=permissions
        )
        
        # Save roles to file if configured
        if self.config.roles_file:
            self._save_roles()
            
        return name
    
    async def update_role(self, role_name: str, role_data: Dict[str, Any]) -> bool:
        """
        Update an existing role.
        
        Args:
            role_name: Name of the role to update
            role_data: Dictionary with role data to update
            
        Returns:
            True if successful, False if role not found
            
        Raises:
            ValueError: If data is invalid
        """
        if role_name not in self.roles:
            return False
            
        # Get current role
        role = self.roles[role_name]
        
        # Update description if provided
        if "description" in role_data:
            role.description = role_data["description"]
            
        # Update permissions if provided
        if "permissions" in role_data:
            permissions = []
            for perm_name in role_data["permissions"]:
                try:
                    perm = Permission(perm_name)
                    permissions.append(perm)
                except ValueError:
                    raise ValueError(f"Invalid permission name: {perm_name}")
            role.permissions = permissions
            
        # Save roles to file if configured
        if self.config.roles_file:
            self._save_roles()
            
        return True
    
    async def delete_role(self, role_name: str) -> bool:
        """
        Delete a role.
        
        Args:
            role_name: Name of the role to delete
            
        Returns:
            True if successful, False if role not found
            
        Raises:
            ValueError: If role is in use or protected
        """
        # Check if role exists
        if role_name not in self.roles:
            return False
            
        # Check if role is protected
        if role_name in ["admin", "operator", "readonly"]:
            raise ValueError(f"Cannot delete protected role: {role_name}")
            
        # Check if role is in use
        for user_id, user_data in self.users.items():
            if role_name in user_data.get("roles", []):
                raise ValueError(f"Cannot delete role {role_name} because it is assigned to users")
                
        # Delete role
        del self.roles[role_name]
        
        # Save roles to file if configured
        if self.config.roles_file:
            self._save_roles()
            
        return True
    
    def _save_users(self):
        """Save users to file if configured."""
        if not self.config.users_file:
            return
            
        try:
            with open(self.config.users_file, "w") as f:
                json.dump(list(self.users.values()), f, indent=2)
        except Exception as e:
            logger.error(f"Error saving users to file: {e}")
    
    def _save_roles(self):
        """Save roles to file if configured."""
        if not self.config.roles_file:
            return
            
        try:
            # Convert roles to dictionaries
            roles_data = []
            for role in self.roles.values():
                roles_data.append({
                    "name": role.name,
                    "description": role.description,
                    "permissions": [p.value for p in role.permissions]
                })
                
            with open(self.config.roles_file, "w") as f:
                json.dump(roles_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving roles to file: {e}") 