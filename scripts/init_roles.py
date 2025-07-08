import sys
from pathlib import Path

# Add project root to Python path
sys.path.append(str(Path(__file__).parent.parent))

from src.database.database import SessionLocal, init_db
from src.database.models import UserRole
from src.database.repositories import UserRoleRepository


def create_default_roles():
    """Create default roles in the database."""
    db = SessionLocal()
    try:
        role_repo = UserRoleRepository(db)
        
        # Define default roles
        default_roles = [
            {
                "name": "admin",
                "description": "System administrator with full access"
            },
            {
                "name": "healthcare_provider",
                "description": "Healthcare provider with access to patient data"
            },
            {
                "name": "patient",
                "description": "Patient with access to own data"
            }
        ]
        
        # Create roles
        for role_data in default_roles:
            # Check if role already exists
            existing_role = role_repo.get_by_name(role_data["name"])
            if existing_role:
                print(f"Role '{role_data['name']}' already exists")
            else:
                role = role_repo.create(**role_data)
                print(f"Created role: {role.name}")
        
        db.commit()
        print("\nDefault roles initialized successfully!")
        
    except Exception as e:
        print(f"Error creating roles: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    print("Initializing database tables...")
    init_db()
    
    print("\nCreating default roles...")
    create_default_roles()