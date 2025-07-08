import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_jwt_keys(output_dir: str = "./keys"):
    """
    Generate RSA key pair for JWT signing.
    
    Args:
        output_dir: Directory to save keys
    """
    # Create output directory
    keys_dir = Path(output_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate private key
    print("Generating RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Save private key
    private_key_path = keys_dir / "jwt_private_key.pem"
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_path.write_bytes(private_pem)
    
    # Set secure permissions (Unix-like systems)
    try:
        os.chmod(private_key_path, 0o600)
        print(f"Private key saved to: {private_key_path}")
    except Exception as e:
        print(f"Warning: Could not set permissions on private key: {e}")
    
    # Generate and save public key
    print("Generating RSA public key...")
    public_key = private_key.public_key()
    public_key_path = keys_dir / "jwt_public_key.pem"
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_path.write_bytes(public_pem)
    
    try:
        os.chmod(public_key_path, 0o644)
        print(f"Public key saved to: {public_key_path}")
    except Exception as e:
        print(f"Warning: Could not set permissions on public key: {e}")
    
    print("\nKeys generated successfully!")
    print("\nAdd these paths to your .env file:")
    print(f"JWT_PRIVATE_KEY_PATH={private_key_path}")
    print(f"JWT_PUBLIC_KEY_PATH={public_key_path}")
    
    # Display public key for sharing
    print("\nPublic key (can be shared with other services):")
    print(public_pem.decode())


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate JWT RSA key pair")
    parser.add_argument(
        "--output-dir",
        default="./keys",
        help="Directory to save keys (default: ./keys)"
    )
    
    args = parser.parse_args()
    generate_jwt_keys(args.output_dir)