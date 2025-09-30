# key_generator.py
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

def generate_keys():
    """Generate RSA key pair for testing"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate public key
    public_key = private_key.public_key()

    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NG"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lagos"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lagos"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Bank"),
        x509.NameAttribute(NameOID.COMMON_NAME, "testbank.nibss-plc.com.ng"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("testbank.nibss-plc.com.ng"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save certificate
    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Save public key
    with open("nibss_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Keys generated successfully!")
    print("private_key.pem - Your private key for signing")
    print("cert.pem - Your certificate")
    print("nibss_public_key.pem - NIBSS public key for encryption")

if __name__ == "__main__":
    generate_keys()