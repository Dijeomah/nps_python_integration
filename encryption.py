# encryption.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64
from lxml import etree

class XMLEncryptionService:
    @staticmethod
    def encrypt_xml(xml_content: str, public_key) -> str:
        """
        Encrypt XML using AES-256-GCM for payload and RSA-OAEP for session key
        Following ISO 20022 XML Encryption standards
        """
        try:
            # Parse XML
            root = etree.fromstring(xml_content.encode('utf-8'))

            # 1. Generate AES-256 session key
            session_key = os.urandom(32)  # 256 bits

            # 2. Encrypt session key with RSA public key (RSA-OAEP with SHA-256)
            encrypted_session_key = public_key.encrypt(
                session_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 3. Find the element to encrypt (FIToFICstmrCdtTrf)
            # Support multiple namespace formats
            element_to_encrypt = root.find('.//{urn:iso:std:iso:20022:tech:xsd:pacs.008.001.12}FIToFICstmrCdtTrf')
            if element_to_encrypt is None:
                # Try without namespace
                element_to_encrypt = root.find('.//FIToFICstmrCdtTrf')
            if element_to_encrypt is None:
                raise Exception("Could not find FIToFICstmrCdtTrf element to encrypt")

            # Get the original element content
            original_content = etree.tostring(element_to_encrypt, encoding='utf-8')

            # 4. Encrypt the content with AES-256-GCM
            iv = os.urandom(12)  # GCM standard IV size is 12 bytes
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_content = encryptor.update(original_content) + encryptor.finalize()
            auth_tag = encryptor.tag

            # 5. Create EncryptedData structure following XML Encryption standard
            enc_ns = "http://www.w3.org/2001/04/xmlenc#"
            ds_ns = "http://www.w3.org/2000/09/xmldsig#"

            encrypted_data = etree.Element(f"{{{enc_ns}}}EncryptedData")
            encrypted_data.set("Type", f"{enc_ns}Content")

            # Encryption method for content
            encryption_method = etree.SubElement(encrypted_data, f"{{{enc_ns}}}EncryptionMethod")
            encryption_method.set("Algorithm", f"{enc_ns}aes256-gcm")

            # Key info
            key_info = etree.SubElement(encrypted_data, f"{{{ds_ns}}}KeyInfo")
            encrypted_key = etree.SubElement(key_info, f"{{{enc_ns}}}EncryptedKey")

            # Encryption method for key
            key_encryption_method = etree.SubElement(encrypted_key, f"{{{enc_ns}}}EncryptionMethod")
            key_encryption_method.set("Algorithm", f"{enc_ns}rsa-oaep-mgf1p")

            # Add digest method for OAEP
            digest_method = etree.SubElement(key_encryption_method, f"{{{ds_ns}}}DigestMethod")
            digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

            # Cipher data for encrypted session key
            key_cipher_data = etree.SubElement(encrypted_key, f"{{{enc_ns}}}CipherData")
            key_cipher_value = etree.SubElement(key_cipher_data, f"{{{enc_ns}}}CipherValue")
            key_cipher_value.text = base64.b64encode(encrypted_session_key).decode('utf-8')

            # Cipher data for encrypted content
            cipher_data = etree.SubElement(encrypted_data, f"{{{enc_ns}}}CipherData")
            cipher_value = etree.SubElement(cipher_data, f"{{{enc_ns}}}CipherValue")

            # Combine IV + encrypted content + auth tag (GCM format)
            full_encrypted_data = iv + encrypted_content + auth_tag
            cipher_value.text = base64.b64encode(full_encrypted_data).decode('utf-8')

            # 6. Replace original element with encrypted data
            parent = element_to_encrypt.getparent()
            parent.replace(element_to_encrypt, encrypted_data)

            # Return as string with XML declaration
            return etree.tostring(
                root,
                pretty_print=False,
                xml_declaration=True,
                encoding="UTF-8"
            ).decode('utf-8')

        except Exception as e:
            raise Exception(f"XML encryption failed: {str(e)}")

    @staticmethod
    def decrypt_xml(encrypted_xml: str, private_key) -> str:
        """
        Decrypt XML encrypted with AES-256-GCM and RSA-OAEP
        """
        try:
            root = etree.fromstring(encrypted_xml.encode('utf-8'))

            enc_ns = "http://www.w3.org/2001/04/xmlenc#"
            ds_ns = "http://www.w3.org/2000/09/xmldsig#"

            # Find EncryptedData element
            encrypted_data = root.find(f'.//{{{enc_ns}}}EncryptedData')
            if encrypted_data is None:
                # If no encryption found, return as-is
                return encrypted_xml

            # Extract encrypted session key
            encrypted_key_elem = encrypted_data.find(f'.//{{{enc_ns}}}EncryptedKey')
            if encrypted_key_elem is None:
                raise Exception("EncryptedKey element not found")

            cipher_value_elem = encrypted_key_elem.find(f'.//{{{enc_ns}}}CipherValue')
            if cipher_value_elem is None or cipher_value_elem.text is None:
                raise Exception("CipherValue for key not found")

            encrypted_session_key = base64.b64decode(cipher_value_elem.text)

            # Decrypt session key with private key
            session_key = private_key.decrypt(
                encrypted_session_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Extract encrypted content
            content_cipher_value = encrypted_data.find(f'.//{{{enc_ns}}}CipherData/{{{enc_ns}}}CipherValue')
            if content_cipher_value is None or content_cipher_value.text is None:
                raise Exception("CipherValue for content not found")

            full_encrypted_data = base64.b64decode(content_cipher_value.text)

            # Split IV, encrypted content, and auth tag
            # GCM uses 12-byte IV and 16-byte auth tag
            if len(full_encrypted_data) < 28:  # 12 + 16
                raise Exception("Encrypted data is too short")

            iv = full_encrypted_data[:12]
            encrypted_content = full_encrypted_data[12:-16]
            auth_tag = full_encrypted_data[-16:]

            # Decrypt content with AES-GCM
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(iv, auth_tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

            # Parse decrypted content and replace EncryptedData
            decrypted_element = etree.fromstring(decrypted_content)
            parent = encrypted_data.getparent()
            parent.replace(encrypted_data, decrypted_element)

            return etree.tostring(
                root,
                pretty_print=False,
                xml_declaration=True,
                encoding="UTF-8"
            ).decode('utf-8')

        except Exception as e:
            raise Exception(f"XML decryption failed: {str(e)}")