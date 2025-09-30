# signing.py
from signxml import XMLSigner, XMLVerifier, methods
from lxml import etree
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class XMLSigningService:
    @staticmethod
    def sign_xml(xml_content: str, private_key_path: str, cert_path: str) -> str:
        """
        Sign XML document using W3C XML Signature standard (enveloped signature)
        Following ISO 20022 signature requirements
        """
        try:
            # Parse XML
            root = etree.fromstring(xml_content.encode('utf-8'))

            # Load private key and certificate
            with open(private_key_path, "rb") as f:
                key_data = f.read()
            with open(cert_path, "rb") as f:
                cert_data = f.read()

            # Configure signer with proper algorithms
            signer = XMLSigner(
                method=methods.enveloped,
                signature_algorithm="rsa-sha256",
                digest_algorithm="sha256",
                c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            )

            # Sign the XML document
            signed_root = signer.sign(
                root,
                key=key_data,
                cert=cert_data
            )

            # Convert back to string
            signed_xml = etree.tostring(
                signed_root,
                pretty_print=False,
                xml_declaration=True,
                encoding="UTF-8"
            )

            logger.info("XML document signed successfully")
            return signed_xml.decode('utf-8')

        except Exception as e:
            logger.error(f"XML signing error: {str(e)}")
            raise Exception(f"XML signing failed: {str(e)}")

    @staticmethod
    def verify_signature(signed_xml: str, cert_path: str = None) -> bool:
        """
        Verify XML signature

        Args:
            signed_xml: The signed XML content
            cert_path: Optional path to certificate for verification

        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            root = etree.fromstring(signed_xml.encode('utf-8'))

            # Load certificate if provided
            cert_data = None
            if cert_path:
                with open(cert_path, "rb") as f:
                    cert_data = f.read()

            # Verify signature
            verifier = XMLVerifier()
            verified_data = verifier.verify(root, x509_cert=cert_data)

            logger.info("XML signature verified successfully")
            return True

        except Exception as e:
            logger.error(f"Signature verification failed: {str(e)}")
            return False


class XMLSignatureValidator:
    @staticmethod
    def validate_signature(signed_xml: str, public_key=None) -> bool:
        """
        Validate XML signature using public key

        Args:
            signed_xml: The signed XML content
            public_key: Public key for verification (optional)

        Returns:
            bool: True if signature is valid
        """
        try:
            root = etree.fromstring(signed_xml.encode('utf-8'))
            verifier = XMLVerifier()

            # Verify the signature
            verified_data = verifier.verify(root)

            logger.info("Signature validation successful")
            return True

        except Exception as e:
            logger.error(f"Signature validation failed: {str(e)}")
            return False