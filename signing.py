# signing.py
"""
XML Signing Service using cryptography library directly
This avoids the pyOpenSSL dependency issues with signxml
"""
from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import base64
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class XMLSigningService:
    @staticmethod
    def sign_xml(xml_content: str, private_key_path: str, cert_path: str) -> str:
        """
        Sign XML document using W3C XML Signature standard (enveloped signature)
        Manual implementation to avoid pyOpenSSL issues
        """
        try:
            # Parse XML
            root = etree.fromstring(xml_content.encode('utf-8'))

            # Load private key
            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )

            # Load certificate
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(
                    f.read(),
                    backend=default_backend()
                )

            # Canonicalize the XML (C14N)
            canonical_xml = etree.tostring(
                root,
                method='c14n',
                exclusive=False,
                with_comments=False
            )

            # Calculate digest (SHA-256)
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(canonical_xml)
            digest_value = base64.b64encode(digest.finalize()).decode('utf-8')

            # Create SignedInfo
            signed_info = XMLSigningService._create_signed_info(digest_value)

            # Canonicalize SignedInfo
            signed_info_canonical = etree.tostring(
                signed_info,
                method='c14n',
                exclusive=False,
                with_comments=False
            )

            # Sign the SignedInfo
            signature_bytes = private_key.sign(
                signed_info_canonical,
                asym_padding.PKCS1v15(),
                hashes.SHA256()
            )
            signature_value = base64.b64encode(signature_bytes).decode('utf-8')

            # Create complete Signature element
            signature = XMLSigningService._create_signature_element(
                signed_info,
                signature_value,
                cert
            )

            # Add signature to document
            root.append(signature)

            # Return signed XML
            signed_xml = etree.tostring(
                root,
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
    def _create_signed_info(digest_value: str) -> etree.Element:
        """Create SignedInfo element"""
        ds_ns = "http://www.w3.org/2000/09/xmldsig#"

        signed_info = etree.Element(f"{{{ds_ns}}}SignedInfo")

        # CanonicalizationMethod
        c14n_method = etree.SubElement(signed_info, f"{{{ds_ns}}}CanonicalizationMethod")
        c14n_method.set("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")

        # SignatureMethod
        sig_method = etree.SubElement(signed_info, f"{{{ds_ns}}}SignatureMethod")
        sig_method.set("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

        # Reference
        reference = etree.SubElement(signed_info, f"{{{ds_ns}}}Reference")
        reference.set("URI", "")

        # Transforms
        transforms = etree.SubElement(reference, f"{{{ds_ns}}}Transforms")
        transform = etree.SubElement(transforms, f"{{{ds_ns}}}Transform")
        transform.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")

        # DigestMethod
        digest_method = etree.SubElement(reference, f"{{{ds_ns}}}DigestMethod")
        digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

        # DigestValue
        digest_value_elem = etree.SubElement(reference, f"{{{ds_ns}}}DigestValue")
        digest_value_elem.text = digest_value

        return signed_info

    @staticmethod
    def _create_signature_element(signed_info: etree.Element, signature_value: str, cert: x509.Certificate) -> etree.Element:
        """Create complete Signature element"""
        ds_ns = "http://www.w3.org/2000/09/xmldsig#"

        signature = etree.Element(f"{{{ds_ns}}}Signature")

        # Add SignedInfo
        signature.append(signed_info)

        # SignatureValue
        sig_value = etree.SubElement(signature, f"{{{ds_ns}}}SignatureValue")
        sig_value.text = signature_value

        # KeyInfo
        key_info = etree.SubElement(signature, f"{{{ds_ns}}}KeyInfo")
        x509_data = etree.SubElement(key_info, f"{{{ds_ns}}}X509Data")
        x509_cert = etree.SubElement(x509_data, f"{{{ds_ns}}}X509Certificate")

        # Get certificate in base64
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        x509_cert.text = base64.b64encode(cert_der).decode('utf-8')

        return signature

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
            ds_ns = "http://www.w3.org/2000/09/xmldsig#"

            # Find Signature element
            signature = root.find(f".//{{{ds_ns}}}Signature")
            if signature is None:
                logger.error("No signature found in XML")
                return False

            # Extract SignedInfo, SignatureValue, and Certificate
            signed_info = signature.find(f"{{{ds_ns}}}SignedInfo")
            signature_value = signature.find(f"{{{ds_ns}}}SignatureValue")
            x509_cert_elem = signature.find(f".//{{{ds_ns}}}X509Certificate")

            if signed_info is None or signature_value is None:
                logger.error("Incomplete signature structure")
                return False

            # Get certificate
            if x509_cert_elem is not None and x509_cert_elem.text:
                cert_der = base64.b64decode(x509_cert_elem.text)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
            elif cert_path:
                with open(cert_path, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            else:
                logger.error("No certificate available for verification")
                return False

            # Canonicalize SignedInfo
            signed_info_canonical = etree.tostring(
                signed_info,
                method='c14n',
                exclusive=False,
                with_comments=False
            )

            # Decode signature value
            sig_bytes = base64.b64decode(signature_value.text)

            # Verify signature
            public_key = cert.public_key()
            public_key.verify(
                sig_bytes,
                signed_info_canonical,
                asym_padding.PKCS1v15(),
                hashes.SHA256()
            )

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
        return XMLSigningService.verify_signature(signed_xml)