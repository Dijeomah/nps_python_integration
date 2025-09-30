from signxml import XMLSigner, methods
from lxml import etree

# 1. Load XML
with open("pacs008.xml", "rb") as f:
    xml_data = f.read()
root = etree.fromstring(xml_data)

# 2. Sign XML (RSA-SHA256, C14n)
signer = XMLSigner(
    method=methods.enveloped,
    signature_algorithm="rsa-sha256",
    digest_algorithm="sha256",
    c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
)

# 3. Load Private Key & Certificate
with open("private_key.pem", "rb") as f:
    key_data = f.read()
with open("cert.pem", "rb") as f:
    cert_data = f.read()

# 4. Sign Document
signed_root = signer.sign(root, key=key_data, cert=cert_data)

# 5. Output Signed XML
signed_xml = etree.tostring(signed_root, pretty_print=True, xml_declaration=True, encoding="UTF-8")
with open("pacs008_signed.xml", "wb") as f:
    f.write(signed_xml)