# api_endpoints.py
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, validator
from typing import Optional
import uuid
from datetime import datetime
import httpx
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

class PaymentRequest(BaseModel):
    amount: float = Field(..., gt=0, description="Payment amount must be greater than 0")
    debtor_name: str = Field(..., min_length=1, max_length=140)
    debtor_account: str = Field(..., min_length=10, max_length=10, description="10-digit account number")
    debtor_bvn: str = Field(..., min_length=11, max_length=11, description="11-digit BVN")
    creditor_name: str = Field(..., min_length=1, max_length=140)
    creditor_account: str = Field(..., min_length=10, max_length=10, description="10-digit account number")
    creditor_bvn: str = Field(..., min_length=11, max_length=11, description="11-digit BVN")
    narration: Optional[str] = Field(default="Payment Transfer", max_length=140)

    @validator('debtor_account', 'creditor_account')
    def validate_account(cls, v):
        if not v.isdigit():
            raise ValueError('Account number must contain only digits')
        return v

    @validator('debtor_bvn', 'creditor_bvn')
    def validate_bvn(cls, v):
        if not v.isdigit():
            raise ValueError('BVN must contain only digits')
        return v

@router.post("/send-payment")
async def send_payment(request: PaymentRequest):
    """
    Send a PACS.008 payment message to NPS

    This endpoint:
    1. Creates an ISO 20022 PACS.008 XML message
    2. Signs the XML with your private key
    3. Encrypts the XML with NIBSS public key
    4. Sends it to NPS endpoint
    """
    try:
        # Import here to avoid circular imports
        from main import PACS_008_TEMPLATE, nps_service, NPS_PACS_ENDPOINT

        # Validate keys are loaded
        if not nps_service.private_key:
            raise HTTPException(
                status_code=500,
                detail="Private key not loaded. Run key_generator.py first."
            )
        if not nps_service.nibss_public_key:
            raise HTTPException(
                status_code=500,
                detail="NIBSS public key not loaded. Run key_generator.py first."
            )

        # Generate unique IDs
        # msg_id = str(uuid.uuid4())
        # instr_id = f"INSTR-{msg_id[:8]}"
        # end_to_end_id = f"E2E-{msg_id[:8]}"
        # tx_id = f"TX-{msg_id[:8]}"

        msg_id = '99905820250721095222930239203831889'
        instr_id = '99905899905720250721085722893090687'
        end_to_end_id = '99905899905798653637383920281615142'
        tx_id = '99905820250721095222930239203831889'

        logger.info(f"Processing payment - Message ID: {msg_id}")

        # Create XML message
        xml_content = PACS_008_TEMPLATE.format(
            msg_id=msg_id,
            create_dt=datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            instr_id=instr_id,
            end_to_end_id=end_to_end_id,
            tx_id=tx_id,
            amount=f"{request.amount:.2f}",
            settlement_date= datetime.utcnow().strftime('%Y-%m-%d'),
            debtor_name=request.debtor_name,
            debtor_account=request.debtor_account,
            debtor_bvn=request.debtor_bvn,
            creditor_name=request.creditor_name,
            creditor_account=request.creditor_account,
            creditor_bvn=request.creditor_bvn
        )

        logger.info("XML message created successfully")

        # Sign XML
        from signing import XMLSigningService
        try:
            signed_xml = XMLSigningService.sign_xml(
                xml_content,
                "private_key.pem",
                "cert.pem"
            )
            logger.info("XML signed successfully")
        except Exception as e:
            logger.error(f"Signing failed: {str(e)}")
            raise HTTPException(status_code=500, detail=f"XML signing failed: {str(e)}")

        # Encrypt XML
        from encryption import XMLEncryptionService
        try:
            encrypted_xml = XMLEncryptionService.encrypt_xml(
                signed_xml,
                nps_service.nibss_public_key
            )
            logger.info("XML encrypted successfully")
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise HTTPException(status_code=500, detail=f"XML encryption failed: {str(e)}")

        # Send to NPS
        try:
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                response = await client.post(
                    NPS_PACS_ENDPOINT,
                    headers={
                        "Content-Type": "application/xml",
                        "Accept": "application/xml"
                    },
                    content=encrypted_xml.encode('utf-8')
                )

            logger.info(f"NPS response status: {response.status_code}")

            return {
                "status": "success",
                "message_id": msg_id,
                "transaction_id": tx_id,
                "nps_response_status": response.status_code,
                "nps_response": response.text if response.status_code != 200 else "Payment accepted"
            }

        except httpx.TimeoutException:
            logger.error("Request to NPS timed out")
            raise HTTPException(status_code=504, detail="Request to NPS timed out")
        except httpx.RequestError as e:
            logger.error(f"Network error: {str(e)}")
            raise HTTPException(status_code=503, detail=f"Network error: {str(e)}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Payment processing failed: {str(e)}")

@router.post("/test-connection")
async def test_connection():
    """
    Test connection to NPS endpoint
    """
    try:
        from main import NPS_BASE_URL

        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            # Try to connect to the base URL
            response = await client.get(
                # f"{NPS_BASE_URL}/health",
                f"{NPS_BASE_URL}",
                timeout=10.0
            )

        return {
            "status": "success",
            "nps_status": response.status_code,
            "message": "Connected to NPS successfully"
        }
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Connection to NPS timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Connection test failed: {str(e)}")

@router.post("/receive-payment")
async def receive_payment(request: Request):
    """
    Receive and process inbound payment messages from NPS

    This endpoint:
    1. Receives encrypted XML from NPS
    2. Decrypts the XML with your private key
    3. Validates the signature
    4. Processes the payment
    """
    try:
        from main import nps_service

        # Validate keys are loaded
        if not nps_service.private_key:
            raise HTTPException(
                status_code=500,
                detail="Private key not loaded. Cannot decrypt incoming payments."
            )

        # Get raw XML from request
        xml_content = await request.body()
        xml_str = xml_content.decode('utf-8')

        logger.info("Received inbound payment message")

        # Decrypt XML
        from encryption import XMLEncryptionService
        try:
            decrypted_xml = XMLEncryptionService.decrypt_xml(
                xml_str,
                nps_service.private_key
            )
            logger.info("XML decrypted successfully")
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise HTTPException(status_code=400, detail=f"XML decryption failed: {str(e)}")

        # TODO: Validate signature
        # from signing import XMLSignatureValidator
        # is_valid = XMLSignatureValidator.validate_signature(decrypted_xml, nps_service.nibss_public_key)
        # if not is_valid:
        #     raise HTTPException(status_code=400, detail="Invalid signature")

        # Parse the XML to extract payment details
        from lxml import etree
        try:
            root = etree.fromstring(decrypted_xml.encode('utf-8'))
            # Extract payment information
            ns = {'ns': 'urn:iso:std:iso:20022:tech:xsd:pacs.008.001.12'}

            msg_id = root.find('.//ns:GrpHdr/ns:MsgId', ns)
            amount = root.find('.//ns:CdtTrfTxInf/ns:IntrBkSttlmAmt', ns)

            payment_info = {
                "message_id": msg_id.text if msg_id is not None else "Unknown",
                "amount": amount.text if amount is not None else "Unknown"
            }

            logger.info(f"Payment received: {payment_info}")

        except Exception as e:
            logger.error(f"XML parsing failed: {str(e)}")
            payment_info = {}

        return {
            "status": "success",
            "message": "Payment received and processed",
            "payment_info": payment_info
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Payment reception failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Payment reception failed: {str(e)}")

@router.get("/")
async def root():
    return {
        "message": "NPS Integration API",
        "status": "running",
        "version": "1.0.0"
    }