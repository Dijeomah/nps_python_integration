# main.py
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
from lxml import etree
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
from typing import Optional
import uuid
from datetime import datetime

app = FastAPI(title="NPS Integration API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
NPS_BASE_URL = os.getenv("NPS_BASE_URL", "https://198.51.100.204:8022")
NPS_PACS_ENDPOINT = f"{NPS_BASE_URL}/nps/pacs"

class NPSService:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.nibss_public_key = None
        self.certificate = None
        self.load_keys()

    def load_keys(self):
        """Load RSA keys for signing and encryption"""
        try:
            # Load your private key for signing
            if os.path.exists("private_key.pem"):
                with open("private_key.pem", "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
                print("✓ Private key loaded successfully")
            else:
                print("⚠ Warning: private_key.pem not found")

            # Load your certificate
            if os.path.exists("cert.pem"):
                with open("cert.pem", "rb") as f:
                    cert_data = f.read()
                    self.certificate = cert_data
                    # Also load as public key for reference
                    from cryptography import x509
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    self.public_key = cert.public_key()
                print("✓ Certificate loaded successfully")
            else:
                print("⚠ Warning: cert.pem not found")

            # Load NIBSS public key for encryption
            if os.path.exists("nibss_public_key.pem"):
                with open("nibss_public_key.pem", "rb") as f:
                    self.nibss_public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )
                print("✓ NIBSS public key loaded successfully")
            else:
                print("⚠ Warning: nibss_public_key.pem not found")

        except Exception as e:
            print(f"❌ Error loading keys: {e}")
            raise

nps_service = NPSService()

# XML Template for PACS.008 (ISO 20022)
PACS_008_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.12" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <FIToFICstmrCdtTrf>
        <GrpHdr>
            <MsgId>{msg_id}</MsgId>
            <CreDtTm>{create_dt}</CreDtTm>
            <BtchBookg>false</BtchBookg>
            <NbOfTxs>1</NbOfTxs>
            <SttlmInf>
                <SttlmMtd>CLRG</SttlmMtd>
            </SttlmInf>
            <InstgAgt>
                <FinInstnId>
                    <BICFI>999058</BICFI>
                    <ClrSysMmbId>
                        <MmbId>999058</MmbId>
                    </ClrSysMmbId>
                </FinInstnId>
            </InstgAgt>
            <InstdAgt>
                <FinInstnId>
                    <BICFI>999057</BICFI>
                    <ClrSysMmbId>
                        <MmbId>999057</MmbId>
                    </ClrSysMmbId>
                </FinInstnId>
            </InstdAgt>
        </GrpHdr>
        <CdtTrfTxInf>
            <PmtId>
                <InstrId>{instr_id}</InstrId>
                <EndToEndId>{end_to_end_id}</EndToEndId>
                <TxId>{tx_id}</TxId>
            </PmtId>
            <PmtTpInf>
                <ClrChanl>RTNS</ClrChanl>
                <SvcLvl>
                    <Prtry>0100</Prtry>
                </SvcLvl>
                <LclInstrm>
                    <Prtry>CTAA</Prtry>
                </LclInstrm>
                <CtgyPurp>
                    <Prtry>001</Prtry>
                </CtgyPurp>
            </PmtTpInf>
            <IntrBkSttlmAmt Ccy="NGN">{amount}</IntrBkSttlmAmt>
            <IntrBkSttlmDt>{settlement_date}</IntrBkSttlmDt>
            <ChrgBr>SLEV</ChrgBr>
            <InstgAgt>
                <FinInstnId>
                    <ClrSysMmbId>
                        <MmbId>999058</MmbId>
                    </ClrSysMmbId>
                </FinInstnId>
            </InstgAgt>
            <InstdAgt>
                <FinInstnId>
                    <ClrSysMmbId>
                        <MmbId>999057</MmbId>
                    </ClrSysMmbId>
                </FinInstnId>
            </InstdAgt>
            <Dbtr>
                <Nm>{debtor_name}</Nm>
            </Dbtr>
            <DbtrAcct>
                <Id>
                    <Othr>
                        <Id>{debtor_account}</Id>
                    </Othr>
                </Id>
            </DbtrAcct>
            <DbtrAgt>
                <FinInstnId>
                    <ClrSysMmbId>
                        <MmbId>999058</MmbId>
                    </ClrSysMmbId>
                </FinInstnId>
            </DbtrAgt>
            <CdtrAgt>
                <FinInstnId>
                    <ClrSysMmbId>
                        <MmbId>999057</MmbId>
                    </ClrSysMmbId>
                </FinInstnId>
            </CdtrAgt>
            <Cdtr>
                <Nm>{creditor_name}</Nm>
            </Cdtr>
            <CdtrAcct>
                <Id>
                    <Othr>
                        <Id>{creditor_account}</Id>
                    </Othr>
                </Id>
            </CdtrAcct>
            <RmtInf>
                <Ustrd>Payment Transfer</Ustrd>
            </RmtInf>
        </CdtTrfTxInf>
        <SplmtryData>
            <PlcAndNm>AdditionalVerificationDetails</PlcAndNm>
            <Envlp>
                <CustomData>
                    <DebtorInfo>
                        <AccountDesignation>1</AccountDesignation>
                        <IdType>bvn</IdType>
                        <IdValue>{debtor_bvn}</IdValue>
                        <AccountTier>1</AccountTier>
                    </DebtorInfo>
                    <CreditorInfo>
                        <AccountDesignation>1</AccountDesignation>
                        <IdType>bvn</IdType>
                        <IdValue>{creditor_bvn}</IdValue>
                        <AccountTier>1</AccountTier>
                    </CreditorInfo>
                    <TransactionInfo>
                        <TransactionLocation>01080652440N020900337921E</TransactionLocation>
                        <NameEnquiryMsgId></NameEnquiryMsgId>
                        <ChannelCode>1</ChannelCode>
                        <RiskRating>R000000000000000000B9</RiskRating>
                    </TransactionInfo>
                </CustomData>
            </Envlp>
        </SplmtryData>
    </FIToFICstmrCdtTrf>
</Document>"""

@app.on_event("startup")
async def startup_event():
    """Check if keys are loaded on startup"""
    if not nps_service.private_key:
        print("\n⚠️  WARNING: Private key not loaded. Run key_generator.py first!")
    if not nps_service.nibss_public_key:
        print("\n⚠️  WARNING: NIBSS public key not loaded. Run key_generator.py first!")

@app.get("/")
async def root():
    return {
        "message": "NPS Integration API",
        "status": "running",
        "version": "1.0.0",
        "endpoints": {
            "send_payment": "/send-payment",
            "test_connection": "/test-connection",
            "receive_payment": "/receive-payment",
            "health": "/health"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "keys_loaded": {
            "private_key": nps_service.private_key is not None,
            "certificate": nps_service.certificate is not None,
            "nibss_public_key": nps_service.nibss_public_key is not None
        }
    }