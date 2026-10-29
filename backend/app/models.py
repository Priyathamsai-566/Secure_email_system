from typing import Literal

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: Literal["alice", "bob"]
    password: str = Field(min_length=1, max_length=200)


class KeyGenerateRequest(BaseModel):
    user_id: Literal["alice", "bob"]
    password: str = Field(min_length=8, max_length=200)


class SendMessageRequest(BaseModel):
    sender_id: Literal["alice", "bob"]
    recipient_id: Literal["alice", "bob"]
    password: str = Field(min_length=8, max_length=200)
    subject: str = Field(min_length=1, max_length=300)
    body: str = Field(min_length=1, max_length=100_000)


class DecryptMessageRequest(BaseModel):
    user_id: Literal["alice", "bob"]
    password: str = Field(min_length=8, max_length=200)


class ContactImportRequest(BaseModel):
    owner_id: Literal["alice", "bob"]
    contact_id: Literal["alice", "bob"]
    display_name: str = Field(min_length=1, max_length=100)
    public_key_pem: str = Field(min_length=1, max_length=20_000)
    accept_replacement: bool = False


class TrustRequest(BaseModel):
    owner_id: Literal["alice", "bob"]
    contact_id: Literal["alice", "bob"]
    status: Literal["trusted", "untrusted", "unknown"]
    method: str = Field(min_length=1, max_length=200)
    notes: str = Field(default="", max_length=500)


class InitializeCaRequest(BaseModel):
    password: str = Field(min_length=8, max_length=200)


class IssueCertificateRequest(BaseModel):
    subject_id: Literal["alice", "bob"]
    ca_password: str = Field(min_length=8, max_length=200)


class ValidateCertificateRequest(BaseModel):
    subject_id: Literal["alice", "bob"]
    certificate_pem: str = Field(min_length=1, max_length=50_000)


class VerifyRequest(BaseModel):
    recipient_id: Literal["alice", "bob"]


class LabTamperRequest(BaseModel):
    recipient_id: Literal["alice", "bob"]
    field: Literal["ciphertext_and_tag", "subject"] = "ciphertext_and_tag"