import os
import hashlib
from ctypes import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import fernet
import enclave

# Initialize SGX enclave
ENCLAVE_PATH = "./enclave.signed.so"
enclave_id = sgx_create_enclave(ENCLAVE_PATH, sgx_launch_token_t(), None, None, None)

if enclave_id == None
