"""
"""
import json
import uuid
from ipaddress import IPv4Address
from typing import Dict, List, Optional

import pydantic as pydantic
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from ops import Unit, Model, Relation
from pydantic import Json

# The unique Charmhub library identifier, never change it
LIBID = "a399f21a9e4a4245ac16d98675d158e2"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class TrustStoreRequirerUnitDatabagSchema(pydantic.BaseModel):
    csr: str


class Trust(pydantic.BaseModel):
    certificate: str


class TrustStoreProviderAppDatabagSchema(pydantic.BaseModel):
    certificate: str
    # a mapping from unit names to Trust objects
    trust: Json[Dict[str, Trust]]


def generate_private_key(
        password: Optional[bytes] = None,
        key_size: int = 2048,
        public_exponent: int = 65537,
) -> bytes:
    """Generates a private key.

    Args:
        password (bytes): Password for decrypting the private key
        key_size (int): Key size in bytes
        public_exponent: Public exponent.

    Returns:
        bytes: Private Key
    """
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption(),
    )
    return key_bytes


def generate_csr(
        private_key: bytes,
        subject: str,
        add_unique_id_to_subject_name: bool = True,
        organization: Optional[str] = None,
        email_address: Optional[str] = None,
        country_name: Optional[str] = None,
        private_key_password: Optional[bytes] = None,
        sans: Optional[List[str]] = None,
        sans_oid: Optional[List[str]] = None,
        sans_ip: Optional[List[str]] = None,
        sans_dns: Optional[List[str]] = None,
        additional_critical_extensions: Optional[List] = None,
) -> bytes:
    """Generates a CSR using private key and subject.

    Args:
        private_key (bytes): Private key
        subject (str): CSR Subject.
        add_unique_id_to_subject_name (bool): Whether a unique ID must be added to the CSR's
            subject name. Always leave to "True" when the CSR is used to request certificates
            using the tls-certificates relation.
        organization (str): Name of organization.
        email_address (str): Email address.
        country_name (str): Country Name.
        private_key_password (bytes): Private key password
        sans (list): Use sans_dns - this will be deprecated in a future release
            List of DNS subject alternative names (keeping it for now for backward compatibility)
        sans_oid (list): List of registered ID SANs
        sans_dns (list): List of DNS subject alternative names (similar to the arg: sans)
        sans_ip (list): List of IP subject alternative names
        additional_critical_extensions (list): List if critical additional extension objects.
            Object must be a x509 ExtensionType.

    Returns:
        bytes: CSR
    """
    signing_key = serialization.load_pem_private_key(private_key, password=private_key_password)
    subject_name = [x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)]
    if add_unique_id_to_subject_name:
        unique_identifier = uuid.uuid4()
        subject_name.append(
            x509.NameAttribute(x509.NameOID.X500_UNIQUE_IDENTIFIER, str(unique_identifier))
        )
    if organization:
        subject_name.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization))
    if email_address:
        subject_name.append(x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, email_address))
    if country_name:
        subject_name.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country_name))
    csr = x509.CertificateSigningRequestBuilder(subject_name=x509.Name(subject_name))

    _sans: List[x509.GeneralName] = []
    if sans_oid:
        _sans.extend([x509.RegisteredID(x509.ObjectIdentifier(san)) for san in sans_oid])
    if sans_ip:
        _sans.extend([x509.IPAddress(IPv4Address(san)) for san in sans_ip])
    if sans:
        _sans.extend([x509.DNSName(san) for san in sans])
    if sans_dns:
        _sans.extend([x509.DNSName(san) for san in sans_dns])
    if _sans:
        csr = csr.add_extension(x509.SubjectAlternativeName(set(_sans)), critical=False)

    if additional_critical_extensions:
        for extension in additional_critical_extensions:
            csr = csr.add_extension(extension, critical=True)

    signed_certificate = csr.sign(signing_key, hashes.SHA256())  # type: ignore[arg-type]
    return signed_certificate.public_bytes(serialization.Encoding.PEM)


class TrustStoreProvider:
    def __init__(self, unit: Unit, relation_name: str, model: Model):
        self._unit = unit
        self._relation_name = relation_name
        self._model = model
        if not unit.is_leader():
            raise RuntimeError('only leaders should use this object')

    def is_ready(self) -> bool:
        return len(self._model.relations[self._relation_name]) > 0

    @property
    def relations(self) -> List[Relation]:
        return self._model.relations[self._relation_name]

    def csrs(self):
        csrs = []
        app = self._unit.app

        for relation in self.relations:
            for u in relation.units:
                if u.app is app:
                    continue
                csrs.append(relation.data[u]['certificate_signing_request'])
        return csrs

    def publish_certificates(self, certificates):
        """Publishes the certificates for all remotes to see."""
        app = self._unit.app

        for relation in self.relations:
            app_databag = relation.data[app]
            for u in relation.units:
                if u.app is app:
                    continue

                csr_for_unit = relation.data[u]['certificate_signing_request']

                # find what certificate corresponds to the unit that requested it
                cert = next(filter(
                    lambda cert: cert['certificate_signing_request'] == csr_for_unit,
                    certificates
                ))

                app_databag[u.name] = json.dumps(cert)


class TrustStoreRequirer:
    def __init__(self, unit: Unit, relation_name: str, model: Model):
        self._unit = unit
        self._relation_name = relation_name
        self._model = model

    def is_ready(self) -> bool:
        return len(self._model.relations[self._relation_name]) == 1

    @property
    def relation(self) -> Relation:
        rels = self._model.relations[self._relation_name]
        if not len(rels) == 1:
            raise RuntimeError(f'too many or too few relations on {self._relation_name}')
        return rels[0]

    @staticmethod
    def generate_private_key(password: str):
        return generate_private_key(password=password.encode('utf-8'))

    def request_certificate(self, password: str, private_key: str, subject: str):
        csr = generate_csr(
            private_key=private_key.encode('utf-8'),
            private_key_password=password.encode(),
            subject=subject,
        ).decode()
        self.relation.data[self._unit]['certificate_signing_request'] = csr
