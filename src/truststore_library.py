from typing import Callable, Optional, Union

from ops.charm import CharmBase
from ops.framework import EventBase, Framework, Object
from ops.model import (
    ActiveStatus,
    WaitingStatus
)

from charms.tls_certificates_interface.v2.tls_certificates import (
    AllCertificatesInvalidatedEvent,
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateInvalidatedEvent,
)

class ObservabilityTruststore(Object):
    def __init__(
        self,
        charm: CharmBase,
        private_key_password: bytes,
        generate_private_key: Callable,
        generate_csr: Callable,
        cert_subject: Optional[str] = None,
        peer_relation_name: str = "replicas",
        truststore_relation_name: str = "tls-truststore",
        key: str = "observability-truststore",
        ):
        super().__init__(charm, key)

        self.charm = charm
        self.private_key_password = private_key_password
        self.generate_private_key = generate_private_key
        self.generate_csr = generate_csr
        self.cert_subject = charm.unit.name if not cert_subject else cert_subject
        self.peer_relation_name = peer_relation_name
        self.truststore_relation_name = truststore_relation_name

        self.framework.observe(charm.on.install, self._on_install)
        self.framework.observe(charm.on[truststore_relation_name].relation_joined, self._on_truststore_relation_joined)
        self.framework.observe(charm.on[truststore_relation_name].certificate_available, self._on_certificate_available)
        self.framework.observe(charm.on[truststore_relation_name].certificate_expiring, self._on_certificate_expiring)



    def _is_peer_relation_ready(self, event: EventBase) -> Optional[Relation]:
        """Check if the peer relation is ready for keys storage."""
        replicas_relation = self.charm.model.get_relation("replicas")
        if not replicas_relation:
            self.charm.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return None
        return replicas_relation

    def _on_install(self, event):
        """Generate the private key and store it an a peer relation."""
        if replicas_relation := self._is_peer_relation_ready(event):
            private_key = self.generate_private_key(self.private_key_password)
            replicas_relation.data[self.charm.app].update(
                {
                    "private_key_password": self.private_key_password.decode(),
                    "private_key": private_key.decode()
                }
            )

    def _on_truststore_relation_joined(
        self,
        event: RelationJoinedEvent,
        ) -> None:
        """Generate the CSR and send it over relation data."""
        if replicas_relation := self._is_peer_relation_ready(event):
            private_key_password = replicas_relation.data[self.charm.app].get("private_key_password")
            private_key = replicas_relation.data[self.charm.app].get("private_key")
            if not private_key_password or not private_key:
                return # TODO is return okay?
            csr = self.generate_csr(
                private_key=private_key.encode(),
                private_key_password=private_key_password.encode(),
                subject=self.cert_subject,
            )
            replicas_relation.data[self.charm.app].update({"csr": csr.decode()})
            truststore_relation = self.charm.model.get_relation(self.truststore_relation_name)
            if truststore_relation:
                truststore_relation.data[self.charm.unit].update({"csr": csr.decode()})
 
    def _on_certificate_available(
        self,
        event: CertificateAvailableEvent
    ) -> None:
        """Get the certificate from the event and store it in a peer relation."""
        if replicas_relation := self._is_peer_relation_ready(event):
            replicas_relation.data[self.charm.app].update({
                "certificate": event.certificate,
                "ca": event.ca,
                "chain": event.chain,
            })
            self.charm.unit.status = ActiveStatus() # TODO correct? will it override a Blocked ?

    def _on_certificate_expiring(
        self,
        event: Union[CertificateExpiringEvent, CertificateInvalidatedEvent]
    ) -> None:
        if replicas_relation := self._is_peer_relation_ready(event):
            old_csr = replicas_relation.data[self.charm.app].get("csr")
            if not old_csr:
                return # TODO what to do here? there should always be a csr ?
            private_key_password = replicas_relation.data[self.charm.app].get("private_key_password")
            private_key = replicas_relation.data[self.charm.app].get("private_key")
            if not private_key_password or not private_key:
                return # TODO is return okay ?
            new_csr = self.generate_csr(
                private_key=private_key.encode(),
                private_key_password=private_key_password.encode(),
                subject=self.cert_subject,
            )
            # TODO somehow trigger tls_certificates.request_certificate_renewal,
            #        NOT certificate emission
            replicas_relation.data[self.charm.app].update({"csr": new_csr.decode()})
            truststore_relation = self.charm.model.get_relation(self.truststore_relation_name)
            if truststore_relation:
                truststore_relation.data[self.charm.unit].update({"csr": new_csr.decode()})

    # TODO: write the others _on_* handlers

    def _on_certificate_revoked(self, event) -> None:
        pass 
    
    def _on_certificate_invalidated(self, event: CertificateInvalidatedEvent) -> None:
        pass

    def _on_all_certificates_invalidated(self, event: AllCertificatesInvalidatedEvent) -> None:
        pass



