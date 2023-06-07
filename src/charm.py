#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service.

Refer to the following post for a quick-start guide that will help you
develop a new k8s charm using the Operator Framework:

    https://discourse.charmhub.io/t/4208
"""
import json
import logging

from charms.tls_certificates_interface.v2.tls_certificates import (
    TLSCertificatesRequiresV2,
)
from charms.tls_truststore_operator.v0.truststore import TrustStoreProvider
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus

logger = logging.getLogger(__name__)


class TLSTrustStoreCharm(CharmBase):
    """Charm the TLS Trust."""

    def __init__(self, *args):
        super().__init__(*args)
        self.truststore_provider = TrustStoreProvider(self)

        self.certificates = TLSCertificatesRequiresV2(self, "tls-certificates")
        self.framework.observe(self.on.install, self._on_install)

        self.framework.observe(
            self.on.tls_certificates_relation_changed, self._on_tls_certificates_relation_changed
        )
        self.framework.observe(
            self.on.tls_truststore_relation_changed, self._on_tls_truststore_relation_changed
        )

    def _on_install(self, _):
        self.unit.status = WaitingStatus("waiting for relations...")

    def is_ready(self):
        """Readiness check."""
        return self.truststore_provider.is_ready()

    def _on_tls_truststore_relation_changed(self, _event) -> None:
        # forward csrs to the certificates relation
        if not self.is_ready():
            self.unit.status = WaitingStatus("not ready.")
            return

        for csr in self.truststore_provider.csrs:
            self.certificates.request_certificate_creation(csr.encode("utf-8"))
        self.unit.status = ActiveStatus()

    def _on_tls_certificates_relation_changed(self, _event) -> None:
        """Publish all certificates over to the tls-truststore side."""
        if not self.is_ready():
            self.unit.status = WaitingStatus("not ready.")
            return

        raw_certificates = _event.relation.data[_event.relation.app]["certificates"]
        certificates = json.loads(raw_certificates)
        self.truststore_provider.publish_certificates(certificates)
        self.unit.status = ActiveStatus()


if __name__ == "__main__":
    main(TLSTrustStoreCharm)
