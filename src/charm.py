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
import logging

from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus

from charms.tls_certificates_interface.v2.tls_certificates import (
    TLSCertificatesRequiresV2,
)
from charms.tls_truststore_operator.v0.truststore import TrustStoreProvider

logger = logging.getLogger(__name__)


class TLSTrustStoreCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.truststore_provider = TrustStoreProvider(self)

        self.certificates = TLSCertificatesRequiresV2(self, "tls_certificates")
        self.framework.observe(self.on.install, self._on_install)

        self.framework.observe(
            self.on.tls_certificates_relation_changed,
            self._on_tls_certificates_relation_changed
        )
        self.framework.observe(
            self.on.tls_truststore_relation_changed,
            self._on_tls_truststore_relation_changed
        )

    def _on_install(self, _):
        self.unit.status = WaitingStatus('waiting for relations...')

    def is_ready(self):
        return self.truststore_provider.is_ready()

    def _on_tls_truststore_relation_changed(self, _event) -> None:
        # forward csrs to the certificates relation
        if not self.is_ready():
            self.unit.status = WaitingStatus('not ready.')
            return

        for csr in self.truststore_provider.csrs:
            self.certificates.request_certificate_creation(csr)

    def _on_certificates_relation_changed(self, _event) -> None:
        """Publish all certificates over to the tls-truststore side."""
        if not self.is_ready():
            self.unit.status = WaitingStatus('not ready.')
            return

        certificates = _event.relation.data[_event.relation.app]['certificates']
        self.truststore_provider.publish_certificates(certificates)



if __name__ == "__main__":
    main(TLSTrustStoreCharm)
