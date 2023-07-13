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

        self.framework.observe(self.on.install, self._on_install)

        ts_events = self.on['tls_truststore']
        for event in [ts_events.relation_changed, ts_events.relation_created, ts_events.relation_joined, ts_events.relation_departed, ts_events.relation_broken]:
            self.framework.observe(
                event, self._on_tls_truststore_event
            )

    def _on_install(self, _):
        self.unit.status = WaitingStatus("waiting for relations...")

    def is_ready(self):
        """Readiness check."""
        return self.truststore_provider.is_ready()

    def _on_tls_truststore_event(self, _event) -> None:
        """Refresh the store so that all related units can see one another's certs."""
        if not self.is_ready():
            self.unit.status = WaitingStatus("not ready.")
            return

        self.truststore_provider.refresh_store()
        self.unit.status = ActiveStatus()


if __name__ == "__main__":
    main(TLSTrustStoreCharm)
