"""
"""
import json
from typing import Dict, List

import pydantic as pydantic
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

    def submit_csr(self, csr):
        self.relation.data[self._unit]['certificate_signing_request'] = csr
