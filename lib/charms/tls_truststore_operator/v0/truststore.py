"""
"""
import json
from typing import Dict, List

import pydantic as pydantic
from ops import Unit, Model, Relation, CharmBase
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
    certificate_signing_request: str
    ca: str
    chain: List[str]


class TrustStoreProviderAppDatabagSchema(pydantic.BaseModel):
    # a mapping from unit names to Trust objects; e.g.
    # {
    #     'traefik/0': {
    #         'certificate': str,
    #         'certificate_signing_request': str,
    #         'ca': str,
    #         'chain': List[str],
    #     },
    # }
    trust: Json[Dict[str, Trust]]


class TrustStoreProvider:
    def __init__(self, charm: CharmBase,
                 relation_name: str = 'tls_truststore'):
        self._unit = unit = charm.unit
        self._relation_name = relation_name
        self._model = charm.model

        if not unit.is_leader():
            raise RuntimeError('only leaders should use this object')

    def is_ready(self) -> bool:
        return len(self._model.relations[self._relation_name]) > 0

    @property
    def relations(self) -> List[Relation]:
        return self._model.relations[self._relation_name]

    @property
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

            data = {}
            for u in relation.units:
                if u.app is app:
                    continue

                csr_for_unit = relation.data[u]['certificate_signing_request']

                # FIXME: this has horrible O, could optimize
                # find what certificate corresponds to the unit that requested it
                cert = next(filter(
                    lambda cert: cert['certificate_signing_request'] == csr_for_unit,
                    certificates
                ))

                data[u.name] = cert

            # dump to app databag.
            relation.data[app]['trust'] = json.dumps(data)


class TrustStoreRequirer:
    def __init__(self, charm: CharmBase, relation_name: str):
        self._unit = charm.unit
        self._relation_name = relation_name
        self._model = charm.model

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
