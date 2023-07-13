"""
"""
import json
from typing import Dict, List

import pydantic as pydantic
from ops import Relation, CharmBase
from pydantic import Json

# The unique Charmhub library identifier, never change it
LIBID = "a399f21a9e4a4245ac16d98675d158e2"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class Trust(pydantic.BaseModel):
    certificate: str
    # ca: str
    # chain: List[str]


class TrustStoreRequirerUnitDatabagSchema(pydantic.BaseModel):
    trust: Trust


class TrustStoreRequirerSchema(pydantic.BaseModel):
    unit: TrustStoreRequirerUnitDatabagSchema
    app: None


class TrustStoreProviderAppDatabagSchema(pydantic.BaseModel):
    # a mapping from unit names to Trust objects; e.g.
    # {
    #     'traefik/0': {
    #         'certificate': str,
    #     },
    # }
    trust: Json[Dict[str, Trust]]


class TrustStoreProviderSchema(pydantic.BaseModel):
    unit: None
    app: TrustStoreProviderAppDatabagSchema


class TrustStoreProvider:
    def __init__(self, charm: CharmBase,
                 relation_name: str = 'tls-truststore'):
        self._unit = charm.unit
        self._relation_name = relation_name
        self._model = charm.model

    def is_ready(self) -> bool:
        if not self._unit.is_leader():
            return False
        return len(self._model.relations[self._relation_name]) > 0

    @property
    def relations(self) -> List[Relation]:
        return self._model.relations[self._relation_name]

    def refresh_store(self):
        """Publishes all certificates for all remotes to see."""
        if not self._unit.is_leader():
            raise RuntimeError('only leaders can do this')

        app = self._unit.app

        for relation in self.relations:

            data = {}
            for u in relation.units:
                if u.app is app:
                    continue

                # todo: use .load() from Tempo
                cert_for_unit = TrustStoreRequirerUnitDatabagSchema.parse_obj(relation.data[u]).trust.certificate
                data[u.name] = cert_for_unit

            # dump to app databag.
            data = TrustStoreProviderAppDatabagSchema.parse_raw(data)
            relation.data[app]['trust'] = data.json()


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

    def submit_cert(self, cert:       str):
        trust = Trust(certificate=cert)
        self.relation.data[self._unit]['trust'] = trust.json()
