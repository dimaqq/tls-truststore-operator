import pytest as pytest
from scenario import Context

from charm import TLSTrustStoreCharm


@pytest.fixture
def ctx():
    return Context(TLSTrustStoreCharm)
