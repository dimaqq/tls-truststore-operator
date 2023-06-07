import pytest as pytest
from charm import TLSTrustStoreCharm
from scenario import Context


@pytest.fixture
def ctx():
    return Context(TLSTrustStoreCharm)
