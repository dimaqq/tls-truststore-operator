from ops import WaitingStatus
from scenario import State


def test_no_relations(ctx):
    state_out = ctx.run('install', State(leader=True))
    assert isinstance(state_out.status.unit, WaitingStatus)
