import pytest

from promptfence import ToolBudget, ToolPolicy


def test_allow_list_permits_named_tools():
    policy = ToolPolicy.of("run_sql", "request_human_review")
    assert policy.permits("run_sql")
    assert not policy.permits("delete_all_records")


def test_empty_policy_denies_everything():
    assert not ToolPolicy.of().permits("anything")


def test_check_raises_for_unauthorized_tool():
    policy = ToolPolicy.of("run_sql")
    with pytest.raises(PermissionError):
        policy.check("exfiltrate")


def test_budget_allows_up_to_cap_then_halts():
    budget = ToolBudget(cap=2)
    assert budget.request()
    assert budget.request()
    assert not budget.request()
    assert budget.halted
    assert budget.executed == 2
    assert budget.attempted == 3


def test_budget_remaining_never_negative():
    budget = ToolBudget(cap=1)
    budget.request()
    budget.request()
    assert budget.remaining == 0
