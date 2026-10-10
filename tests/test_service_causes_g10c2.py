"""G10-C2: the fields where AWS itself names a cause - a scaling activity's Cause, a node group's health issue codes, a
failed execution's error, a Lambda function's state reason (AWS-native research 2026-10-10, section 1.8; field names
checked against the botocore 1.43.90 service models). Codes are WARDEN's STATE lines; AWS's prose is quarantined."""

from __future__ import annotations

from test_aws_stack import P, _alert, _backend, _clients, _lambda


def _lines(**labels):
    return _backend(_clients()).logs(_alert(**labels))


def test_a_scheduled_scale_in_is_named_with_its_before_and_after_and_old_activities_are_left_out():
    lines = _lines(asg=f"{P}web")
    [state] = [line for line in lines if line.startswith(f"STATE asg {P}web activity")]
    assert "status=Successful cause=scheduled capacity=6->2" in state, state
    assert any(line.startswith(f"EVENT asg {P}web activity: At ") for line in lines)
    assert not any("an old one" in line for line in lines)  # five hours before the alert


def test_a_node_group_that_cannot_launch_says_why_in_its_own_code():
    lines = _lines(eks_cluster=f"{P}eks")
    assert f"STATE eks/{P}eks nodegroup {P}ng status=DEGRADED issues=[InsufficientFreeAddresses]" in lines, lines
    assert any(line.startswith(f"EVENT eks/{P}eks nodegroup issue:") for line in lines)


def test_a_healthy_node_group_adds_no_line():
    from test_aws_stack import Fake

    eks = _clients()["eks"]
    eks._methods["describe_nodegroup"] = {"nodegroup": {"status": "ACTIVE", "health": {"issues": []}}}
    lines = _backend(_clients(eks=Fake(**eks._methods))).logs(_alert(eks_cluster=f"{P}eks"))
    assert not any(" nodegroup " in line for line in lines)


def test_a_failed_execution_gives_its_error_name_and_its_cause_only_as_quarantined_text():
    lines = _lines(state_machine=f"{P}saga")
    [state] = [line for line in lines if line.startswith(f"STATE states {P}saga failed execution")]
    assert state.endswith("error=States.TaskFailed") and "KeyError" not in state
    assert f"EVENT states {P}saga failure: KeyError: 'sku'" in lines


def test_a_lambda_that_cannot_run_names_the_reason_and_a_healthy_one_adds_no_line():
    from test_aws_stack import Fake

    lam = _lambda()
    original = lam._methods["get_function_configuration"]

    def failed(**kw):
        base = original(**kw) if callable(original) else original
        return {**base, "State": "Failed", "StateReasonCode": "SubnetOutOfIPAddresses"}

    lines = _backend(_clients(**{"lambda": Fake(**{**lam._methods, "get_function_configuration": failed})})).logs(
        _alert(**{"lambda": f"{P}checkout"}))
    assert any(line.startswith(f"STATE lambda {P}checkout state=Failed reason=SubnetOutOfIPAddresses") for line in lines)
    healthy = _lines(**{"lambda": f"{P}checkout"})
    assert not any(line.startswith("STATE lambda ") for line in healthy)
