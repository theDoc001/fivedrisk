"""Tests for ActingIdentity primitive (OSS-PASS-THROUGH-IDENTITY-001).

Verifies the dataclass, serialization, default ANONYMOUS, and that the
identity flows through to Action without modifying any other behavior.
"""

from __future__ import annotations

from fivedrisk.classifier import classify_tool_call
from fivedrisk.policy import Policy
from fivedrisk.schema import (
    Action,
    ActingIdentity,
    AttestationSource,
    PrincipalType,
)


class TestActingIdentityDataclass:
    def test_construct_minimal(self) -> None:
        ai = ActingIdentity(principal_id="user-42")
        assert ai.principal_id == "user-42"
        assert ai.principal_type == PrincipalType.ANONYMOUS
        assert ai.attestation_source == AttestationSource.NONE

    def test_construct_full(self) -> None:
        ai = ActingIdentity(
            principal_id="svc-payroll",
            principal_type=PrincipalType.SERVICE,
            attestation_source=AttestationSource.JWT_CLAIM,
            roles=["finance.read", "finance.write"],
            data_scope=["tenant-acme"],
        )
        assert ai.principal_type == PrincipalType.SERVICE
        assert ai.attestation_source == AttestationSource.JWT_CLAIM
        assert ai.roles == ["finance.read", "finance.write"]
        assert ai.data_scope == ["tenant-acme"]

    def test_anonymous_class_method(self) -> None:
        ai = ActingIdentity.anonymous()
        assert ai.principal_type == PrincipalType.ANONYMOUS
        assert ai.attestation_source == AttestationSource.NONE

    def test_to_dict_minimal(self) -> None:
        ai = ActingIdentity(principal_id="user-42")
        d = ai.to_dict()
        assert d["principal_id"] == "user-42"
        assert d["principal_type"] == "ANONYMOUS"
        assert d["attestation_source"] == "NONE"
        assert "roles" not in d
        assert "data_scope" not in d

    def test_to_dict_full(self) -> None:
        ai = ActingIdentity(
            principal_id="svc-payroll",
            principal_type=PrincipalType.SERVICE,
            attestation_source=AttestationSource.HTTP_HEADER,
            roles=["finance.read"],
            data_scope=["tenant-acme"],
        )
        d = ai.to_dict()
        assert d["principal_type"] == "SERVICE"
        assert d["attestation_source"] == "HTTP_HEADER"
        assert d["roles"] == ["finance.read"]
        assert d["data_scope"] == ["tenant-acme"]


class TestActionWithActingIdentity:
    def test_action_accepts_acting_identity(self) -> None:
        ai = ActingIdentity(
            principal_id="user-42",
            principal_type=PrincipalType.USER,
            attestation_source=AttestationSource.HTTP_HEADER,
        )
        action = Action(tool_name="Read", acting_identity=ai)
        assert action.acting_identity is ai

    def test_action_default_acting_identity_is_none(self) -> None:
        action = Action(tool_name="Read")
        assert action.acting_identity is None

    def test_action_to_dict_includes_acting_identity(self) -> None:
        ai = ActingIdentity(
            principal_id="user-42", principal_type=PrincipalType.USER
        )
        action = Action(tool_name="Read", acting_identity=ai)
        d = action.to_dict()
        assert "acting_identity" in d
        assert d["acting_identity"]["principal_id"] == "user-42"
        assert d["acting_identity"]["principal_type"] == "USER"

    def test_action_to_dict_omits_acting_identity_when_none(self) -> None:
        action = Action(tool_name="Read")
        d = action.to_dict()
        assert "acting_identity" not in d


class TestClassifierIdentityIntegration:
    def test_classifier_does_not_set_identity(self) -> None:
        """classify_tool_call leaves acting_identity at default (None).

        Identity attachment is the caller's responsibility per the
        pass-through design.
        """
        policy = Policy()
        action = classify_tool_call("Read", {"path": "/tmp/x"}, policy=policy)
        assert action.acting_identity is None
