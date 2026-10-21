"""B19 (audit retention) needed room in the runtime boundary, which sits near IAM's 6,144-character limit. The room
came from shorter, exact-equivalent wildcards for IAM role actions: the boundary grants and denies exactly what it
did before. These tests expand each statement's IAM patterns, the old ones and today's, over every IAM action and
compare the sets."""

from __future__ import annotations

import fnmatch
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
BOUNDARY = ROOT / "iam" / "templates" / "runtime-boundary.json"

# Every IAM action: the AWS Service Reference (servicereference.us-east-1.amazonaws.com/v1/iam/iam.json, read
# 2026-10-21) and botocore 1.43.109's IAM operations together, 192 names: botocore adds AcquireRole and
# UpdateDelegationRequest, the reference adds actions that are no API call, such as PassRole.
IAM_ACTIONS = frozenset([
    "AcceptDelegationRequest", "AcquireRole", "AddClientIDToOpenIDConnectProvider", "AddRoleToInstanceProfile",
    "AddUserToGroup", "AssociateDelegationRequest", "AttachGroupPolicy", "AttachRolePolicy", "AttachUserPolicy",
    "ChangePassword", "CreateAccessKey", "CreateAccountAlias", "CreateDelegationRequest", "CreateGroup",
    "CreateInstanceProfile", "CreateLoginProfile", "CreateOpenIDConnectProvider", "CreatePolicy",
    "CreatePolicyVersion", "CreateRole", "CreateSAMLProvider", "CreateServiceLinkedRole",
    "CreateServiceSpecificCredential", "CreateUser", "CreateVirtualMFADevice", "DeactivateMFADevice",
    "DeleteAccessKey", "DeleteAccountAlias", "DeleteAccountPasswordPolicy", "DeleteCloudFrontPublicKey",
    "DeleteGroup", "DeleteGroupPolicy", "DeleteInstanceProfile", "DeleteLoginProfile",
    "DeleteOpenIDConnectProvider", "DeletePolicy", "DeletePolicyVersion", "DeleteRole",
    "DeleteRolePermissionsBoundary", "DeleteRolePolicy", "DeleteSAMLProvider", "DeleteSSHPublicKey",
    "DeleteServerCertificate", "DeleteServiceLinkedRole", "DeleteServiceSpecificCredential",
    "DeleteSigningCertificate", "DeleteUser", "DeleteUserPermissionsBoundary", "DeleteUserPolicy",
    "DeleteVirtualMFADevice", "DetachGroupPolicy", "DetachRolePolicy", "DetachUserPolicy",
    "DisableOrganizationsRootCredentialsManagement", "DisableOrganizationsRootSessions",
    "DisableOutboundWebIdentityFederation", "EnableMFADevice", "EnableOrganizationsRootCredentialsManagement",
    "EnableOrganizationsRootSessions", "EnableOutboundWebIdentityFederation", "GenerateCredentialReport",
    "GenerateOrganizationsAccessReport", "GenerateServiceLastAccessedDetails", "GetAccessKeyLastUsed",
    "GetAccountAuthorizationDetails", "GetAccountEmailAddress", "GetAccountName", "GetAccountPasswordPolicy",
    "GetAccountProperties", "GetAccountSummary", "GetCloudFrontPublicKey", "GetContextKeysForCustomPolicy",
    "GetContextKeysForPrincipalPolicy", "GetCredentialReport", "GetDelegationRequest", "GetGroup", "GetGroupPolicy",
    "GetHumanReadableSummary", "GetInstanceProfile", "GetLoginProfile", "GetMFADevice", "GetOpenIDConnectProvider",
    "GetOrganizationsAccessReport", "GetOutboundWebIdentityFederationInfo", "GetPolicy", "GetPolicyVersion",
    "GetRole", "GetRolePolicy", "GetRoleTemplateVersion", "GetSAMLProvider", "GetSSHPublicKey",
    "GetServerCertificate", "GetServiceLastAccessedDetails", "GetServiceLastAccessedDetailsWithEntities",
    "GetServiceLinkedRoleDeletionStatus", "GetUser", "GetUserPolicy", "ListAccessKeys", "ListAccountAliases",
    "ListAttachedGroupPolicies", "ListAttachedRolePolicies", "ListAttachedUserPolicies", "ListCloudFrontPublicKeys",
    "ListDelegationRequests", "ListEntitiesForPolicy", "ListGroupPolicies", "ListGroups", "ListGroupsForUser",
    "ListInstanceProfileTags", "ListInstanceProfiles", "ListInstanceProfilesForRole", "ListMFADeviceTags",
    "ListMFADevices", "ListOpenIDConnectProviderTags", "ListOpenIDConnectProviders", "ListOrganizationsFeatures",
    "ListPolicies", "ListPoliciesGrantingServiceAccess", "ListPolicyTags", "ListPolicyVersions", "ListRolePolicies",
    "ListRoleTags", "ListRoles", "ListSAMLProviderTags", "ListSAMLProviders", "ListSSHPublicKeys",
    "ListSTSRegionalEndpointsStatus", "ListServerCertificateTags", "ListServerCertificates",
    "ListServiceSpecificCredentials", "ListSigningCertificates", "ListUserPolicies", "ListUserTags", "ListUsers",
    "ListVirtualMFADevices", "PassRole", "PutAccountProperties", "PutGroupPolicy", "PutRolePermissionsBoundary",
    "PutRolePolicy", "PutUserPermissionsBoundary", "PutUserPolicy", "RejectDelegationRequest",
    "RemoveClientIDFromOpenIDConnectProvider", "RemoveRoleFromInstanceProfile", "RemoveUserFromGroup",
    "ResetServiceSpecificCredential", "ResyncMFADevice", "SendDelegationToken", "SetDefaultPolicyVersion",
    "SetSTSRegionalEndpointStatus", "SetSecurityTokenServicePreferences", "SimulateCustomPolicy",
    "SimulatePrincipalPolicy", "TagInstanceProfile", "TagMFADevice", "TagOpenIDConnectProvider", "TagPolicy",
    "TagRole", "TagSAMLProvider", "TagServerCertificate", "TagUser", "UntagInstanceProfile", "UntagMFADevice",
    "UntagOpenIDConnectProvider", "UntagPolicy", "UntagRole", "UntagSAMLProvider", "UntagServerCertificate",
    "UntagUser", "UpdateAccessKey", "UpdateAccountEmailAddress", "UpdateAccountName", "UpdateAccountPasswordPolicy",
    "UpdateAssumeRolePolicy", "UpdateCloudFrontPublicKey", "UpdateDelegationRequest", "UpdateGroup",
    "UpdateLoginProfile", "UpdateOpenIDConnectProviderThumbprint", "UpdateRole", "UpdateRoleDescription",
    "UpdateSAMLProvider", "UpdateSSHPublicKey", "UpdateServerCertificate", "UpdateServiceSpecificCredential",
    "UpdateSigningCertificate", "UpdateUser", "UploadCloudFrontPublicKey", "UploadSSHPublicKey",
    "UploadServerCertificate", "UploadSigningCertificate",
])

# The statements' IAM actions before the change (main, 2026-10-21).
BEFORE = {
    "CeilingIam": ["CreateRole", "DeleteRole", "GetRole", "UpdateRole", "TagRole", "UntagRole", "PutRolePolicy",
                   "GetRolePolicy", "DeleteRolePolicy", "AttachRolePolicy", "DetachRolePolicy",
                   "PutRolePermissionsBoundary", "List*", "*InstanceProfile", "PassRole"],
    "DenySelfEdit": ["PutRolePolicy", "DeleteRolePolicy", "AttachRolePolicy", "DetachRolePolicy", "UpdateRole",
                     "UpdateAssumeRolePolicy", "DeleteRole", "TagRole", "UntagRole", "PutRolePermissionsBoundary"],
}


def _statement(sid: str) -> dict:
    doc = json.loads(BOUNDARY.read_text(encoding="utf-8"))
    return next(st for st in doc["Statement"] if st.get("Sid") == sid)


def _reach(patterns: list[str]) -> set[str]:
    """The IAM actions the patterns reach (IAM matches action names case-insensitively)."""
    lowered = [p.lower() for p in patterns]
    return {a for a in IAM_ACTIONS if any(fnmatch.fnmatchcase(a.lower(), p) for p in lowered)}


def _iam_patterns(sid: str) -> list[str]:
    return [a.split(":", 1)[1] for a in _statement(sid)["Action"] if a.startswith("iam:")]


def test_the_ceiling_allows_exactly_the_role_actions_it_did():
    assert _reach(_iam_patterns("CeilingIam")) == _reach(BEFORE["CeilingIam"])


def test_the_deploy_role_still_cannot_edit_itself():
    assert _reach(_iam_patterns("DenySelfEdit")) == _reach(BEFORE["DenySelfEdit"])
    assert _statement("DenySelfEdit")["Resource"] == "arn:aws:iam::*:role/warden-${env}-deploy"
