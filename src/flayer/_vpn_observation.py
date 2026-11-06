"""Enforce frozen creation labels and complete effective ingress at every selected-project boundary."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from flayer._vpn_creation import CreationBaseline
from flayer.core.contracts import StackIdentity
from flayer.profiles.vpn import VpnError
from flayer.providers._yandex_firewall import ExpectedRules, RuleSemantics, SecurityGroupSnapshot
from flayer.providers.contracts import (
    ProviderCapability,
    ProviderError,
    ProviderErrorCode,
    ProviderIdentity,
    ProviderResource,
    ResourceKind,
    ResourceReference,
)
from flayer.providers.lifecycle import MutationError, ResourceSpec
from flayer.vpn_project import VpnYandexProvider


class CreationProvider:
    """A profile-specific lifecycle boundary that never recompiles or relabels original resources."""

    def __init__(self, provider: VpnYandexProvider, baseline: CreationBaseline) -> None:
        """Require the original complete stack scope before any resource observation."""

        if (provider.Identity.providerId != baseline.plan.identity.provider
                or provider.Identity.scopeId != baseline.plan.identity.scopeId):
            raise VpnError("Provider identity differs from the frozen creation scope")

        self.provider = provider
        self.baseline = baseline
        self.specs: Mapping[str, ResourceSpec] = MappingProxyType({spec.logicalId: spec for spec in baseline.plan.resources})

    @property
    def Identity(self) -> ProviderIdentity:
        """Keep credentials external to the immutable original scope."""

        return self.provider.Identity

    @property
    def Capabilities(self) -> frozenset[ProviderCapability]:
        """Retain the actual adapter's capabilities rather than assuming cloud permission."""

        return self.provider.Capabilities

    def _Spec(self, spec: ResourceSpec, identity: StackIdentity | None = None) -> None:
        """Reject a changed desired graph before delegating validation, discovery or mutation."""

        if self.specs.get(spec.logicalId) != spec or identity is not None and identity != self.baseline.plan.identity:
            raise VpnError("Selected lifecycle must use its unchanged frozen resource specs and scope")

    def ValidateSpec(self, spec: ResourceSpec) -> None:
        """Validate only a previously frozen exact spec, including its original bootstrap artifact."""

        self._Spec(spec)
        self.provider.ValidateSpec(spec)

    def _Verify(self, spec: ResourceSpec, resource: ProviderResource) -> ProviderResource:
        """Require complete original creation identity, name and zone for every observed locator."""

        expected = self.baseline.plan.identity
        reference = resource.reference
        zone = dict(spec.parameters).get("zone_id")

        if (reference.providerId != expected.provider or reference.scopeId != expected.scopeId or reference.kind != spec.kind
                or resource.name != spec.name or not resource.HasLabels(spec.OwnershipLabels(expected))
                or zone is not None and resource.zoneId != zone):
            raise VpnError("Cloud observation differs from the frozen creation ownership")

        if spec.kind == ResourceKind.SECURITY_GROUP:
            self.Firewall(resource)

        return resource

    def Firewall(self, resource: ProviderResource) -> SecurityGroupSnapshot:
        """Compare the complete effective rule multiset and original owned network attachment."""

        expected = self.baseline.plan.identity
        networkSpec = self.specs["network"]
        network = self.provider.FindResource(networkSpec, expected)

        if network is None:
            raise VpnError("Security-group creation network is absent")

        self._Verify(networkSpec, network)
        snapshot = self.provider.ReadSecurityGroupRules(resource)

        if (snapshot.networkId != network.reference.resourceId
                or RuleSemantics(snapshot.rules) != RuleSemantics(ExpectedRules(self.specs["firewall"]))):
            raise VpnError("Effective security-group policy differs from the frozen creation baseline")

        return snapshot

    def FindResource(self, spec: ResourceSpec, identity: StackIdentity) -> ProviderResource | None:
        """Discover exact original creation content, never adopt an unexplained effective ingress policy."""

        self._Spec(spec, identity)
        resource = self.provider.FindResource(spec, identity)

        return self._Verify(spec, resource) if resource is not None else None

    def GetResource(self, reference: ResourceReference) -> ProviderResource:
        """Verify the current exact locator's complete spec labels and effective policy on every read."""

        resource = self.provider.GetResource(reference)
        logicalId = dict(resource.labels).get("flayer-resource", "")
        spec = self.specs.get(logicalId)

        if spec is None or resource.reference != reference:
            raise VpnError("Cloud locator is outside the frozen creation graph")

        return self._Verify(spec, resource)

    def CreateResource(
        self, spec: ResourceSpec, identity: StackIdentity, dependencies: Mapping[str, ProviderResource], operationId: str,
    ) -> ProviderResource:
        """Re-observe creation readback; failed post-dispatch proof remains an uncertain mutation."""

        self._Spec(spec, identity)

        if set(dependencies) != set(spec.dependencies):
            raise VpnError("Creation dependencies differ from the original graph")

        try:
            for logicalId, resource in dependencies.items():
                current = self.GetResource(resource.reference)

                if current.reference != resource.reference or dict(current.labels).get("flayer-resource") != logicalId:
                    raise VpnError("An owned creation dependency changed before submission")

        except (ProviderError, VpnError):
            raise MutationError(ProviderErrorCode.CONFLICT, "creation-dependencies", False) from None

        created = self.provider.CreateResource(spec, identity, dependencies, operationId)

        try:
            if dict(created.labels).get("flayer-operation") != operationId:
                raise VpnError("Creation readback lacks its exact operation identity")

            return self._Verify(spec, created)

        except (ProviderError, VpnError):
            raise MutationError(ProviderErrorCode.CONFLICT, "creation-readback", True) from None

    def DeleteResource(
        self, reference: ResourceReference, identity: StackIdentity, logicalId: str, operationId: str | None = None,
    ) -> None:
        """Bind deletion to a freshly verified exact spec and full policy rather than identity labels alone."""

        spec = self.specs.get(logicalId)

        if spec is None:
            raise VpnError("Deletion target is outside the original creation graph")

        self._Spec(spec, identity)

        # Recheck every surviving original resource before each destructive dispatch.
        # A drifted firewall must stop deletion before the instance or disk is removed.
        for original in self.baseline.plan.resources:
            self.FindResource(original, identity)

        try:
            resource = self.GetResource(reference)

        except ProviderError as error:
            if error.code == ProviderErrorCode.NOT_FOUND:
                return

            raise

        policy = self.Firewall(resource) if spec.kind == ResourceKind.SECURITY_GROUP else None
        self.provider.DeleteCreationResource(resource, spec, identity, policy=policy, operationId=operationId)
