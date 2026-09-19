"""
KMS Provider Factory — maps provider names to provider instances.
"""
from app.kms_providers.aws_kms_sim  import AWSKMSProvider
from app.kms_providers.azure_kv_sim import AzureKeyVaultProvider
from app.kms_providers.gcp_kms_sim  import GCPCloudKMSProvider

_PROVIDERS = {
    # Primary names (report nomenclature)
    "aws_kms":   AWSKMSProvider(),
    "azure_kv":  AzureKeyVaultProvider(),
    "gcp_kms":   GCPCloudKMSProvider(),
    # Legacy / alternate names for backward compatibility
    "aws_sim":   AWSKMSProvider(),
    "azure_sim": AzureKeyVaultProvider(),
    "gcp_sim":   GCPCloudKMSProvider(),
}


def get_provider(name: str):
    provider = _PROVIDERS.get(name)
    if not provider:
        raise ValueError(
            f"Unknown KMS provider: '{name}'. "
            f"Valid options: {list(_PROVIDERS.keys())}"
        )
    return provider


def all_providers() -> dict:
    """Return health info for every unique provider."""
    seen = set()
    result = {}
    for name, p in _PROVIDERS.items():
        if p.provider_name not in seen:
            seen.add(p.provider_name)
            result[p.provider_name] = p.health() if hasattr(p, "health") else {}
    return result
