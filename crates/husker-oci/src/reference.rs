//! Parsing of Docker/OCI image references into registry, repository, and tag.

use crate::OciError;

/// A parsed image reference: which registry to talk to, the repository path,
/// and the tag or digest to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    /// Registry host, e.g. `"docker.io"` or `"ghcr.io"`.
    pub registry: String,
    /// Repository path, e.g. `"library/alpine"` or `"rvben/husker"`.
    pub repository: String,
    /// Tag (`"3.20"`) or digest (`"sha256:..."`).
    pub reference: String,
}

impl ImageReference {
    /// Parse a reference like `alpine`, `alpine:3.20`, `ghcr.io/o/i:tag`, or
    /// `repo@sha256:...`. Docker Hub is the default registry, and bare names
    /// there are namespaced under `library/`.
    pub fn parse(input: &str) -> Result<Self, OciError> {
        let bad = |m: &str| OciError::InvalidReference(input.to_string(), m.to_string());
        if input.is_empty() {
            return Err(bad("empty reference"));
        }

        // Split off the registry: the first path component is the registry only
        // if it looks like a host (contains '.' or ':' or is "localhost").
        let (registry, remainder) = match input.split_once('/') {
            Some((head, rest))
                if head.contains('.') || head.contains(':') || head == "localhost" =>
            {
                (normalize_registry(head), rest.to_string())
            }
            _ => ("docker.io".to_string(), input.to_string()),
        };

        // Split off the tag/digest. A digest uses '@'; a tag uses ':' (the
        // registry port colon, if any, has already been stripped above).
        let (name, reference) = if let Some((name, digest)) = remainder.split_once('@') {
            (name.to_string(), digest.to_string())
        } else if let Some((name, tag)) = remainder.rsplit_once(':') {
            (name.to_string(), tag.to_string())
        } else {
            (remainder.clone(), "latest".to_string())
        };

        if name.is_empty() || reference.is_empty() {
            return Err(bad("missing repository or tag"));
        }

        // Docker Hub namespaces single-component repos under `library/`.
        let repository = if registry == "docker.io" && !name.contains('/') {
            format!("library/{name}")
        } else {
            name
        };

        Ok(Self {
            registry,
            repository,
            reference,
        })
    }

    /// HTTPS base URL for the registry's distribution API.
    pub fn registry_base(&self) -> String {
        if self.registry == "docker.io" {
            "https://registry-1.docker.io".to_string()
        } else {
            format!("https://{}", self.registry)
        }
    }

    /// `(token_url, service)` for the anonymous pull-token request.
    pub fn auth_endpoint(&self) -> (String, String) {
        if self.registry == "docker.io" {
            (
                "https://auth.docker.io/token".to_string(),
                "registry.docker.io".to_string(),
            )
        } else {
            (
                format!("https://{}/token", self.registry),
                self.registry.clone(),
            )
        }
    }
}

/// Map registry aliases to their canonical host.
fn normalize_registry(host: &str) -> String {
    match host {
        "docker.io" | "index.docker.io" | "registry-1.docker.io" => "docker.io".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> ImageReference {
        ImageReference::parse(s).unwrap()
    }

    #[test]
    fn bare_name_defaults_to_dockerhub_library_latest() {
        let r = parse("alpine");
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "latest");
        assert_eq!(r.registry_base(), "https://registry-1.docker.io");
    }

    #[test]
    fn name_with_tag() {
        let r = parse("alpine:3.20");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "3.20");
    }

    #[test]
    fn dockerhub_user_repo_is_not_libraried() {
        let r = parse("rvben/husker:latest");
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "rvben/husker");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn explicit_registry_host() {
        let r = parse("ghcr.io/rvben/husker:v1");
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "rvben/husker");
        assert_eq!(r.reference, "v1");
        assert_eq!(r.registry_base(), "https://ghcr.io");
        assert_eq!(
            r.auth_endpoint(),
            ("https://ghcr.io/token".to_string(), "ghcr.io".to_string())
        );
    }

    #[test]
    fn digest_reference() {
        let r = parse("alpine@sha256:abc123");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "sha256:abc123");
    }

    #[test]
    fn registry_with_port_is_not_confused_with_tag() {
        let r = parse("localhost:5000/myimage:dev");
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "myimage");
        assert_eq!(r.reference, "dev");
        assert_eq!(r.registry_base(), "https://localhost:5000");
    }

    #[test]
    fn empty_is_rejected() {
        assert!(ImageReference::parse("").is_err());
    }
}
