//! Shared, dependency-light domain vocabulary used across husker's layers.

use serde::{Deserialize, Serialize};

/// The concrete VMM implementation that owns a VM.
///
/// This identity crosses orchestration, runtime dispatch, persistence, and API
/// boundaries. Keeping it here prevents those layers from maintaining subtly
/// different string vocabularies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Firecracker,
    Qemu,
    AppleVz,
}

impl BackendKind {
    pub const ALL: [Self; 3] = [Self::Firecracker, Self::Qemu, Self::AppleVz];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::Qemu => "qemu",
            Self::AppleVz => "apple_vz",
        }
    }
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown backend kind '{0}'")]
pub struct InvalidBackendKind(String);

impl std::str::FromStr for BackendKind {
    type Err = InvalidBackendKind;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "firecracker" => Ok(Self::Firecracker),
            "qemu" => Ok(Self::Qemu),
            "apple_vz" => Ok(Self::AppleVz),
            other => Err(InvalidBackendKind(other.to_string())),
        }
    }
}

/// The guest boot mechanism, without backend-specific artifact paths.
///
/// This identity is used for backend selection, persistence, readiness policy,
/// and API serialization. The stable wire values remain `direct`, `uefi`, and
/// `efi`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BootKind {
    #[default]
    #[serde(rename = "direct")]
    DirectKernel,
    Uefi,
    Efi,
}

impl BootKind {
    pub const ALL: [Self; 3] = [Self::DirectKernel, Self::Uefi, Self::Efi];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectKernel => "direct",
            Self::Uefi => "uefi",
            Self::Efi => "efi",
        }
    }

    pub const fn uses_firmware(self) -> bool {
        matches!(self, Self::Uefi | Self::Efi)
    }
}

impl std::fmt::Display for BootKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown boot kind '{0}'")]
pub struct InvalidBootKind(String);

impl std::str::FromStr for BootKind {
    type Err = InvalidBootKind;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "direct" => Ok(Self::DirectKernel),
            "uefi" => Ok(Self::Uefi),
            "efi" => Ok(Self::Efi),
            other => Err(InvalidBootKind(other.to_string())),
        }
    }
}

/// The artifact shape stored in the managed image catalog.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageKind {
    #[default]
    Rootfs,
    CloudImage,
}

impl ImageKind {
    pub const ALL: [Self; 2] = [Self::Rootfs, Self::CloudImage];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rootfs => "rootfs",
            Self::CloudImage => "cloud-image",
        }
    }
}

impl std::fmt::Display for ImageKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown image kind '{0}'")]
pub struct InvalidImageKind(String);

impl std::str::FromStr for ImageKind {
    type Err = InvalidImageKind;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "rootfs" => Ok(Self::Rootfs),
            "cloud-image" => Ok(Self::CloudImage),
            other => Err(InvalidImageKind(other.to_string())),
        }
    }
}

/// The host networking topology assigned to a VM.
///
/// The stable wire value for [`NetworkMode::Isolated`] is `"none"`, matching
/// the CLI flag while naming the runtime property directly in Rust.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    #[default]
    Nat,
    Bridged,
    #[serde(rename = "none")]
    Isolated,
}

impl NetworkMode {
    pub const ALL: [Self; 3] = [Self::Nat, Self::Bridged, Self::Isolated];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nat => "nat",
            Self::Bridged => "bridged",
            Self::Isolated => "none",
        }
    }
}

impl std::fmt::Display for NetworkMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown network mode '{0}'")]
pub struct InvalidNetworkMode(String);

impl std::str::FromStr for NetworkMode {
    type Err = InvalidNetworkMode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "nat" => Ok(Self::Nat),
            "bridged" => Ok(Self::Bridged),
            "none" => Ok(Self::Isolated),
            other => Err(InvalidNetworkMode(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_kind_has_a_stable_round_trip_for_every_value() {
        for kind in BackendKind::ALL {
            let wire_value = kind.as_str();
            assert_eq!(wire_value.parse::<BackendKind>().unwrap(), kind);
            assert_eq!(kind.to_string(), wire_value);
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{wire_value}\"")
            );
            assert_eq!(
                serde_json::from_str::<BackendKind>(&format!("\"{wire_value}\"")).unwrap(),
                kind
            );
        }

        assert!("QEMU".parse::<BackendKind>().is_err());
        assert!("unknown".parse::<BackendKind>().is_err());
    }

    #[test]
    fn network_mode_has_a_stable_round_trip_for_every_value() {
        for mode in NetworkMode::ALL {
            let wire_value = mode.as_str();
            assert_eq!(wire_value.parse::<NetworkMode>().unwrap(), mode);
            assert_eq!(mode.to_string(), wire_value);
            assert_eq!(
                serde_json::to_string(&mode).unwrap(),
                format!("\"{wire_value}\"")
            );
            assert_eq!(
                serde_json::from_str::<NetworkMode>(&format!("\"{wire_value}\"")).unwrap(),
                mode
            );
        }

        assert!("NAT".parse::<NetworkMode>().is_err());
        assert!("unknown".parse::<NetworkMode>().is_err());
    }

    #[test]
    fn boot_kind_has_a_stable_round_trip_for_every_value() {
        for kind in BootKind::ALL {
            let wire_value = kind.as_str();
            assert_eq!(wire_value.parse::<BootKind>().unwrap(), kind);
            assert_eq!(kind.to_string(), wire_value);
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{wire_value}\"")
            );
            assert_eq!(
                serde_json::from_str::<BootKind>(&format!("\"{wire_value}\"")).unwrap(),
                kind
            );
        }

        assert!("Direct".parse::<BootKind>().is_err());
        assert!("bios".parse::<BootKind>().is_err());
    }

    #[test]
    fn image_kind_has_a_stable_round_trip_for_every_value() {
        for kind in ImageKind::ALL {
            let wire_value = kind.as_str();
            assert_eq!(wire_value.parse::<ImageKind>().unwrap(), kind);
            assert_eq!(kind.to_string(), wire_value);
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{wire_value}\"")
            );
            assert_eq!(
                serde_json::from_str::<ImageKind>(&format!("\"{wire_value}\"")).unwrap(),
                kind
            );
        }

        assert!("cloud_image".parse::<ImageKind>().is_err());
        assert!("disk".parse::<ImageKind>().is_err());
    }
}
