//! Compatibility exports for cross-platform provisioning-profile parsing and validation.

pub use rustferry_remote::{
    MAX_DECODED_PROFILE_BYTES, ProfileField, ProfileValidationErrors, ProfileValidationIssue,
    ProfileValidationRequest, ProvisioningProfileParseError, ValidatedProvisioningProfile,
    parse_decoded_provisioning_profile, parse_provisioning_profile_value,
    validate_profile_for_target,
};

#[cfg(test)]
mod tests {
    use super::{
        MAX_DECODED_PROFILE_BYTES, ProvisioningProfileParseError,
        parse_decoded_provisioning_profile,
    };

    #[test]
    fn worker_facade_exposes_the_cross_platform_profile_parser() {
        assert_eq!(MAX_DECODED_PROFILE_BYTES, 4 * 1024 * 1024);
        assert_eq!(
            parse_decoded_provisioning_profile(&[]),
            Err(ProvisioningProfileParseError::InputSize)
        );
    }
}
