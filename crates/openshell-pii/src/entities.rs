// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! PII entity type definitions with compiled regex patterns.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::LazyLock;

/// Supported PII entity types.
///
/// Variants fall into two categories:
/// - **Regex-detected**: Have compiled patterns in `builtin_patterns()` (Ssn through Passport).
/// - **NER-only**: Detected by the ML-based NER service (Person through NationalId).
///   These have no regex patterns and require the `ner` feature and a running NER service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    // -- Regex-detected entity types --
    Ssn,
    CreditCard,
    Email,
    Phone,
    IpAddress,
    AwsAccessKey,
    AwsSecretKey,
    Jwt,
    ApiKey,
    Passport,
    // -- NER-only entity types (no regex pattern) --
    Person,
    Organization,
    Address,
    DateOfBirth,
    MedicalTerm,
    Location,
    NationalId,
    /// User-defined custom pattern (name carried in PiiDetection metadata).
    Custom,
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssn => write!(f, "ssn"),
            Self::CreditCard => write!(f, "credit_card"),
            Self::Email => write!(f, "email"),
            Self::Phone => write!(f, "phone"),
            Self::IpAddress => write!(f, "ip_address"),
            Self::AwsAccessKey => write!(f, "aws_access_key"),
            Self::AwsSecretKey => write!(f, "aws_secret_key"),
            Self::Jwt => write!(f, "jwt"),
            Self::ApiKey => write!(f, "api_key"),
            Self::Passport => write!(f, "passport"),
            Self::Person => write!(f, "person"),
            Self::Organization => write!(f, "organization"),
            Self::Address => write!(f, "address"),
            Self::DateOfBirth => write!(f, "date_of_birth"),
            Self::MedicalTerm => write!(f, "medical_term"),
            Self::Location => write!(f, "location"),
            Self::NationalId => write!(f, "national_id"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl EntityType {
    /// Parse from the YAML/JSON string form.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ssn" => Some(Self::Ssn),
            "credit_card" => Some(Self::CreditCard),
            "email" => Some(Self::Email),
            "phone" => Some(Self::Phone),
            "ip_address" => Some(Self::IpAddress),
            "aws_access_key" => Some(Self::AwsAccessKey),
            "aws_secret_key" => Some(Self::AwsSecretKey),
            "jwt" => Some(Self::Jwt),
            "api_key" => Some(Self::ApiKey),
            "passport" => Some(Self::Passport),
            "person" => Some(Self::Person),
            "organization" | "org" => Some(Self::Organization),
            "address" => Some(Self::Address),
            "date_of_birth" | "dob" => Some(Self::DateOfBirth),
            "medical_term" | "medical" => Some(Self::MedicalTerm),
            "location" | "loc" | "gpe" => Some(Self::Location),
            "national_id" => Some(Self::NationalId),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    /// Returns `true` for entity types that can only be detected by a NER model,
    /// not by regex patterns.
    pub fn is_ner_only(&self) -> bool {
        matches!(
            self,
            Self::Person
                | Self::Organization
                | Self::Address
                | Self::DateOfBirth
                | Self::MedicalTerm
                | Self::Location
                | Self::NationalId
        )
    }
}

/// A compiled pattern for a single entity type.
pub struct EntityPattern {
    pub entity_type: EntityType,
    pub regex: &'static Regex,
    /// Base confidence for regex matches (0.0–1.0).
    pub confidence: f32,
    /// Optional post-match validator (e.g., Luhn check for credit cards).
    pub validator: Option<fn(&str) -> bool>,
}

// ---------- Compiled regex patterns (built once, reused) ----------

static RE_SSN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("SSN regex"));

static RE_CREDIT_CARD: LazyLock<Regex> = LazyLock::new(|| {
    // 13–19 digit sequences, optionally separated by a single space or dash.
    // Uses `[ -]?` (0 or 1) instead of `[ -]*?` to avoid nested quantifiers.
    Regex::new(r"\b\d(?:[ -]?\d){12,18}\b").expect("credit card regex")
});

static RE_EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").expect("email regex")
});

static RE_PHONE: LazyLock<Regex> = LazyLock::new(|| {
    // US/intl formats: +1-555-123-4567, (555) 123-4567, 555.123.4567, etc.
    Regex::new(r"(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
        .expect("phone regex")
});

static RE_IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
        .expect("IPv4 regex")
});

static RE_AWS_ACCESS_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("AWS access key regex"));

static RE_AWS_SECRET_KEY: LazyLock<Regex> = LazyLock::new(|| {
    // 40-char base64 string (letters, digits, +, /) commonly following an access key.
    Regex::new(r"\b[A-Za-z0-9/+=]{40}\b").expect("AWS secret key regex")
});

static RE_JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.+-]+\b").expect("JWT regex")
});

static RE_API_KEY: LazyLock<Regex> = LazyLock::new(|| {
    // High-entropy hex or base64 strings of 32+ characters, typically prefixed by
    // common key identifiers. Deliberately conservative to reduce false positives.
    Regex::new(r"\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[A-Za-z0-9_-]{32,}\b")
        .expect("API key regex")
});

static RE_PASSPORT: LazyLock<Regex> = LazyLock::new(|| {
    // Common passport formats: US (9 digits), UK (9 digits), EU (2 letters + 7 digits).
    Regex::new(r"\b[A-Z]{1,2}\d{6,9}\b").expect("passport regex")
});

/// Luhn algorithm for credit card validation.
fn luhn_check(digits_str: &str) -> bool {
    let digits: Vec<u8> = digits_str
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut val = u32::from(d);
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }
    sum % 10 == 0
}

/// All built-in entity patterns.
pub fn builtin_patterns() -> Vec<EntityPattern> {
    vec![
        EntityPattern {
            entity_type: EntityType::Ssn,
            regex: &RE_SSN,
            confidence: 0.9,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::CreditCard,
            regex: &RE_CREDIT_CARD,
            confidence: 0.95,
            validator: Some(luhn_check),
        },
        EntityPattern {
            entity_type: EntityType::Email,
            regex: &RE_EMAIL,
            confidence: 0.95,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::Phone,
            regex: &RE_PHONE,
            confidence: 0.7,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::IpAddress,
            regex: &RE_IPV4,
            confidence: 0.6,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::AwsAccessKey,
            regex: &RE_AWS_ACCESS_KEY,
            confidence: 0.99,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::AwsSecretKey,
            regex: &RE_AWS_SECRET_KEY,
            confidence: 0.4, // Low confidence: pattern matches many base64 strings (commit SHAs, UUIDs)
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::Jwt,
            regex: &RE_JWT,
            confidence: 0.99,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::ApiKey,
            regex: &RE_API_KEY,
            confidence: 0.8,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::Passport,
            regex: &RE_PASSPORT,
            confidence: 0.5,
            validator: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SSN ----
    #[test]
    fn ssn_detects_valid() {
        assert!(RE_SSN.is_match("123-45-6789"));
        assert!(RE_SSN.is_match("My SSN is 078-05-1120 ok"));
    }

    #[test]
    fn ssn_rejects_partial() {
        assert!(!RE_SSN.is_match("123-456-789"));
        assert!(!RE_SSN.is_match("12-34-5678"));
    }

    // ---- Credit card + Luhn ----
    #[test]
    fn credit_card_luhn_valid() {
        assert!(luhn_check("4111111111111111")); // Visa test
        assert!(luhn_check("5500000000000004")); // MC test
        assert!(luhn_check("378282246310005")); // Amex test
    }

    #[test]
    fn credit_card_luhn_invalid() {
        assert!(!luhn_check("4111111111111112"));
        assert!(!luhn_check("1234567890"));
    }

    // ---- Email ----
    #[test]
    fn email_detects_valid() {
        assert!(RE_EMAIL.is_match("user@example.com"));
        assert!(RE_EMAIL.is_match("test.user+tag@sub.domain.io"));
    }

    #[test]
    fn email_rejects_invalid() {
        assert!(!RE_EMAIL.is_match("@example.com"));
        assert!(!RE_EMAIL.is_match("user@"));
    }

    // ---- AWS access key ----
    #[test]
    fn aws_access_key_detects() {
        assert!(RE_AWS_ACCESS_KEY.is_match("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn aws_access_key_rejects_short() {
        assert!(!RE_AWS_ACCESS_KEY.is_match("AKIA1234"));
    }

    // ---- JWT ----
    #[test]
    fn jwt_detects_valid() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(RE_JWT.is_match(jwt));
    }

    #[test]
    fn jwt_rejects_random() {
        assert!(!RE_JWT.is_match("not.a.jwt"));
        assert!(!RE_JWT.is_match("eyJ.short.x"));
    }

    // ---- API key ----
    #[test]
    fn api_key_detects() {
        assert!(RE_API_KEY.is_match("sk-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(RE_API_KEY.is_match("api_key_Abcdefghijklmnopqrstuvwxyz12345"));
    }

    #[test]
    fn api_key_rejects_short() {
        assert!(!RE_API_KEY.is_match("sk-short"));
    }

    // ---- IP address ----
    #[test]
    fn ip_detects_valid() {
        assert!(RE_IPV4.is_match("192.168.1.1"));
        assert!(RE_IPV4.is_match("10.0.0.255"));
    }

    #[test]
    fn ip_rejects_out_of_range() {
        assert!(!RE_IPV4.is_match("999.999.999.999"));
    }

    // ---- Phone ----
    #[test]
    fn phone_detects_us_formats() {
        assert!(RE_PHONE.is_match("(555) 123-4567"));
        assert!(RE_PHONE.is_match("+1-555-123-4567"));
        assert!(RE_PHONE.is_match("555.123.4567"));
    }

    // ---- Passport ----
    #[test]
    fn passport_detects() {
        assert!(RE_PASSPORT.is_match("AB1234567"));
        assert!(RE_PASSPORT.is_match("C12345678"));
    }

    #[test]
    fn passport_rejects_lowercase() {
        assert!(!RE_PASSPORT.is_match("ab1234567"));
    }

    // ---- NER entity types ----
    #[test]
    fn ner_entity_types_parse() {
        assert_eq!(EntityType::parse("person"), Some(EntityType::Person));
        assert_eq!(EntityType::parse("organization"), Some(EntityType::Organization));
        assert_eq!(EntityType::parse("org"), Some(EntityType::Organization));
        assert_eq!(EntityType::parse("address"), Some(EntityType::Address));
        assert_eq!(EntityType::parse("date_of_birth"), Some(EntityType::DateOfBirth));
        assert_eq!(EntityType::parse("dob"), Some(EntityType::DateOfBirth));
        assert_eq!(EntityType::parse("medical_term"), Some(EntityType::MedicalTerm));
        assert_eq!(EntityType::parse("medical"), Some(EntityType::MedicalTerm));
        assert_eq!(EntityType::parse("location"), Some(EntityType::Location));
        assert_eq!(EntityType::parse("loc"), Some(EntityType::Location));
        assert_eq!(EntityType::parse("gpe"), Some(EntityType::Location));
        assert_eq!(EntityType::parse("national_id"), Some(EntityType::NationalId));
    }

    #[test]
    fn ner_entity_types_display() {
        assert_eq!(EntityType::Person.to_string(), "person");
        assert_eq!(EntityType::Organization.to_string(), "organization");
        assert_eq!(EntityType::Address.to_string(), "address");
        assert_eq!(EntityType::DateOfBirth.to_string(), "date_of_birth");
        assert_eq!(EntityType::MedicalTerm.to_string(), "medical_term");
        assert_eq!(EntityType::Location.to_string(), "location");
        assert_eq!(EntityType::NationalId.to_string(), "national_id");
    }

    #[test]
    fn is_ner_only_discriminator() {
        // Regex-detected types should return false.
        assert!(!EntityType::Ssn.is_ner_only());
        assert!(!EntityType::CreditCard.is_ner_only());
        assert!(!EntityType::Email.is_ner_only());
        assert!(!EntityType::ApiKey.is_ner_only());

        // NER-only types should return true.
        assert!(EntityType::Person.is_ner_only());
        assert!(EntityType::Organization.is_ner_only());
        assert!(EntityType::Address.is_ner_only());
        assert!(EntityType::DateOfBirth.is_ner_only());
        assert!(EntityType::MedicalTerm.is_ner_only());
        assert!(EntityType::Location.is_ner_only());
        assert!(EntityType::NationalId.is_ner_only());
    }
}
