/* policy.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of SE050Sim.
 *
 * SE050Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * SE050Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

//! Model of SE05x secure object policies used by object management.
//!
//! Covers only what the strict applet 7.2 ECDH derive-target contract
//! needs: a TAG_POLICY TLV attached to an object creation is a sequence
//! of entries `length(1) | authObjectId(4) | AR header(4, big endian) |
//! extension...` (see se05x_const.h in the Plug & Trust middleware, where
//! DEFAULT_OBJECT_POLICY_SIZE = 8 covers authObjectId + AR header), and
//! The applet uses default-deny semantics once a policy is attached.

/// POLICY_OBJ_ALLOW_READ bit of the 4-byte object policy AR header,
/// per se05x_const.h in the Plug & Trust middleware.
pub const POLICY_OBJ_ALLOW_READ: u32 = 0x0020_0000;
pub const POLICY_OBJ_ALLOW_WRITE: u32 = 0x0010_0000;
pub const POLICY_OBJ_ALLOW_DELETE: u32 = 0x0004_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPolicy;

/// Validate and copy the optional TAG_POLICY from a parsed command.
pub fn creation_policy(
    tlvs: &[crate::tlv::Tlv],
) -> Result<Option<Vec<u8>>, InvalidPolicy> {
    match crate::tlv::find_tlv(tlvs, crate::tlv::TAG_POLICY) {
        Some(tlv) if tlv.value.is_empty() => Ok(None),
        Some(tlv) if ar_header_union(&tlv.value).is_some() => Ok(Some(tlv.value.clone())),
        Some(_) => Err(InvalidPolicy),
        None => Ok(None),
    }
}

/// Extract the union of all AR headers from a TAG_POLICY TLV value.
///
/// The real applet evaluates the policy entry matching the session's
/// auth object; the simulator has no authentication, so it ORs every
/// entry's header together. Returns None if the value does not parse as
/// a policy entry sequence (including an empty value).
pub fn ar_header_union(value: &[u8]) -> Option<u32> {
    let mut rest = value;
    let mut header: u32 = 0;
    let mut seen = false;
    while !rest.is_empty() {
        let len = rest[0] as usize;
        // A valid entry covers at least authObjectId(4) + AR header(4);
        // anything past that is a policy extension we don't model.
        if len < 8 || rest.len() < 1 + len {
            return None;
        }
        header |= u32::from_be_bytes([rest[5], rest[6], rest[7], rest[8]]);
        seen = true;
        rest = &rest[1 + len..];
    }
    if seen {
        Some(header)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(auth_id: u32, header: u32, ext: &[u8]) -> Vec<u8> {
        let mut e = vec![(8 + ext.len()) as u8];
        e.extend_from_slice(&auth_id.to_be_bytes());
        e.extend_from_slice(&header.to_be_bytes());
        e.extend_from_slice(ext);
        e
    }

    #[test]
    fn test_single_entry() {
        let value = entry(0, POLICY_OBJ_ALLOW_READ | 0x0010_0000, &[]);
        assert_eq!(
            ar_header_union(&value),
            Some(POLICY_OBJ_ALLOW_READ | 0x0010_0000)
        );
    }

    #[test]
    fn test_multiple_entries_are_ored() {
        let mut value = entry(0, 0x0010_0000, &[]);
        value.extend_from_slice(&entry(0x7DA00001, POLICY_OBJ_ALLOW_READ, &[]));
        assert_eq!(
            ar_header_union(&value),
            Some(POLICY_OBJ_ALLOW_READ | 0x0010_0000)
        );
    }

    #[test]
    fn test_entry_with_extension() {
        let value = entry(0, POLICY_OBJ_ALLOW_READ, &[0xAA; 4]);
        assert_eq!(ar_header_union(&value), Some(POLICY_OBJ_ALLOW_READ));
    }

    #[test]
    fn test_empty_value_is_none() {
        assert_eq!(ar_header_union(&[]), None);
    }

    #[test]
    fn test_truncated_entry_is_none() {
        let mut value = entry(0, POLICY_OBJ_ALLOW_READ, &[]);
        value.truncate(6);
        assert_eq!(ar_header_union(&value), None);
    }
}
