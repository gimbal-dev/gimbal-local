// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Finding the placeholders that freestanding guest helpers carry.
//!
//! [`nicfg`](super::nicfg) and [`cdpfwd`](super::cdpfwd) both ship an assembled
//! aarch64 image with recognisable four-byte sentinels in its data, which chm
//! rewrites from its own constants before the image is written. Neither may
//! restate an address or a port, because a second copy is a copy that drifts.
//!
//! The search itself is one rule and both callers need exactly the same rule,
//! so it lives here rather than being written twice: **a sentinel must occur
//! exactly once**. Finding it twice is as bad as not finding it, because we
//! would not know which copy the program actually reads, and rewriting the
//! first would produce a binary that configures the wrong thing while looking
//! entirely healthy.

/// Locate `sentinel` in `image`, refusing unless it occurs exactly once.
///
/// The sentinel is compared as little-endian bytes because that is how an
/// assembler's `.word` lands in the file.
///
/// On success the offset of the first byte; on failure the number of matches,
/// which is what the caller's error message needs.
pub fn find_exactly_once(image: &[u8], sentinel: u32) -> Result<usize, usize> {
    let needle = sentinel.to_le_bytes();
    let hits: Vec<usize> = image
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .collect();
    match hits.as_slice() {
        [at] => Ok(*at),
        other => Err(other.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sentinel_that_occurs_once_is_found() {
        let mut image = vec![0u8; 16];
        image[8..12].copy_from_slice(&0xC0DE_0001u32.to_le_bytes());
        assert_eq!(find_exactly_once(&image, 0xC0DE_0001), Ok(8));
    }

    #[test]
    fn an_absent_sentinel_is_refused() {
        assert_eq!(find_exactly_once(&[0u8; 16], 0xC0DE_0001), Err(0));
    }

    /// The case that matters: two copies means we cannot say which one the
    /// program reads, so taking the first would be a guess.
    #[test]
    fn a_duplicated_sentinel_is_refused_rather_than_guessed() {
        let mut image = Vec::new();
        image.extend_from_slice(&0xC0DE_0001u32.to_le_bytes());
        image.extend_from_slice(&[0u8; 8]);
        image.extend_from_slice(&0xC0DE_0001u32.to_le_bytes());
        assert_eq!(find_exactly_once(&image, 0xC0DE_0001), Err(2));
    }

    /// An image shorter than a sentinel has no matches rather than panicking on
    /// a window it cannot form.
    #[test]
    fn an_image_too_short_to_hold_a_sentinel_is_refused_not_a_panic() {
        assert_eq!(find_exactly_once(&[1, 2, 3], 0xC0DE_0001), Err(0));
    }
}
