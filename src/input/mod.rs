//! Input analysis module
//!
//! This module provides functionality to analyze input strings and extract
//! characteristics for use in the detection pipeline.

pub mod characteristics;
pub mod classifier;
pub mod matcher;
pub mod signature;

pub use characteristics::{extract_characteristics, InputCharacteristics};
pub use classifier::{classify_input, is_substrate_extrinsic, DetectedKeyType, InputPossibility};
pub use matcher::match_input_with_metadata;
pub use signature::CategorySignature;
