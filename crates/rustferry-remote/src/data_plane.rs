//! Length-framed binary transport for large worker source and artifact payloads.

use std::io::{Read, Write};

use thiserror::Error;

use crate::{MAX_SOURCE_BUNDLE_DESCRIPTOR_BYTES, protocol::MAX_EVENT_LINE_BYTES};

/// Current schema for binary worker data-plane frame headers.
pub const WORKER_DATA_PLANE_SCHEMA_VERSION: u16 = 1;
/// Exact encoded size of one binary worker data-plane frame header.
pub const WORKER_DATA_PLANE_HEADER_BYTES: usize = 24;
/// Maximum build-request JSON size.
pub const MAX_WORKER_DATA_PLANE_REQUEST_BYTES: u64 = 1024 * 1024;
/// Maximum cancellation or acknowledgement JSON size.
pub const MAX_WORKER_DATA_PLANE_CONTROL_BYTES: u64 = 64 * 1024;
/// Maximum terminal result JSON size.
pub const MAX_WORKER_DATA_PLANE_RESULT_BYTES: u64 = MAX_SOURCE_BUNDLE_DESCRIPTOR_BYTES;
/// Maximum snapshot ZIP accepted from a client.
pub const MAX_WORKER_DATA_PLANE_SOURCE_BYTES: u64 = 640 * 1024 * 1024;
/// Maximum sealed physical-iPhone artifact returned by a worker.
pub const MAX_WORKER_DATA_PLANE_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

const WORKER_DATA_PLANE_MAGIC: [u8; 4] = *b"RFDP";

/// Typed frame carried by the full-duplex worker data plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum WorkerDataPlaneFrameKind {
    /// Declarative [`crate::IosDeviceBuildRequest`] JSON.
    BuildRequest = 1,
    /// Strict [`crate::SourceBundleDescriptor`] JSON.
    SourceDescriptor = 2,
    /// Raw deterministic source ZIP bytes.
    SourceArchive = 3,
    /// In-band cancellation request JSON.
    Cancel = 4,
    /// Worker job acknowledgement JSON.
    JobAccepted = 5,
    /// One [`crate::RemoteBuildEvent`] JSON object.
    Event = 6,
    /// Strict artifact descriptor or manifest JSON.
    ArtifactDescriptor = 7,
    /// Raw artifact bytes bound by the preceding descriptor.
    Artifact = 8,
    /// Terminal build and cleanup result JSON.
    Complete = 9,
    /// Stable secret-free error JSON.
    Error = 10,
    /// Client proof that the offered artifact was verified and published.
    ArtifactReceipt = 11,
}

impl WorkerDataPlaneFrameKind {
    /// Maximum payload bytes accepted for this frame kind.
    #[must_use]
    pub const fn maximum_payload_bytes(self) -> u64 {
        match self {
            Self::BuildRequest => MAX_WORKER_DATA_PLANE_REQUEST_BYTES,
            Self::SourceDescriptor | Self::ArtifactDescriptor => MAX_SOURCE_BUNDLE_DESCRIPTOR_BYTES,
            Self::SourceArchive => MAX_WORKER_DATA_PLANE_SOURCE_BYTES,
            Self::Cancel | Self::JobAccepted | Self::Error | Self::ArtifactReceipt => {
                MAX_WORKER_DATA_PLANE_CONTROL_BYTES
            }
            Self::Event => MAX_EVENT_LINE_BYTES as u64,
            Self::Artifact => MAX_WORKER_DATA_PLANE_ARTIFACT_BYTES,
            Self::Complete => MAX_WORKER_DATA_PLANE_RESULT_BYTES,
        }
    }

    fn from_wire(value: u16) -> Result<Self, WorkerDataPlaneFrameError> {
        match value {
            1 => Ok(Self::BuildRequest),
            2 => Ok(Self::SourceDescriptor),
            3 => Ok(Self::SourceArchive),
            4 => Ok(Self::Cancel),
            5 => Ok(Self::JobAccepted),
            6 => Ok(Self::Event),
            7 => Ok(Self::ArtifactDescriptor),
            8 => Ok(Self::Artifact),
            9 => Ok(Self::Complete),
            10 => Ok(Self::Error),
            11 => Ok(Self::ArtifactReceipt),
            _ => Err(WorkerDataPlaneFrameError::UnknownFrameKind),
        }
    }
}

/// Validated header for one length-framed worker payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerDataPlaneFrameHeader {
    kind: WorkerDataPlaneFrameKind,
    sequence: u64,
    payload_bytes: u64,
}

/// Per-direction monotonic frame-sequence validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerDataPlaneSequence {
    next: Option<u64>,
}

impl WorkerDataPlaneSequence {
    /// Start a stream at sequence zero.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: Some(0) }
    }

    /// Accept exactly the next header in this direction.
    ///
    /// # Errors
    ///
    /// Rejects gaps, duplicates, replay, and frames after sequence exhaustion.
    pub fn accept(
        &mut self,
        header: WorkerDataPlaneFrameHeader,
    ) -> Result<(), WorkerDataPlaneFrameError> {
        let Some(expected) = self.next else {
            return Err(WorkerDataPlaneFrameError::SequenceExhausted);
        };
        if header.sequence != expected {
            return Err(WorkerDataPlaneFrameError::UnexpectedSequence {
                expected,
                received: header.sequence,
            });
        }
        self.next = expected.checked_add(1);
        Ok(())
    }
}

impl Default for WorkerDataPlaneSequence {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerDataPlaneFrameHeader {
    /// Construct one bounded frame header.
    ///
    /// # Errors
    ///
    /// Rejects payload sizes above the fixed limit for `kind`.
    pub fn new(
        kind: WorkerDataPlaneFrameKind,
        sequence: u64,
        payload_bytes: u64,
    ) -> Result<Self, WorkerDataPlaneFrameError> {
        let maximum = kind.maximum_payload_bytes();
        if payload_bytes > maximum {
            return Err(WorkerDataPlaneFrameError::PayloadTooLarge {
                kind,
                payload_bytes,
                maximum,
            });
        }
        Ok(Self {
            kind,
            sequence,
            payload_bytes,
        })
    }

    /// Typed payload interpretation.
    #[must_use]
    pub const fn kind(self) -> WorkerDataPlaneFrameKind {
        self.kind
    }

    /// Monotonic sequence within one stream direction.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Exact following payload size.
    #[must_use]
    pub const fn payload_bytes(self) -> u64 {
        self.payload_bytes
    }
}

/// Stable binary-frame parsing or serialization failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkerDataPlaneFrameError {
    /// Reading or writing the stream failed.
    #[error("worker data-plane I/O failed")]
    Io,
    /// No frame header was supplied.
    #[error("worker data-plane stream is empty")]
    EmptyInput,
    /// Input ended inside a frame header.
    #[error("worker data-plane frame header is truncated")]
    TruncatedHeader,
    /// Header magic does not identify the `RustFerry` data plane.
    #[error("worker data-plane frame magic is invalid")]
    InvalidMagic,
    /// Header schema is not supported.
    #[error("worker data-plane frame schema is unsupported")]
    UnsupportedSchemaVersion {
        /// Supported header schema.
        supported: u16,
        /// Received header schema.
        received: u16,
    },
    /// Frame kind has no defined v1 meaning.
    #[error("worker data-plane frame kind is unknown")]
    UnknownFrameKind,
    /// Declared payload exceeds the fixed bound for its kind.
    #[error("worker data-plane frame payload exceeds its limit")]
    PayloadTooLarge {
        /// Frame interpretation.
        kind: WorkerDataPlaneFrameKind,
        /// Declared payload size.
        payload_bytes: u64,
        /// Maximum accepted size.
        maximum: u64,
    },
    /// Input ended before the declared payload length.
    #[error("worker data-plane frame payload is truncated")]
    TruncatedPayload,
    /// A small payload cannot be represented in local address space.
    #[error("worker data-plane frame payload cannot be represented")]
    PayloadSizeUnsupported,
    /// A raw source or artifact payload must be copied into a bounded sink.
    #[error("worker data-plane raw payload requires streaming")]
    StreamingRequired {
        /// Raw frame interpretation.
        kind: WorkerDataPlaneFrameKind,
    },
    /// A frame was replayed, skipped, or reordered within its direction.
    #[error("worker data-plane frame sequence is invalid")]
    UnexpectedSequence {
        /// Exact next sequence required.
        expected: u64,
        /// Sequence received from the peer.
        received: u64,
    },
    /// No frame may follow sequence `u64::MAX`.
    #[error("worker data-plane frame sequence is exhausted")]
    SequenceExhausted,
}

/// Encode one validated header without buffering its payload.
///
/// # Errors
///
/// Returns a stable I/O error if the complete header cannot be written.
pub fn write_worker_data_plane_header(
    writer: &mut impl Write,
    header: WorkerDataPlaneFrameHeader,
) -> Result<(), WorkerDataPlaneFrameError> {
    let mut encoded = [0_u8; WORKER_DATA_PLANE_HEADER_BYTES];
    encoded[..4].copy_from_slice(&WORKER_DATA_PLANE_MAGIC);
    encoded[4..6].copy_from_slice(&WORKER_DATA_PLANE_SCHEMA_VERSION.to_be_bytes());
    encoded[6..8].copy_from_slice(&(header.kind as u16).to_be_bytes());
    encoded[8..16].copy_from_slice(&header.sequence.to_be_bytes());
    encoded[16..24].copy_from_slice(&header.payload_bytes.to_be_bytes());
    writer
        .write_all(&encoded)
        .map_err(|_| WorkerDataPlaneFrameError::Io)
}

/// Decode and validate one fixed-size frame header without reading its payload.
///
/// # Errors
///
/// Distinguishes empty input, truncation, schema/kind mismatch, and an
/// over-limit declaration before payload allocation or I/O.
pub fn read_worker_data_plane_header(
    reader: &mut impl Read,
) -> Result<WorkerDataPlaneFrameHeader, WorkerDataPlaneFrameError> {
    let mut encoded = [0_u8; WORKER_DATA_PLANE_HEADER_BYTES];
    read_header_exact(reader, &mut encoded)?;
    if encoded[..4] != WORKER_DATA_PLANE_MAGIC {
        return Err(WorkerDataPlaneFrameError::InvalidMagic);
    }
    let schema_version = u16::from_be_bytes([encoded[4], encoded[5]]);
    if schema_version != WORKER_DATA_PLANE_SCHEMA_VERSION {
        return Err(WorkerDataPlaneFrameError::UnsupportedSchemaVersion {
            supported: WORKER_DATA_PLANE_SCHEMA_VERSION,
            received: schema_version,
        });
    }
    let kind = WorkerDataPlaneFrameKind::from_wire(u16::from_be_bytes([encoded[6], encoded[7]]))?;
    let sequence = u64::from_be_bytes([
        encoded[8],
        encoded[9],
        encoded[10],
        encoded[11],
        encoded[12],
        encoded[13],
        encoded[14],
        encoded[15],
    ]);
    let payload_bytes = u64::from_be_bytes([
        encoded[16],
        encoded[17],
        encoded[18],
        encoded[19],
        encoded[20],
        encoded[21],
        encoded[22],
        encoded[23],
    ]);
    WorkerDataPlaneFrameHeader::new(kind, sequence, payload_bytes)
}

/// Write one bounded in-memory frame.
///
/// # Errors
///
/// Rejects an oversized payload before writing and returns a stable I/O error
/// if the header or complete payload cannot be written.
pub fn write_worker_data_plane_frame(
    writer: &mut impl Write,
    kind: WorkerDataPlaneFrameKind,
    sequence: u64,
    payload: &[u8],
) -> Result<(), WorkerDataPlaneFrameError> {
    let payload_bytes = u64::try_from(payload.len())
        .map_err(|_| WorkerDataPlaneFrameError::PayloadSizeUnsupported)?;
    let header = WorkerDataPlaneFrameHeader::new(kind, sequence, payload_bytes)?;
    write_worker_data_plane_header(writer, header)?;
    writer
        .write_all(payload)
        .map_err(|_| WorkerDataPlaneFrameError::Io)
}

/// Write one header followed by an exact-length streamed payload.
///
/// The caller must separately bind raw payload bytes to a trusted descriptor
/// and verify its digest. This function guarantees framing and constant memory.
///
/// # Errors
///
/// Rejects an over-limit declaration, a short source, or an I/O failure.
pub fn write_worker_data_plane_stream(
    writer: &mut impl Write,
    kind: WorkerDataPlaneFrameKind,
    sequence: u64,
    reader: &mut impl Read,
    payload_bytes: u64,
) -> Result<u64, WorkerDataPlaneFrameError> {
    let header = WorkerDataPlaneFrameHeader::new(kind, sequence, payload_bytes)?;
    write_worker_data_plane_header(writer, header)?;
    copy_worker_data_plane_payload(reader, writer, header)
}

/// Read one bounded in-memory payload after its validated header.
///
/// Raw source and artifact frames should instead use
/// [`copy_worker_data_plane_payload`] to avoid allocating their declared size.
///
/// # Errors
///
/// Rejects sizes unavailable in local address space and distinguishes a short
/// payload from another I/O failure.
pub fn read_worker_data_plane_payload(
    reader: &mut impl Read,
    header: WorkerDataPlaneFrameHeader,
) -> Result<Vec<u8>, WorkerDataPlaneFrameError> {
    if matches!(
        header.kind,
        WorkerDataPlaneFrameKind::SourceArchive | WorkerDataPlaneFrameKind::Artifact
    ) {
        return Err(WorkerDataPlaneFrameError::StreamingRequired { kind: header.kind });
    }
    let length = usize::try_from(header.payload_bytes)
        .map_err(|_| WorkerDataPlaneFrameError::PayloadSizeUnsupported)?;
    let mut payload = vec![0_u8; length];
    read_payload_exact(reader, &mut payload)?;
    Ok(payload)
}

/// Stream exactly one validated payload into a sink with constant memory.
///
/// # Errors
///
/// Returns [`WorkerDataPlaneFrameError::TruncatedPayload`] if input ends before
/// the declared length, or a stable I/O error if reading or writing otherwise
/// fails.
pub fn copy_worker_data_plane_payload(
    reader: &mut impl Read,
    writer: &mut impl Write,
    header: WorkerDataPlaneFrameHeader,
) -> Result<u64, WorkerDataPlaneFrameError> {
    let mut remaining = header.payload_bytes;
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    while remaining != 0 {
        let chunk = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| WorkerDataPlaneFrameError::PayloadSizeUnsupported)?;
        let count = reader
            .read(&mut buffer[..chunk])
            .map_err(|_| WorkerDataPlaneFrameError::Io)?;
        if count == 0 {
            return Err(WorkerDataPlaneFrameError::TruncatedPayload);
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|_| WorkerDataPlaneFrameError::Io)?;
        let count = count as u64;
        remaining -= count;
        copied += count;
    }
    Ok(copied)
}

fn read_header_exact(
    reader: &mut impl Read,
    output: &mut [u8],
) -> Result<(), WorkerDataPlaneFrameError> {
    let mut offset = 0;
    while offset < output.len() {
        let count = reader
            .read(&mut output[offset..])
            .map_err(|_| WorkerDataPlaneFrameError::Io)?;
        if count == 0 {
            return Err(if offset == 0 {
                WorkerDataPlaneFrameError::EmptyInput
            } else {
                WorkerDataPlaneFrameError::TruncatedHeader
            });
        }
        offset += count;
    }
    Ok(())
}

fn read_payload_exact(
    reader: &mut impl Read,
    output: &mut [u8],
) -> Result<(), WorkerDataPlaneFrameError> {
    let mut offset = 0;
    while offset < output.len() {
        let count = reader
            .read(&mut output[offset..])
            .map_err(|_| WorkerDataPlaneFrameError::Io)?;
        if count == 0 {
            return Err(WorkerDataPlaneFrameError::TruncatedPayload);
        }
        offset += count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn concatenated_frames_round_trip_without_consuming_each_other() {
        let mut bytes = Vec::new();
        write_worker_data_plane_frame(
            &mut bytes,
            WorkerDataPlaneFrameKind::BuildRequest,
            0,
            br#"{"request":"one"}"#,
        )
        .expect("request frame");
        write_worker_data_plane_frame(
            &mut bytes,
            WorkerDataPlaneFrameKind::Cancel,
            1,
            br#"{"reason":"user_requested"}"#,
        )
        .expect("cancel frame");

        let mut input = Cursor::new(bytes);
        let first = read_worker_data_plane_header(&mut input).expect("first header");
        assert_eq!(first.kind(), WorkerDataPlaneFrameKind::BuildRequest);
        assert_eq!(first.sequence(), 0);
        assert_eq!(
            read_worker_data_plane_payload(&mut input, first).expect("first payload"),
            br#"{"request":"one"}"#
        );
        let second = read_worker_data_plane_header(&mut input).expect("second header");
        assert_eq!(second.kind(), WorkerDataPlaneFrameKind::Cancel);
        assert_eq!(second.sequence(), 1);
        assert_eq!(
            read_worker_data_plane_payload(&mut input, second).expect("second payload"),
            br#"{"reason":"user_requested"}"#
        );
        assert_eq!(
            read_worker_data_plane_header(&mut input),
            Err(WorkerDataPlaneFrameError::EmptyInput)
        );
    }

    #[test]
    fn malformed_headers_are_rejected_before_payload_reads() {
        let valid = encoded_header(WorkerDataPlaneFrameKind::Event, 7, 0);
        let mut wrong_magic = valid;
        wrong_magic[0] = b'X';
        assert_eq!(
            read_worker_data_plane_header(&mut Cursor::new(wrong_magic)),
            Err(WorkerDataPlaneFrameError::InvalidMagic)
        );

        let mut wrong_schema = valid;
        wrong_schema[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            read_worker_data_plane_header(&mut Cursor::new(wrong_schema)),
            Err(WorkerDataPlaneFrameError::UnsupportedSchemaVersion {
                supported: WORKER_DATA_PLANE_SCHEMA_VERSION,
                received: 2,
            })
        );

        let mut unknown_kind = valid;
        unknown_kind[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            read_worker_data_plane_header(&mut Cursor::new(unknown_kind)),
            Err(WorkerDataPlaneFrameError::UnknownFrameKind)
        );
    }

    #[test]
    fn empty_truncated_header_and_payload_are_distinct() {
        assert_eq!(
            read_worker_data_plane_header(&mut Cursor::new(Vec::<u8>::new())),
            Err(WorkerDataPlaneFrameError::EmptyInput)
        );
        assert_eq!(
            read_worker_data_plane_header(&mut Cursor::new(vec![0_u8; 12])),
            Err(WorkerDataPlaneFrameError::TruncatedHeader)
        );

        let header = WorkerDataPlaneFrameHeader::new(WorkerDataPlaneFrameKind::Event, 0, 4)
            .expect("bounded header");
        assert_eq!(
            read_worker_data_plane_payload(&mut Cursor::new(b"abc"), header),
            Err(WorkerDataPlaneFrameError::TruncatedPayload)
        );
    }

    #[test]
    fn oversized_declaration_is_rejected_from_header_alone() {
        let encoded = encoded_header(
            WorkerDataPlaneFrameKind::SourceArchive,
            0,
            MAX_WORKER_DATA_PLANE_SOURCE_BYTES + 1,
        );
        assert_eq!(
            read_worker_data_plane_header(&mut Cursor::new(encoded)),
            Err(WorkerDataPlaneFrameError::PayloadTooLarge {
                kind: WorkerDataPlaneFrameKind::SourceArchive,
                payload_bytes: MAX_WORKER_DATA_PLANE_SOURCE_BYTES + 1,
                maximum: MAX_WORKER_DATA_PLANE_SOURCE_BYTES,
            })
        );
    }

    #[test]
    fn raw_payload_copy_is_exact_and_constant_memory() {
        let payload = vec![0x5a; 3 * 64 * 1024 + 17];
        let header = WorkerDataPlaneFrameHeader::new(
            WorkerDataPlaneFrameKind::SourceArchive,
            2,
            payload.len() as u64,
        )
        .expect("bounded source frame");
        let mut output = Vec::new();
        assert_eq!(
            copy_worker_data_plane_payload(&mut Cursor::new(&payload), &mut output, header)
                .expect("streamed payload"),
            payload.len() as u64
        );
        assert_eq!(output, payload);
    }

    #[test]
    fn raw_payload_copy_reports_truncation() {
        let header = WorkerDataPlaneFrameHeader::new(WorkerDataPlaneFrameKind::Artifact, 4, 4)
            .expect("bounded artifact frame");
        assert_eq!(
            copy_worker_data_plane_payload(&mut Cursor::new(b"abc"), &mut Vec::new(), header),
            Err(WorkerDataPlaneFrameError::TruncatedPayload)
        );
    }

    #[test]
    fn raw_payload_cannot_enter_the_in_memory_reader() {
        for kind in [
            WorkerDataPlaneFrameKind::SourceArchive,
            WorkerDataPlaneFrameKind::Artifact,
        ] {
            let header = WorkerDataPlaneFrameHeader::new(kind, 0, 1).expect("bounded raw frame");
            assert_eq!(
                read_worker_data_plane_payload(&mut Cursor::new([0_u8]), header),
                Err(WorkerDataPlaneFrameError::StreamingRequired { kind })
            );
        }
    }

    #[test]
    fn sequence_rejects_gap_replay_and_exhaustion() {
        let mut sequence = WorkerDataPlaneSequence::new();
        let first = WorkerDataPlaneFrameHeader::new(WorkerDataPlaneFrameKind::BuildRequest, 0, 0)
            .expect("first header");
        sequence.accept(first).expect("first sequence");
        let gap = WorkerDataPlaneFrameHeader::new(WorkerDataPlaneFrameKind::Cancel, 2, 0)
            .expect("gap header");
        assert_eq!(
            sequence.accept(gap),
            Err(WorkerDataPlaneFrameError::UnexpectedSequence {
                expected: 1,
                received: 2,
            })
        );
        let replay = WorkerDataPlaneFrameHeader::new(WorkerDataPlaneFrameKind::Cancel, 0, 0)
            .expect("replay header");
        assert_eq!(
            sequence.accept(replay),
            Err(WorkerDataPlaneFrameError::UnexpectedSequence {
                expected: 1,
                received: 0,
            })
        );

        let mut exhausted = WorkerDataPlaneSequence {
            next: Some(u64::MAX),
        };
        let last = WorkerDataPlaneFrameHeader::new(WorkerDataPlaneFrameKind::Complete, u64::MAX, 0)
            .expect("last header");
        exhausted.accept(last).expect("last sequence");
        assert_eq!(
            exhausted.accept(last),
            Err(WorkerDataPlaneFrameError::SequenceExhausted)
        );
    }

    #[test]
    fn streamed_frame_writes_exact_payload_without_buffering_it() {
        let payload = vec![0x3c; 2 * 64 * 1024 + 9];
        let mut encoded = Vec::new();
        assert_eq!(
            write_worker_data_plane_stream(
                &mut encoded,
                WorkerDataPlaneFrameKind::Artifact,
                8,
                &mut Cursor::new(&payload),
                payload.len() as u64,
            )
            .expect("streamed frame"),
            payload.len() as u64
        );
        let mut input = Cursor::new(encoded);
        let header = read_worker_data_plane_header(&mut input).expect("stream header");
        assert_eq!(header.kind(), WorkerDataPlaneFrameKind::Artifact);
        assert_eq!(header.sequence(), 8);
        let mut output = Vec::new();
        copy_worker_data_plane_payload(&mut input, &mut output, header).expect("stream payload");
        assert_eq!(output, payload);
    }

    fn encoded_header(
        kind: WorkerDataPlaneFrameKind,
        sequence: u64,
        payload_bytes: u64,
    ) -> [u8; WORKER_DATA_PLANE_HEADER_BYTES] {
        let mut bytes = Vec::new();
        let header = WorkerDataPlaneFrameHeader {
            kind,
            sequence,
            payload_bytes,
        };
        write_worker_data_plane_header(&mut bytes, header).expect("encoded header");
        bytes.try_into().expect("fixed header size")
    }
}
