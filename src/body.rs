use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use reqwest::Body;

#[derive(Debug)]
pub(crate) enum BodyReadError {
    TooLarge,
    /// The body could not be read to completion, e.g. the client disconnected or the
    /// underlying stream errored mid-body.
    Io(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyReadError::TooLarge => write!(f, "body exceeds size limit"),
            BodyReadError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Read the whole body into memory, up to `limit` bytes.
pub(crate) async fn to_bytes(body: Body, limit: usize) -> Result<Bytes, BodyReadError> {
    match Limited::new(body, limit).collect().await {
        Ok(col) => Ok(col.to_bytes()),
        Err(e)
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some() =>
        {
            Err(BodyReadError::TooLarge)
        }
        Err(e) => Err(BodyReadError::Io(e)),
    }
}
