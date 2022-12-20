use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("MatterError: {0}")]
    MatterError(String),
}