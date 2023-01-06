use thiserror::Error;

pub mod error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Matter error: {0}")]
    MatterError(String),
}
