use std;
use std::fmt::{self, Display, Formatter};

use thiserror::Error;

use crate::error::error::Error::Message;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    Message(String),
    MatterError,
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            Message(msg) => formatter.write_str(msg),
            matter_error => formatter.write_str("matter error"),
        }
    }
}

impl std::error::Error for Error {}