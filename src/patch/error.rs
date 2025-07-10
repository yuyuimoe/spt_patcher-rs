use std::fmt;

#[derive(Debug, PartialEq)]
pub enum PatcherError {
    InvalidBpfHeader,
    InvalidOriginalChecksum,
    InvalidPatchedChecksum,
    CouldNotReadInputFile,
    CouldNotReadBpfFile,
    AlreadyPatched,
    FailedToGenerateInfo,
}

impl fmt::Display for PatcherError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let cause = match *self {
            PatcherError::InvalidOriginalChecksum => {
                "Input file checksum does not match expectation of the bpf"
            }
            PatcherError::InvalidPatchedChecksum => {
                "Output file checksum does not match expectation of the bpf"
            }
            PatcherError::InvalidBpfHeader => "BPF File has invalid header",
            PatcherError::CouldNotReadInputFile => "Unable to read input file",
            PatcherError::CouldNotReadBpfFile => "Unable to read bpf file",
            PatcherError::AlreadyPatched => "Input file is already patched",
            PatcherError::FailedToGenerateInfo => "Failed to generate Patch Info",
        };
        f.write_str(cause)
    }
}

impl std::error::Error for PatcherError {}
