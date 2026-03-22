#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnpadCommand {
    Continue = 0,
    End = 1,
    Direct = 2,
}

impl TryFrom<u8> for UnpadCommand {
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(UnpadCommand::Continue),
            1 => Ok(UnpadCommand::End),
            2 => Ok(UnpadCommand::Direct),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid padding command: {value}"),
            )),
        }
    }
}

#[derive(Debug, Default)]
pub struct UnpadResult {
    pub content: Vec<u8>,
    pub command: Option<UnpadCommand>,
}

#[derive(Debug, Clone)]
enum UnpadState {
    Initial {
        expected_uuid: [u8; 16],
    },
    ReadingCommand,
    ReadingContentLength {
        command: UnpadCommand,
        first_byte: Option<u8>,
    },
    ReadingPaddingLength {
        command: UnpadCommand,
        content_len: u16,
        first_byte: Option<u8>,
    },
    ReadingContent {
        command: UnpadCommand,
        partial_content: Vec<u8>,
        remaining_content_len: u16,
        padding_len: u16,
    },
    ReadingPadding {
        command: UnpadCommand,
        content: Vec<u8>,
        remaining_padding_len: u16,
    },
    Done,
}

#[derive(Debug, Clone)]
pub struct VisionUnpadder {
    state: UnpadState,
    first_block: bool,
    accumulated_buffer: Vec<u8>,
}

impl VisionUnpadder {
    pub fn new(expected_uuid: [u8; 16]) -> Self {
        Self {
            state: UnpadState::Initial { expected_uuid },
            first_block: true,
            accumulated_buffer: Vec::new(),
        }
    }

    pub fn unpad(&mut self, mut data: &[u8]) -> std::io::Result<UnpadResult> {
        self.accumulated_buffer.clear();

        loop {
            match &mut self.state {
                UnpadState::Initial { expected_uuid } => {
                    if data.len() < 16 {
                        return Ok(UnpadResult::default());
                    }

                    if &data[..16] != expected_uuid {
                        return Ok(UnpadResult {
                            content: data.to_vec(),
                            command: None,
                        });
                    }

                    data = &data[16..];
                    self.state = UnpadState::ReadingCommand;
                }
                UnpadState::ReadingCommand => {
                    if data.is_empty() {
                        if !self.first_block {
                            return Ok(UnpadResult {
                                content: std::mem::take(
                                    &mut self.accumulated_buffer,
                                ),
                                command: Some(UnpadCommand::Continue),
                            });
                        }
                        return Ok(UnpadResult::default());
                    }

                    let command = UnpadCommand::try_from(data[0])?;
                    data = &data[1..];
                    self.state = UnpadState::ReadingContentLength {
                        command,
                        first_byte: None,
                    };
                }
                UnpadState::ReadingContentLength {
                    command,
                    first_byte,
                } => {
                    if data.is_empty() {
                        if !self.first_block {
                            return Ok(UnpadResult {
                                content: std::mem::take(
                                    &mut self.accumulated_buffer,
                                ),
                                command: Some(UnpadCommand::Continue),
                            });
                        }
                        return Ok(UnpadResult::default());
                    }

                    match first_byte {
                        None => {
                            *first_byte = Some(data[0]);
                            data = &data[1..];
                        }
                        Some(high_byte) => {
                            let low_byte = data[0];
                            data = &data[1..];
                            let content_len =
                                ((*high_byte as u16) << 8) | (low_byte as u16);

                            self.state = UnpadState::ReadingPaddingLength {
                                command: *command,
                                content_len,
                                first_byte: None,
                            };
                        }
                    }
                }
                UnpadState::ReadingPaddingLength {
                    command,
                    content_len,
                    first_byte,
                } => {
                    if data.is_empty() {
                        if !self.first_block {
                            return Ok(UnpadResult {
                                content: std::mem::take(
                                    &mut self.accumulated_buffer,
                                ),
                                command: Some(UnpadCommand::Continue),
                            });
                        }
                        return Ok(UnpadResult::default());
                    }

                    match first_byte {
                        None => {
                            *first_byte = Some(data[0]);
                            data = &data[1..];
                        }
                        Some(high_byte) => {
                            let low_byte = data[0];
                            data = &data[1..];
                            let padding_len =
                                ((*high_byte as u16) << 8) | (low_byte as u16);

                            self.state = UnpadState::ReadingContent {
                                command: *command,
                                partial_content: Vec::with_capacity(
                                    (*content_len as usize).min(data.len()),
                                ),
                                remaining_content_len: *content_len,
                                padding_len,
                            };
                        }
                    }
                }
                UnpadState::ReadingContent {
                    command,
                    partial_content,
                    remaining_content_len,
                    padding_len,
                } => {
                    if *remaining_content_len > 0 {
                        if data.is_empty() {
                            self.accumulated_buffer.append(partial_content);
                            if !self.first_block {
                                return Ok(UnpadResult {
                                    content: std::mem::take(
                                        &mut self.accumulated_buffer,
                                    ),
                                    command: Some(UnpadCommand::Continue),
                                });
                            }
                            return Ok(UnpadResult {
                                content: std::mem::take(
                                    &mut self.accumulated_buffer,
                                ),
                                command: None,
                            });
                        }

                        let to_read =
                            (*remaining_content_len as usize).min(data.len());
                        partial_content.extend_from_slice(&data[..to_read]);
                        data = &data[to_read..];
                        *remaining_content_len -= to_read as u16;
                    }

                    if *remaining_content_len == 0 {
                        self.state = UnpadState::ReadingPadding {
                            command: *command,
                            content: std::mem::take(partial_content),
                            remaining_padding_len: *padding_len,
                        };
                    }
                }
                UnpadState::ReadingPadding {
                    command,
                    content,
                    remaining_padding_len,
                } => {
                    if *remaining_padding_len > 0 {
                        let to_skip =
                            (*remaining_padding_len as usize).min(data.len());
                        data = &data[to_skip..];
                        *remaining_padding_len -= to_skip as u16;
                        if *remaining_padding_len > 0 {
                            return Ok(UnpadResult {
                                content: std::mem::take(content),
                                command: Some(UnpadCommand::Continue),
                            });
                        }
                    }

                    self.accumulated_buffer.extend_from_slice(content);
                    let finished_command = *command;
                    self.first_block = false;

                    match finished_command {
                        UnpadCommand::Continue => {
                            self.state = UnpadState::ReadingCommand;
                            if data.is_empty() {
                                return Ok(UnpadResult {
                                    content: std::mem::take(
                                        &mut self.accumulated_buffer,
                                    ),
                                    command: Some(UnpadCommand::Continue),
                                });
                            }
                        }
                        UnpadCommand::End | UnpadCommand::Direct => {
                            self.state = UnpadState::Done;
                            let mut content =
                                std::mem::take(&mut self.accumulated_buffer);
                            if !data.is_empty() {
                                content.extend_from_slice(data);
                            }
                            return Ok(UnpadResult {
                                content,
                                command: Some(finished_command),
                            });
                        }
                    }
                }
                UnpadState::Done => {
                    if data.is_empty() {
                        return Ok(UnpadResult::default());
                    }
                    return Ok(UnpadResult {
                        content: data.to_vec(),
                        command: None,
                    });
                }
            }
        }
    }
}
