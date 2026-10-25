pub(crate) fn json(error: &serde_json::Error) -> String {
    let category = match error.classify() {
        serde_json::error::Category::Syntax => "syntax error",
        serde_json::error::Category::Data => "invalid value",
        serde_json::error::Category::Eof => "unexpected end of input",
        serde_json::error::Category::Io => "input error",
    };

    format!(
        "{category} at line {}, column {}",
        error.line(),
        error.column()
    )
}

pub(crate) fn json5(error: &json5::Error) -> String {
    let category = error
        .code()
        .map(|code| format!("syntax error ({code:?})"))
        .unwrap_or_else(|| "invalid value".to_string());

    match error.position() {
        Some(position) => format!(
            "{category} at line {}, column {}",
            position.line + 1,
            position.column + 1
        ),
        None => category,
    }
}

pub(crate) fn yaml(error: &serde_yaml::Error) -> String {
    match error.location() {
        Some(location) => format!(
            "invalid value at line {}, column {}",
            location.line(),
            location.column()
        ),
        None => "invalid value".to_string(),
    }
}
