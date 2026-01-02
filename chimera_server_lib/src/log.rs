use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, RwLock},
};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
    filter::Filtered,
    fmt::{
        self,
        format::{DefaultFields, Format, FmtSpan},
        writer::BoxMakeWriter,
    },
    layer::SubscriberExt,
    reload,
    util::SubscriberInitExt,
    EnvFilter,
    Registry,
    Layer,
};

use crate::Error;

type LogLayer = Filtered<fmt::Layer<Registry, DefaultFields, Format, BoxMakeWriter>, EnvFilter, Registry>;

static LOG_RELOAD: OnceLock<reload::Handle<LogLayer, Registry>> = OnceLock::new();
static LOG_STATE: OnceLock<RwLock<LogState>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LogConfig {
    pub access: Option<String>,
    pub dns_log: bool,
    pub error: Option<String>,
    pub loglevel: LogLevel,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            access: Some("none".to_string()),
            dns_log: false,
            error: None,
            loglevel: LogLevel::Warning,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    None,
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Warning
    }
}

impl LogLevel {
    fn as_filter(self) -> LevelFilter {
        match self {
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Warning => LevelFilter::WARN,
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::None => LevelFilter::OFF,
        }
    }

    fn as_directive(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warning => "warn",
            LogLevel::Error => "error",
            LogLevel::None => "off",
        }
    }
}

pub fn init(
    cfg: Option<&LogConfig>,
    cwd: Option<&str>,
    override_error_target: Option<&str>,
) -> Result<(), Error> {
    let log_cfg = cfg.cloned().unwrap_or_default();
    LogState::store(log_cfg.clone(), cwd, override_error_target);
    log_cfg.install(cwd, override_error_target)
}

impl LogConfig {
    fn install(&self, cwd: Option<&str>, override_error_target: Option<&str>) -> Result<(), Error> {
        let base_dir = cwd.map(PathBuf::from);
        let base_ref = base_dir.as_deref();

        let error_destination = override_error_target
            .and_then(|value| parse_destination(Some(value), base_ref))
            .or_else(|| parse_destination(self.error.as_deref(), base_ref))
            .unwrap_or(LogDestination::Stderr);

        let use_ansi = error_destination.ansi_enabled();
        let writer = error_destination.make_writer().map_err(Error::from)?;
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(self.loglevel.as_directive()));

        let layer = fmt::layer()
            .with_span_events(FmtSpan::FULL)
            .with_writer(writer)
            .with_ansi(use_ansi)
            .with_filter(env_filter);

        if let Some(handle) = LOG_RELOAD.get() {
            handle
                .reload(layer)
                .map_err(|err| Error::InvalidConfig(format!("failed to reload logger: {err}")))?;
            return Ok(());
        }

        let (reload_layer, handle) = reload::Layer::new(layer);
        tracing_subscriber::registry()
            .with(reload_layer)
            .try_init()
            .map_err(|err| Error::InvalidConfig(format!("failed to initialize logger: {err}")))?;

        let _ = LOG_RELOAD.set(handle);

        Ok(())
    }
}

#[derive(Clone, Debug)]
struct LogState {
    cfg: LogConfig,
    cwd: Option<String>,
    override_error_target: Option<String>,
}

impl LogState {
    fn store(cfg: LogConfig, cwd: Option<&str>, override_error_target: Option<&str>) {
        let state = LogState {
            cfg,
            cwd: cwd.map(|value| value.to_string()),
            override_error_target: override_error_target.map(|value| value.to_string()),
        };
        let lock = LOG_STATE.get_or_init(|| RwLock::new(state.clone()));
        *lock.write().expect("log state poisoned") = state;
    }
}

pub fn restart() -> Result<(), Error> {
    let state = LOG_STATE
        .get()
        .ok_or_else(|| Error::InvalidConfig("logger not initialized".into()))?;
    let guard = state.read().expect("log state poisoned");
    guard
        .cfg
        .install(guard.cwd.as_deref(), guard.override_error_target.as_deref())
}

fn parse_destination(value: Option<&str>, base: Option<&Path>) -> Option<LogDestination> {
    value
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            if entry.eq_ignore_ascii_case("none") {
                LogDestination::None
            } else if entry.eq_ignore_ascii_case("stdout") {
                LogDestination::Stdout
            } else if entry.eq_ignore_ascii_case("stderr") {
                LogDestination::Stderr
            } else {
                let mut path = PathBuf::from(entry);
                if let Some(root) = base {
                    if path.is_relative() {
                        path = root.join(path);
                    }
                }
                LogDestination::Path(path)
            }
        })
}

#[derive(Debug, Clone)]
enum LogDestination {
    None,
    Stdout,
    Stderr,
    Path(PathBuf),
}

impl LogDestination {
    fn ansi_enabled(&self) -> bool {
        matches!(self, LogDestination::Stdout | LogDestination::Stderr)
    }

    fn make_writer(&self) -> io::Result<BoxMakeWriter> {
        match self {
            LogDestination::None => Ok(BoxMakeWriter::new(|| io::sink())),
            LogDestination::Stdout => Ok(BoxMakeWriter::new(|| io::stdout())),
            LogDestination::Stderr => Ok(BoxMakeWriter::new(|| io::stderr())),
            LogDestination::Path(path) => create_file_writer(path),
        }
    }
}

fn create_file_writer(path: &Path) -> io::Result<BoxMakeWriter> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let buffer = Arc::new(Mutex::new(BufWriter::with_capacity(64 * 1024, file)));

    Ok(BoxMakeWriter::new({
        let buffer = buffer.clone();
        move || SharedFileWriter {
            inner: buffer.clone(),
        }
    }))
}

#[derive(Clone)]
struct SharedFileWriter {
    inner: Arc<Mutex<BufWriter<std::fs::File>>>,
}

impl Write for SharedFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.inner.lock().unwrap();
        // Flush immediately so file logs are visible in tail -f without waiting for the large buffer.
        let written = guard.write(buf)?;
        guard.flush()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self.inner.lock().unwrap();
        guard.flush()
    }
}
