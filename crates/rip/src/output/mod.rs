//! Output formatting (JSON/text) for rip.

mod json;
pub mod monitor;
mod printable;
mod text;

pub use json::JsonOutput;
pub use monitor::{
    AddressEvent, IpEvent, LinkEvent, MonitorConfig, MonitorEvent, NeighborEvent, RouteEvent,
    TcEvent, print_event, print_monitor_start, run_monitor_loop, write_timestamp,
};
pub use text::TextOutput;

use std::io::Write;

/// Output format options.
#[derive(Debug, Clone, Copy, Default)]
pub struct OutputOptions {
    /// Show detailed statistics.
    pub stats: bool,
    /// Show extra details.
    pub details: bool,
    /// Use colored output.
    pub color: bool,
    /// Don't resolve names (show numeric values).
    pub numeric: bool,
    /// Pretty print (for JSON).
    pub pretty: bool,
}

/// Output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Plain text output.
    #[default]
    Text,
    /// JSON output.
    Json,
}

/// Trait for types that can be printed.
pub trait Printable {
    /// Print as plain text.
    fn print_text<W: Write>(&self, w: &mut W, opts: &OutputOptions) -> std::io::Result<()>;

    /// Convert to JSON value.
    fn to_json(&self) -> serde_json::Value;

    /// Print in the specified format.
    fn print<W: Write>(
        &self,
        w: &mut W,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> std::io::Result<()> {
        match format {
            OutputFormat::Text => self.print_text(w, opts),
            OutputFormat::Json => {
                let json = self.to_json();
                if opts.pretty {
                    serde_json::to_writer_pretty(&mut *w, &json)?;
                } else {
                    serde_json::to_writer(&mut *w, &json)?;
                }
                writeln!(w)?;
                Ok(())
            }
        }
    }
}

/// Trait for collections of printable items.
pub trait PrintableList {
    /// The item type.
    type Item: Printable;

    /// Get the items.
    fn items(&self) -> &[Self::Item];

    /// Print all items as text.
    fn print_text<W: Write>(&self, w: &mut W, opts: &OutputOptions) -> std::io::Result<()> {
        for item in self.items() {
            item.print_text(w, opts)?;
        }
        Ok(())
    }

    /// Convert to JSON array.
    fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Array(self.items().iter().map(|item| item.to_json()).collect())
    }

    /// Print in the specified format.
    fn print<W: Write>(
        &self,
        w: &mut W,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> std::io::Result<()> {
        match format {
            OutputFormat::Text => self.print_text(w, opts),
            OutputFormat::Json => {
                let json = self.to_json();
                if opts.pretty {
                    serde_json::to_writer_pretty(&mut *w, &json)?;
                } else {
                    serde_json::to_writer(&mut *w, &json)?;
                }
                writeln!(w)?;
                Ok(())
            }
        }
    }
}

/// Print a list of Printable items to stdout.
///
/// This is the simplest way to print items that implement the `Printable` trait.
/// For types with custom Printable implementations (LinkMessage, RouteMessage, etc.),
/// this eliminates the need for separate print functions.
///
/// # Example
/// ```ignore
/// let links: Vec<LinkMessage> = conn.dump_typed(NlMsgType::RTM_GETLINK).await?;
/// print_all(&links, format, opts)?;
/// ```
pub fn print_all<T: Printable>(
    items: &[T],
    format: OutputFormat,
    opts: &OutputOptions,
) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    match format {
        OutputFormat::Text => {
            for item in items {
                item.print_text(&mut stdout, opts)?;
            }
        }
        OutputFormat::Json => {
            let json: Vec<_> = items.iter().map(|i| i.to_json()).collect();
            if opts.pretty {
                serde_json::to_writer_pretty(&mut stdout, &json)?;
            } else {
                serde_json::to_writer(&mut stdout, &json)?;
            }
            writeln!(stdout)?;
        }
    }
    Ok(())
}

/// Print a list of items in the specified format.
///
/// This helper reduces boilerplate in command files by providing a single
/// function that handles both text and JSON output formats.
///
/// # Arguments
/// * `items` - The items to print
/// * `format` - The output format (Text or Json)
/// * `opts` - Output options
/// * `to_json` - Function to convert an item to JSON
/// * `print_text` - Function to print an item as text
///
/// # Example
/// ```ignore
/// print_items(
///     &links,
///     format,
///     opts,
///     link_to_json,
///     |w, link, opts| print_link_text(w, link, opts),
/// )?;
/// ```
///
/// Note: For types implementing `Printable`, prefer using `print_all()` instead.
/// This function is still useful for types with custom output formats.
pub fn print_items<T, J, P>(
    items: &[T],
    format: OutputFormat,
    opts: &OutputOptions,
    to_json: J,
    print_text: P,
) -> std::io::Result<()>
where
    J: Fn(&T) -> serde_json::Value,
    P: Fn(&mut std::io::StdoutLock<'_>, &T, &OutputOptions) -> std::io::Result<()>,
{
    let mut stdout = std::io::stdout().lock();
    match format {
        OutputFormat::Text => {
            for item in items {
                print_text(&mut stdout, item, opts)?;
            }
        }
        OutputFormat::Json => {
            let json: Vec<_> = items.iter().map(&to_json).collect();
            if opts.pretty {
                serde_json::to_writer_pretty(&mut stdout, &json)?;
            } else {
                serde_json::to_writer(&mut stdout, &json)?;
            }
            writeln!(stdout)?;
        }
    }
    Ok(())
}

/// Print a list of items to a custom writer in the specified format.
///
/// Same as `print_items` but allows specifying a custom writer instead of stdout.
pub fn print_items_to<W, T, J, P>(
    writer: &mut W,
    items: &[T],
    format: OutputFormat,
    opts: &OutputOptions,
    to_json: J,
    print_text: P,
) -> std::io::Result<()>
where
    W: Write,
    J: Fn(&T) -> serde_json::Value,
    P: Fn(&mut W, &T, &OutputOptions) -> std::io::Result<()>,
{
    match format {
        OutputFormat::Text => {
            for item in items {
                print_text(writer, item, opts)?;
            }
        }
        OutputFormat::Json => {
            let json: Vec<_> = items.iter().map(&to_json).collect();
            if opts.pretty {
                serde_json::to_writer_pretty(&mut *writer, &json)?;
            } else {
                serde_json::to_writer(&mut *writer, &json)?;
            }
            writeln!(writer)?;
        }
    }
    Ok(())
}

/// Helper for building text output.
pub struct OutputBuilder<W: Write> {
    writer: W,
    indent: usize,
}

impl<W: Write> OutputBuilder<W> {
    /// Create a new output builder.
    pub fn new(writer: W) -> Self {
        Self { writer, indent: 0 }
    }

    /// Increase indentation.
    pub fn indent(&mut self) {
        self.indent += 4;
    }

    /// Decrease indentation.
    pub fn dedent(&mut self) {
        self.indent = self.indent.saturating_sub(4);
    }

    /// Write indentation.
    pub fn write_indent(&mut self) -> std::io::Result<()> {
        for _ in 0..self.indent {
            write!(self.writer, " ")?;
        }
        Ok(())
    }

    /// Write a line with indentation.
    pub fn writeln(&mut self, s: &str) -> std::io::Result<()> {
        self.write_indent()?;
        writeln!(self.writer, "{}", s)
    }

    /// Write without newline.
    pub fn write(&mut self, s: &str) -> std::io::Result<()> {
        write!(self.writer, "{}", s)
    }

    /// Write a key-value pair.
    pub fn write_kv(&mut self, key: &str, value: &str) -> std::io::Result<()> {
        write!(self.writer, "{} {} ", key, value)
    }

    /// Write a newline.
    pub fn newline(&mut self) -> std::io::Result<()> {
        writeln!(self.writer)
    }

    /// Get the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}
