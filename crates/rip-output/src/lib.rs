//! Output formatting (JSON/text) for rip.

mod json;
mod text;

pub use json::JsonOutput;
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
