use nlink_macros::GenlCommand;

#[derive(GenlCommand)]
#[genl_command(repr = "u8")]
pub enum TooBig {
    A = 0,
    B = 999,  // > u8::MAX
}

fn main() {}
