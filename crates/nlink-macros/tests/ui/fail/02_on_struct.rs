use nlink_macros::GenlCommand;

#[derive(GenlCommand)]
#[genl_command(repr = "u8")]
pub struct NotAnEnum {
    x: u32,
}

fn main() {}
