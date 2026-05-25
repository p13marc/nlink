use nlink_macros::GenlCommand;

#[derive(GenlCommand)]
#[genl_command(repr = "u8")]
pub enum AnonymousDiscriminants {
    A,
    B,
}

fn main() {}
