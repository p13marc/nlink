use nlink_macros::GenlCommand;

#[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_command(repr = "u8")]
pub enum Cmd {
    Unspec = 0,
    Get = 1,
}

fn main() {
    let _: u8 = Cmd::Get.into();
    let _ = Cmd::try_from(0u8).unwrap();
}
