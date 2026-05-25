use nlink_macros::GenlCommand;

#[derive(GenlCommand)]
#[genl_command(repr = "f64")]
pub enum BadRepr {
    A = 0,
}

fn main() {}
