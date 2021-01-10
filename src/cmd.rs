pub const PC_UPTIME: u8 = 0xD2;
pub const UPTIME: u8 = 0xD1;
pub const NAME: [u8; 3] = [0xfe, 0x03, 0x00];
pub const VENDOR: [u8; 3] = [0x03, 0x99, 0x00];
pub const PRODUCT: [u8; 3] = [0x03, 0x9A, 0x00];
pub const TEMP1: u8 = 0x8D;
pub const TEMP2: u8 = 0x8E;
pub const RPM: u8 = 0x90;
pub const IN_VOLTAGE: u8 = 0x88;
pub const IN_POWER: u8 = 0xEE;
pub const OUT_VOLTAGE: u8 = 0x8B;
pub const OUT_CURRENT: u8 = 0x8C;
pub const OUT_POWER: u8 = 0x96;

pub const fn output_select(sel: u8) -> [u8; 3] {
    [0x02, 0x00, sel]
}
