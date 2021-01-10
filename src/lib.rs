//! Read data from Corsair RMi and HXi series power supplies.
//!
//! This uses the Linux HIDRAW interface to communicate with the power supply.
//!
//! This crate is based off of this implementation in C: [notaz/corsairmi]
//!
//! # Example
//!
//! ```no_run
//! use corsairmi::PowerSupply;
//!
//! let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
//! println!("Power consumption: {:.1} Watts", psu.input_power()?);
//! # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
//! ```
//!
//! # udev rules
//!
//! You will most likely want to update your udev rules so that you can access
//! the power supply as a non superuser.
//!
//! These are my udev rules, you will need to update the `idProduct` field for
//! the product ID of your power supply, you can figure this value out with
//! `lsusb`, or by reading the source.
//!
//! Also note the value for `idProduct` must be **lowercase** hexadecimal.
//!
//! ```text
//! # /etc/udev/rules.d/99-corsair.rules
//! SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1b1c", ATTRS{idProduct}=="1c06", MODE="0666"
//! ```
//!
//! udev rules can be reloaded with
//! `sudo udevadm control --reload-rules && sudo udevadm trigger`
//!
//! [notaz/corsairmi]: https://github.com/notaz/corsairmi

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind, Read, Write},
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    time::Duration,
};

/// Corsair vendor ID.
pub const VID: u16 = 0x1B1C;

/// Power supply models compatible with this API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Model {
    RM650i,
    RM750i,
    RM850i,
    RM1000i,
    HX650i,
    HX750i,
    HX850i,
    HX1000i,
    HX1200i,
}

impl Model {
    /// Get the product ID for the power supply model.
    ///
    /// # Example
    ///
    /// ```
    /// use corsairmi::Model;
    ///
    /// let m: Model = Model::RM850i;
    /// assert_eq!(m.pid(), 0x1C0Cu16);
    /// ```
    pub fn pid(&self) -> u16 {
        match self {
            Model::RM650i => 0x1c0a,
            Model::RM750i => 0x1c0b,
            Model::RM850i => 0x1c0c,
            Model::RM1000i => 0x1c0d,
            Model::HX650i => 0x1c04,
            Model::HX750i => 0x1c05,
            Model::HX850i => 0x1c06,
            Model::HX1000i => 0x1c07,
            Model::HX1200i => 0x1c08,
        }
    }
}

/// Array of all models.
pub const MODELS: [Model; 9] = [
    Model::RM650i,
    Model::RM750i,
    Model::RM850i,
    Model::RM1000i,
    Model::HX650i,
    Model::HX750i,
    Model::HX850i,
    Model::HX1000i,
    Model::HX1200i,
];

/// Power supply output rail.
///
/// This is an input argument for [`PowerSupply::rail`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rail {
    /// 12V rail.
    Rail12v,
    /// 5V rail.
    Rail5v,
    /// 3.3V rail.
    Rail3v3,
}

impl Rail {
    pub(crate) fn idx(&self) -> u8 {
        match self {
            Rail::Rail12v => 0,
            Rail::Rail5v => 1,
            Rail::Rail3v3 => 2,
        }
    }
}

/// Array of all rails.
pub const RAILS: [Rail; 3] = [Rail::Rail12v, Rail::Rail5v, Rail::Rail3v3];

/// Output rail sample.
///
/// This is returned by [`PowerSupply::rail`].
#[derive(Debug)]
pub struct RailSample {
    /// Current in amps.
    pub current: f32,
    /// Voltage in volts.
    pub voltage: f32,
    /// Power in watts.
    ///
    /// Note: On my power supply this often does not add up to the product of
    /// current and voltage for some reason.
    pub power: f32,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case)]
struct hidraw_devinfo {
    bustype: u32,
    vendor: u16,
    product: u16,
}

/// Power supply error.
#[derive(Debug)]
pub enum OpenError {
    /// IO error.
    Io(io::Error),
    /// Invalid vendor ID.
    ///
    /// The inner value is the invalid vendor ID received.
    InvalidVendorId(u16),
    /// Invalid product ID.
    ///
    /// The inner value is the invalid product ID received.
    InvalidProductId(u16),
}

impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> Self {
        OpenError::Io(e)
    }
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Io(e) => write!(f, "{}", e),
            OpenError::InvalidVendorId(vid) => write!(
                f,
                "Invalid power supply vendor ID 0x{:04X} (expected 0x{:04X})",
                vid, VID
            ),
            OpenError::InvalidProductId(pid) => {
                write!(f, "Invalid power supply product ID 0x{:04X}", pid)
            }
        }
    }
}

impl std::error::Error for OpenError {}

/// Parses the USB (VID, PID) from the file path component.
///
/// The component is in the form of `0003:046D:C083.0006`.
fn parse_component(component: Option<OsString>) -> Option<(u16, u16)> {
    let component = component?;
    let data: &str = (&component).to_str()?;
    if data.len() < 14 {
        None
    } else {
        let vid: u16 = u16::from_str_radix(&data[5..9], 16).ok()?;
        let pid: u16 = u16::from_str_radix(&data[10..14], 16).ok()?;
        Some((vid, pid))
    }
}

/// Returns `true` if the VID and PID correspond to a valid power supply.
fn valid_vid_pid(vid: u16, pid: u16) -> bool {
    vid == VID && MODELS.iter().find(|m| m.pid() == pid).is_some()
}

/// Last component of a pathbuf, if it exists.
fn last_component(p: &PathBuf) -> Option<OsString> {
    Some(p.components().into_iter().last()?.as_os_str().to_owned())
}

/// List power supply device paths.
///
/// This works by reading the USB vendor ID (VID) and product ID (PID) under
/// `/sys/bus/usb/drivers/usbhid/{}/modalias` and comparing them to the known
/// VID/PID.
///
/// Typically these files are accessible without super user permissions.
///
/// # Example
///
/// ```
/// let mut list = corsairmi::list()?;
/// if let Some(path) = list.pop() {
///     let mut psu = corsairmi::PowerSupply::open(path)?;
///     // call psu methods here
/// } else {
///     eprintln!("No PSUs found");
/// }
/// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
/// ```
pub fn list() -> io::Result<Vec<PathBuf>> {
    let mut ret: Vec<PathBuf> = Vec::new();
    let sys_class_hidraw: &Path = Path::new("/sys/class/hidraw/");

    if sys_class_hidraw.is_dir() {
        for entry in fs::read_dir(sys_class_hidraw)? {
            if let Ok(mut link) = entry?.path().read_link() {
                if let Some(hidrawx) = last_component(&link) {
                    link.pop(); // e.g. hidraw9
                    link.pop(); // e.g. hidraw
                    if let Some((vid, pid)) = parse_component(last_component(&link)) {
                        if valid_vid_pid(vid, pid) {
                            let mut dev: PathBuf = PathBuf::from("/dev/");
                            dev.push(hidrawx);
                            if dev.exists() {
                                ret.push(dev);
                            }
                        }
                    }
                }
            }
        }
    }
    ret.sort();
    ret.dedup();
    Ok(ret)
}

/// Power supply.
#[derive(Debug)]
pub struct PowerSupply {
    f: File,
    model: Model,
}

impl PowerSupply {
    /// Open the power supply by file path.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // call psu methods here
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn open<P: AsRef<Path>>(path: P) -> Result<PowerSupply, OpenError> {
        let f: File = OpenOptions::new().read(true).write(true).open(path)?;

        // Only one IOCTL is needed for this crate.
        // I did not use the nix crate as it greatly increased compile times.
        const IOC_READ: libc::c_ulong = 2;
        const IOC_NRBITS: libc::c_ulong = 8;
        const IOC_TYPEBITS: libc::c_ulong = 8;
        const IOC_SIZEBITS: libc::c_ulong = 14;
        const IOC_NRSHIFT: libc::c_ulong = 0;
        const IOC_TYPESHIFT: libc::c_ulong = IOC_NRSHIFT + IOC_NRBITS;
        const IOC_SIZESHIFT: libc::c_ulong = IOC_TYPESHIFT + IOC_TYPEBITS;
        const IOC_DIRSHIFT: libc::c_ulong = IOC_SIZESHIFT + IOC_SIZEBITS;
        const HIDIOCGRAWINFO: libc::c_ulong = (IOC_READ << IOC_DIRSHIFT)
            | ((b'H' as libc::c_ulong) << IOC_TYPESHIFT)
            | (0x03 << IOC_NRSHIFT)
            | (std::mem::size_of::<hidraw_devinfo>() << IOC_SIZESHIFT) as libc::c_ulong;

        let mut info = hidraw_devinfo {
            bustype: u32::MAX,
            vendor: u16::MAX,
            product: u16::MAX,
        };
        let fd = f.as_raw_fd();
        // safety: `fd` will not be dropped until `f` is dropped
        let rc = unsafe { libc::ioctl(fd, HIDIOCGRAWINFO, &mut info) };

        if rc == -1 {
            Err(OpenError::Io(io::Error::last_os_error()))
        } else if info.vendor != VID {
            Err(OpenError::InvalidVendorId(info.vendor))
        } else if let Some(model) = MODELS.iter().find(|m| m.pid() == info.product) {
            Ok(PowerSupply { f, model: *model })
        } else {
            Err(OpenError::InvalidProductId(info.product))
        }
    }

    /// Get the power supply model.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // e.g. "PSU model: HX580i"
    /// println!("PSU model: {:?}", psu.model());
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn model(&self) -> Model {
        self.model
    }

    fn read(&mut self, cmd: &[u8; 3], buf: &mut [u8]) -> io::Result<()> {
        self.f.write_all(cmd)?;
        self.f.read_exact(buf)?;
        if buf[0] != cmd[0] || buf[1] != cmd[1] {
            Err(io::Error::new(
                ErrorKind::Other,
                "Unexpected response from power supply",
            ))
        } else {
            Ok(())
        }
    }

    fn read_string(&mut self, cmd: &[u8; 3]) -> io::Result<String> {
        let mut buf: [u8; 64] = [0; 64];
        self.read(cmd, &mut buf)?;
        let null_term: usize = buf.iter().position(|x| *x == 0).unwrap_or(buf.len());
        Ok(String::from_utf8_lossy(&buf[2..null_term]).to_string())
    }

    fn read_u32(&mut self, reg: u8) -> io::Result<u32> {
        let mut buf: [u8; 6] = [0; 6];
        self.read(&[0x03, reg, 0x0], &mut buf)?;
        Ok(u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]))
    }

    fn read_u16(&mut self, reg: u8) -> io::Result<u16> {
        let mut buf: [u8; 4] = [0; 4];
        self.read(&[0x03, reg, 0x0], &mut buf)?;
        Ok(u16::from_le_bytes([buf[2], buf[3]]))
    }

    fn output_select(&mut self, output: u8) -> io::Result<()> {
        debug_assert!(output <= 3);
        let cmd: [u8; 3] = [0x02, 0x00, output];
        let mut buf: [u8; 2] = [0; 2];
        self.read(&cmd, &mut buf)?;
        Ok(())
    }

    /// PC uptime.
    ///
    /// This is the duration that the PSU has been powering your PC.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // e.g. "PC uptime: 6935s"
    /// println!("PC uptime: {:?}", psu.pc_uptime()?);
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn pc_uptime(&mut self) -> io::Result<Duration> {
        let uptime: u32 = self.read_u32(0xD2)?;
        Ok(Duration::from_secs(u64::from(uptime)))
    }

    /// Power supply uptime.
    ///
    /// This is the duration that the PSU has been connected to AC power,
    /// regardless of whether or not your PC has been powered on.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // e.g. "PSU uptime: 10535s"
    /// println!("PSU uptime: {:?}", psu.uptime()?);
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn uptime(&mut self) -> io::Result<Duration> {
        let uptime: u32 = self.read_u32(0xD1)?;
        Ok(Duration::from_secs(u64::from(uptime)))
    }

    /// Model name.
    ///
    /// This often contains the same information as [`PowerSupply::model`],
    /// but this method is more expensive to call.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // e.g. "PSU name: HX850i"
    /// println!("PSU name: {:?}", psu.name()?);
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn name(&mut self) -> io::Result<String> {
        self.read_string(&[0xfe, 0x03, 0x00])
    }

    /// Vendor name.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // e.g. "PSU name: CORSAIR"
    /// println!("PSU name: {:?}", psu.vendor()?);
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn vendor(&mut self) -> io::Result<String> {
        self.read_string(&[0x03, 0x99, 0x00])
    }

    /// Product name.
    ///
    /// This often contains the same information as [`PowerSupply::model`],
    /// but this method is more expensive to call.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // e.g. "PSU product: HX850i"
    /// println!("PSU product: {:?}", psu.product()?);
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn product(&mut self) -> io::Result<String> {
        self.read_string(&[0x03, 0x9A, 0x00])
    }

    /// Temperature reading in celsius.
    ///
    /// I do not know what this is a temperature reading of.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // e.g. "Temperature: 42.25"
    /// println!("Temperature: {:.2}", psu.temp1()?);
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn temp1(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(0x8D)?))
    }

    /// Temperature reading in celsius.
    ///
    /// I do not know what this is a temperature reading of.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // e.g. "Temperature: 34.25"
    /// println!("Temperature: {:.2}", psu.temp2()?);
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn temp2(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(0x8E)?))
    }

    /// Fan rotations per minute.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // e.g. "RPM: 0.0"
    /// println!("RPM: {:.1}", psu.rpm()?);
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn rpm(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(0x90)?))
    }

    /// Input voltage in volts.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // e.g. "Input voltage: 115.0"
    /// println!("Input voltage: {:.1}", psu.input_voltage()?);
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn input_voltage(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(0x88)?))
    }

    /// Input power in watts.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // e.g. "Input power: 18.0"
    /// println!("Input power: {:.1}", psu.input_power()?);
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn input_power(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(0xEE)?))
    }

    /// Input current in amps.
    ///
    /// This is derived from the input power and input voltage.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::PowerSupply;
    ///
    /// let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
    /// // e.g. "Input current: 0.16"
    /// println!("Input current: {:.2}", psu.input_current()?);
    /// # Ok::<(), std::boxed::Box<dyn std::error::Error>>(())
    /// ```
    pub fn input_current(&mut self) -> io::Result<f32> {
        Ok(self.input_power()? / self.input_voltage()?)
    }

    /// Get the current, voltage, and power for an output rail.
    pub fn rail(&mut self, rail: Rail) -> io::Result<RailSample> {
        self.output_select(rail.idx())?;
        Ok(RailSample {
            voltage: half(self.read_u16(0x8B)?),
            current: half(self.read_u16(0x8C)?),
            power: half(self.read_u16(0x96)?),
        })
    }
}

/// Number format is IEEE half-precision float:
/// * 1 bit sign
/// * 5 bits exponent
/// * 10 bits fraction
#[must_use = "Why covert a value if you are not going to use the result?"]
fn half(reg: u16) -> f32 {
    let exponent: i32 = ((reg as i16) >> 11) as i32;
    let fraction: i32 = ((reg as i32) << 21) >> 21;
    (fraction as f32) * 2.0_f32.powi(exponent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn unique_pid() {
        let mut pids: HashSet<u16> = HashSet::with_capacity(MODELS.len());
        for model in MODELS.iter() {
            let pid: u16 = model.pid();
            if pids.get(&pid).is_some() {
                panic!("PID 0x{:04X} for model {:?} is a duplicate", pid, model);
            }
            pids.insert(model.pid());
        }
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn half_convert() {
        assert_eq!(half(0), 0.0);
        assert_eq!(half(0xF087), 33.75);
        assert_eq!(half(0xF07D), 31.25);
        assert_eq!(half(0xF062), 24.5);
        assert_eq!(half(0x1000), 0.0);
        assert_eq!(half(0xF8E6), 115.0);
        assert_eq!(half(0x0809), 18.0);
        assert_eq!(half(0xD30A), 12.15625);
        assert_eq!(half(0xF003), 0.75);
        assert_eq!(half(0x0804), 8.0);
        assert_eq!(half(0xD141), 5.015625);
        assert_eq!(half(0xE01A), 1.625);
        assert_eq!(half(0xF80F), 7.5);
        assert_eq!(half(0xD0D3), 3.296875);
        assert_eq!(half(0xE00D), 0.8125);
        assert_eq!(half(0xF805), 2.5);
    }

    #[test]
    fn parse_component_some() {
        assert_eq!(
            parse_component(Some(OsString::from("0000:1B1C:1C06.000A"))),
            Some((0x1B1C, 0x1C06))
        );
        assert_eq!(
            parse_component(Some(OsString::from("0000:1b1c:1c06.000a"))),
            Some((0x1B1C, 0x1C06))
        );
        assert_eq!(
            parse_component(Some(OsString::from("0000:1B1C:1C06"))),
            Some((0x1B1C, 0x1C06))
        );
        assert_eq!(
            parse_component(Some(OsString::from("0000:1B1C:1C06.000AAAAAAAAA"))),
            Some((0x1B1C, 0x1C06)),
        );
    }

    #[test]
    fn parse_component_none() {
        assert_eq!(parse_component(None), None);
        assert_eq!(
            parse_component(Some(OsString::from("0000:1B1Z:1C06.000A"))),
            None,
        );

        assert_eq!(parse_component(Some(OsString::from("0000:1B1C:1C0"))), None);
    }

    #[test]
    fn test_valid_vid_pid() {
        assert!(valid_vid_pid(VID, Model::HX850i.pid()));
        assert!(!valid_vid_pid(0x1234, Model::HX850i.pid()));
        assert!(!valid_vid_pid(VID, 0x1234));
    }
}
