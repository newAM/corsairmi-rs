use std::{
    io::{self, ErrorKind},
    path::Path,
    time::Duration,
};

#[cfg(feature = "tokio")]
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::{cmd, half, Model, OpenError, Rail, HID_REPORT_LEN};

impl From<crate::PowerSupply> for PowerSupply {
    fn from(psu: crate::PowerSupply) -> Self {
        PowerSupply {
            f: psu.f.into(),
            model: psu.model,
        }
    }
}

/// Power supply with asynchronous methods.
///
/// This is extremely overkill for the amount of IO the power supply requires,
/// and the async runtime may actually slow things down depending on your
/// application.
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
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let psu: PowerSupply = PowerSupply::open("/dev/hidraw5").await?;
    /// // call psu methods here
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open<P: AsRef<Path>>(path: P) -> Result<PowerSupply, OpenError> {
        let f: File = OpenOptions::new().read(true).write(true).open(path).await?;
        let (f, model) = crate::open(f)?;
        Ok(PowerSupply { f, model })
    }

    /// Get the power supply model.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let psu: PowerSupply = PowerSupply::open("/dev/hidraw5").await?;
    /// // e.g. "PSU model: HX580i"
    /// println!("PSU model: {:?}", psu.model());
    /// # Ok(())
    /// # }
    /// ```
    pub const fn model(&self) -> Model {
        self.model
    }

    async fn read(&mut self, cmd: &[u8; 3]) -> io::Result<[u8; HID_REPORT_LEN]> {
        let mut buf: [u8; HID_REPORT_LEN] = [0; HID_REPORT_LEN];
        self.f.write_all(cmd).await?;
        self.f.read_exact(&mut buf).await?;
        if buf[0] != cmd[0] || buf[1] != cmd[1] {
            Err(io::Error::new(
                ErrorKind::Other,
                "Unexpected response from power supply",
            ))
        } else {
            Ok(buf)
        }
    }

    async fn read_string(&mut self, cmd: &[u8; 3]) -> io::Result<String> {
        const RESPONSE_BYTES: usize = 2;
        let buf = self.read(cmd).await?;
        let null_term: usize = buf
            .iter()
            .skip(RESPONSE_BYTES)
            .position(|x| *x == 0)
            .unwrap_or(buf.len() - RESPONSE_BYTES)
            + RESPONSE_BYTES;
        Ok(String::from_utf8_lossy(&buf[RESPONSE_BYTES..null_term]).to_string())
    }

    async fn read_u32(&mut self, reg: u8) -> io::Result<u32> {
        let buf = self.read(&[0x03, reg, 0x0]).await?;
        Ok(u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]))
    }

    async fn read_u16(&mut self, reg: u8) -> io::Result<u16> {
        let buf = self.read(&[0x03, reg, 0x0]).await?;
        Ok(u16::from_le_bytes([buf[2], buf[3]]))
    }

    /// PC uptime.
    ///
    /// This is the duration that the PSU has been powering your PC.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// // e.g. "PC uptime: 6935s"
    /// println!("PC uptime: {:?}", psu.pc_uptime().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn pc_uptime(&mut self) -> io::Result<Duration> {
        let uptime: u32 = self.read_u32(cmd::PC_UPTIME).await?;
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
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// // e.g. "PSU uptime: 10535s"
    /// println!("PSU uptime: {:?}", psu.uptime().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn uptime(&mut self) -> io::Result<Duration> {
        let uptime: u32 = self.read_u32(cmd::UPTIME).await?;
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
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// // e.g. "PSU name: HX850i"
    /// println!("PSU name: {:?}", psu.name().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn name(&mut self) -> io::Result<String> {
        self.read_string(&cmd::NAME).await
    }

    /// Vendor name.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// // e.g. "PSU name: CORSAIR"
    /// println!("PSU name: {:?}", psu.vendor().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn vendor(&mut self) -> io::Result<String> {
        self.read_string(&cmd::VENDOR).await
    }

    /// Product name.
    ///
    /// This often contains the same information as [`PowerSupply::model`],
    /// but this method is more expensive to call.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// // e.g. "PSU product: HX850i"
    /// println!("PSU product: {:?}", psu.product().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn product(&mut self) -> io::Result<String> {
        self.read_string(&cmd::PRODUCT).await
    }

    /// Temperature reading in Celsius.
    ///
    /// I do not know what this is a temperature reading of.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// // e.g. "Temperature: 42.25"
    /// println!("Temperature: {:.2}", psu.temp1().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn temp1(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(cmd::TEMP1).await?))
    }

    /// Temperature reading in Celsius.
    ///
    /// I do not know what this is a temperature reading of.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// // e.g. "Temperature: 34.25"
    /// println!("Temperature: {:.2}", psu.temp2().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn temp2(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(cmd::TEMP2).await?))
    }

    /// Fan rotations per minute.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// // e.g. "RPM: 0.0"
    /// println!("RPM: {:.1}", psu.rpm().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn rpm(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(cmd::RPM).await?))
    }

    /// Input voltage in volts.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// // e.g. "Input voltage: 115.0"
    /// println!("Input voltage: {:.1}", psu.input_voltage().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn input_voltage(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(cmd::IN_VOLTAGE).await?))
    }

    /// Input power in watts.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// // e.g. "Input power: 18.0"
    /// println!("Input power: {:.1}", psu.input_power().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn input_power(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(cmd::IN_POWER).await?))
    }

    /// Input current in amps.
    ///
    /// This is derived from the input power and input voltage.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::aio::PowerSupply;
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// // e.g. "Input current: 0.16"
    /// println!("Input current: {:.2}", psu.input_current().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn input_current(&mut self) -> io::Result<f32> {
        let power = self.input_power().await?;
        let voltage = self.input_voltage().await?;
        Ok(power / voltage)
    }

    /// Select the output rail to read from.
    ///
    /// This should be called before calling
    /// [`PowerSupply::output_voltage`],
    /// [`PowerSupply::output_current`],
    /// or [`PowerSupply::output_power`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::{aio::PowerSupply, Rail, RAILS};
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// for rail in RAILS.iter() {
    ///     psu.output_select(*rail).await?;
    ///     println!("{} output voltage: {}V", rail, psu.output_voltage().await?);
    ///     println!("{} output current: {}A", rail, psu.output_current().await?);
    ///     println!("{} output power: {}W", rail, psu.output_power().await?);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn output_select(&mut self, rail: Rail) -> io::Result<()> {
        debug_assert!(rail.idx() <= 3);
        let cmd: [u8; 3] = cmd::output_select(rail.idx());
        self.read(&cmd).await?;
        Ok(())
    }

    /// Get the output voltage in volts.
    ///
    /// Call [`PowerSupply::output_select`] to select the rail to read from.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::{aio::PowerSupply, Rail};
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// psu.output_select(Rail::Rail12v).await?;
    /// println!("12V rail output voltage: {}V", psu.output_voltage().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn output_voltage(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(cmd::OUT_VOLTAGE).await?))
    }

    /// Get the output current in amps.
    ///
    /// Call [`PowerSupply::output_select`] to select the rail to read from.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::{aio::PowerSupply, Rail};
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// psu.output_select(Rail::Rail12v).await?;
    /// println!("12V rail output current: {}A", psu.output_current().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn output_current(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(cmd::OUT_CURRENT).await?))
    }

    /// Get the output power in watts.
    ///
    /// Call [`PowerSupply::output_select`] to select the rail to read from.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use corsairmi::{aio::PowerSupply, Rail};
    ///
    /// # async fn dox() -> Result<(), corsairmi::OpenError> {
    /// let mut psu = PowerSupply::open("/dev/hidraw5").await?;
    /// psu.output_select(Rail::Rail12v).await?;
    /// println!("12V rail output power: {}W", psu.output_power().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn output_power(&mut self) -> io::Result<f32> {
        Ok(half(self.read_u16(cmd::OUT_POWER).await?))
    }
}
