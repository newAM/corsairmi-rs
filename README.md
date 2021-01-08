![Maintenance](https://img.shields.io/badge/maintenance-experimental-blue.svg)
[![crates.io](https://img.shields.io/crates/v/corsairmi.svg)](https://crates.io/crates/corsairmi)
[![docs.rs](https://docs.rs/corsairmi/badge.svg)](https://docs.rs/corsairmi/)
[![CI](https://github.com/newAM/corsairmi-rs/workflows/CI/badge.svg)](https://github.com/newAM/corsairmi-rs/actions)

# corsairmi

Read data from Corsair RMi and HXi series power supplies.

This uses the Linux HIDRAW interface to communicate with the power supply.

This crate is based off of this implementation in C: [notaz/corsairmi]

## Example

```rust
use corsairmi::PowerSupply;

let mut psu: PowerSupply = PowerSupply::open("/dev/hidraw5")?;
println!("Power consumption: {:.1} Watts", psu.input_power()?);
```

[notaz/corsairmi]: https://github.com/notaz/corsairmi
