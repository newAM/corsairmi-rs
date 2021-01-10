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

## udev rules

You will most likely want to update your udev rules so that you can access
the power supply as a non superuser.

These are my udev rules, you will need to update the `idProduct` field for
the product ID of your power supply, you can figure this value out with
`lsusb`, or by reading the source.

Also note the value for `idProduct` must be **lowercase** hexadecimal.

```
# /etc/udev/rules.d/99-corsair.rules
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1b1c", ATTRS{idProduct}=="1c06", MODE="0666"
```

udev rules can be reloaded with
`sudo udevadm control --reload-rules && sudo udevadm trigger`

[notaz/corsairmi]: https://github.com/notaz/corsairmi
