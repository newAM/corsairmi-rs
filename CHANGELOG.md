# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1+deprecated] - 2024-08-31

**Deprecated** Newer Linux kernels have a native driver for these power supplies.

## [2.0.0] - 2022-10-16
### Added
- Added support for the AX1500i and HX1500i models.
  - This is a potentially breaking change because the `MODELS` array has been expanded.

### Removed
- Removed `#[non_exhaustive]` from `Models`.

## [1.0.0] - 2021-12-27
### Changed
- Update the edition from `2018` to `2021`.

## [0.4.0] - 2021-01-30
### Added
- Added `doc_cfg` to docs.rs builds.
- Added `html_root_url` to docs.

### Changed
- Moved `AsyncPowerSupply` to `aio::PowerSupply`.

## [0.3.2] - 2021-01-24
### Fixed
- Fixed clipped strings returned by `name`, `product`, and `vendor` methods.

## [0.3.1] - 2021-01-17
### Fixed
- Fixed occasional IO errors due to incorrect HID report read buffer size.

## [0.3.0] - 2021-01-10
### Added
- Implemented `std::fmt::Display` for the `Rail` enumeration.
- Added `AsyncPowerSupply` with the `tokio` feature flag.

### Changed
- Replaced the `rail` method which sampled the voltage, current, and power of a
  rail with individual `output_select`, `output_voltage`, `output_current`, and
  `output_power` methods.

### Fixed
- Fixed misleading documentation comment for the `list` function.

## [0.2.0] - 2021-01-09
### Added
- Added `udev` setup instructions to the docs.

### Changed
- Changed the write failure error from `std::io::ErrorKind::Other` to
  `std::io::ErrorKind::Interrupted`.
- Added a `list` function to list power supply device paths.

## [0.1.0] - 2021-01-07
- Initial release

[2.0.1+deprecated]: https://github.com/newAM/corsairmi-rs/compare/v2.0.0...v2.0.1%2Bdeprecated
[2.0.0]: https://github.com/newAM/corsairmi-rs/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/newAM/corsairmi-rs/compare/v0.4.0...v1.0.0
[0.4.0]: https://github.com/newAM/corsairmi-rs/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/newAM/corsairmi-rs/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/newAM/corsairmi-rs/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/newAM/corsairmi-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/newAM/corsairmi-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/newAM/corsairmi-rs/releases/tag/v0.1.0
