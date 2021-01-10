# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Implemented `std::fmt::Display` for the `Rail` enumeration.

### Changed
- Changed `rail` method which sampled the voltage, current, and power of a rail
  with individual `output_select`, `output_voltage`, `output_current`, and
  `output_power` methods to provide finer control over readings.

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

[Unreleased]: https://github.com/newAM/corsairmi-rs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/newAM/corsairmi-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/newAM/corsairmi-rs/releases/tag/v0.1.0
