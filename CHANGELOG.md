# Unreleased

## Fixed

- `NaN` and infinite floats are now formatted as strings ("NaN", "inf",
  "-inf"), rather than serialized as JSON `null` by `serde_json`.

# 0.1.0 (October 26, 2025)

Initial release.
