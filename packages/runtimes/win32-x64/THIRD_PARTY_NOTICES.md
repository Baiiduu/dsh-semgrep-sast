# Third-Party Notices

`@aaub-software/semgrep-runtime-win32-x64` is an aggregate binary distribution.
Its components remain subject to their respective licenses; installing this
package does not replace or relicense those components.

## AAUB Software packaging files

The package metadata, runtime manifest, and assembly scripts authored for this
project are distributed under the MIT License. The repository-level license
file contains the applicable terms.

## CPython 3.14.7

- Project: Python
- Upstream: https://www.python.org/
- Source release: https://www.python.org/downloads/release/python-3147/
- License: Python Software Foundation License Version 2 and the additional
  notices shipped with CPython
- Packaged license location: `runtime/python/LICENSE.txt`

The runtime is assembled from Python's official Windows x64 embeddable archive.
This project changes its module search-path configuration but does not modify
CPython source code.

## Semgrep 1.175.0

- Project: Semgrep Community Edition
- Upstream: https://github.com/semgrep/semgrep
- Corresponding source: https://github.com/semgrep/semgrep/tree/v1.175.0
- License: GNU Lesser General Public License v2.1 or later
- Package metadata: https://pypi.org/project/semgrep/1.175.0/

The runtime is assembled from Semgrep's official Windows x64 wheel. This
project does not modify Semgrep source code. License files carried by the wheel
remain in its installed `.dist-info` metadata and are also collected under the
package's `licenses/` directory during release preparation.

## pip 26.2.1

- Project: pip
- Upstream: https://github.com/pypa/pip
- License: MIT License

pip is included only to assemble the private Python environment. Its license
metadata remains in `runtime/python/Lib/site-packages/pip-26.2.1.dist-info/`.

## Python package dependencies

The complete, version-pinned dependency inventory is in `requirements.lock`.
Each dependency remains under the license declared by its own distribution.
License texts and package metadata retained from installed wheels are collected
under `licenses/python-packages/` during release preparation.

## Semgrep Registry rules

This npm package does not contain or redistribute the `p/default` ruleset or
other Semgrep Registry rules. At scan time, Semgrep obtains the selected ruleset
directly from the Registry. Registry rules are governed by Semgrep's separate
rules license: https://semgrep.dev/legal/rules-license/

## Trademarks

Python, Semgrep, pip, and their associated names and marks belong to their
respective owners. Their inclusion here does not imply endorsement of this
package or of AAUB Software.
