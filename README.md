# Overview

Simple skopeo POC

## Example usage

```
# downlaod ubi image to local disk (ubi directory) in oci format with remove signatures to true
./bin/poc -i docker://registry.redhat.io/ubi8/ubi -v latest -a copy -p oci:ubi -r true

```
