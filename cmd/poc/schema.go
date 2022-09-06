package main

import (
	"time"

	commonFlag "github.com/containers/common/pkg/flag"
	"github.com/containers/common/pkg/retry"
)

type globalOptions struct {
	debug              bool          // Enable debug output
	tlsVerify          bool          // Require HTTPS and verify certificates (for docker: and docker-daemon:)
	policyPath         string        // Path to a signature verification policy file
	insecurePolicy     bool          // Use an "allow everything" signature verification policy
	registriesDirPath  string        // Path to a "registries.d" registry configuration directory
	overrideArch       string        // Architecture to use for choosing images, instead of the runtime one
	overrideOS         string        // OS to use for choosing images, instead of the runtime one
	overrideVariant    string        // Architecture variant to use for choosing images, instead of the runtime one
	commandTimeout     time.Duration // Timeout for the command execution
	registriesConfPath string        // Path to the "registries.conf" file
	tmpDir             string        // Path to use for big temporary files
}

type copyOptions struct {
	global                   *globalOptions
	deprecatedTLSVerify      *deprecatedTLSVerifyOption
	srcImage                 *imageOptions
	destImage                *imageDestOptions
	retryOpts                *retry.Options
	additionalTags           []string                  // For docker-archive: destinations, in addition to the name:tag specified as destination, also add these
	removeSignatures         bool                      // Do not copy signatures from the source image
	signByFingerprint        string                    // Sign the image using a GPG key with the specified fingerprint
	signBySigstorePrivateKey string                    // Sign the image using a sigstore private key
	signPassphraseFile       string                    // Path pointing to a passphrase file when signing (for either signature format, but only one of them)
	signIdentity             string                    // Identity of the signed image, must be a fully specified docker reference
	digestFile               string                    // Write digest to this file
	format                   commonFlag.OptionalString // Force conversion of the image to a specified format
	quiet                    bool                      // Suppress output information when copying images
	all                      bool                      // Copy all of the images if the source is a list
	multiArch                commonFlag.OptionalString // How to handle multi architecture images
	preserveDigests          bool                      // Preserve digests during copy
	encryptLayer             []int                     // The list of layers to encrypt
	encryptionKeys           []string                  // Keys needed to encrypt the image
	decryptionKeys           []string                  // Keys needed to decrypt the image
}
