#ifndef FOTA_SECURE_CONFIG_H
#define FOTA_SECURE_CONFIG_H

/* Single-platform configuration for v1 - the one edit point described in
 * docs/FORMAT_SPEC.md's "Explicit Extension Point" section. Adding
 * multi-platform support later means replacing FOTA_CONFIG_PLATFORM_TAG
 * with a small table of supported tags (see that section) - the wire
 * format doesn't need to change.
 *
 * The signing public key and platform tag are baked in at build/
 * provisioning time (docs/THREAT_MODEL.md: "not user-suppliable"), not
 * runtime arguments - that's the whole point of a baked-in root of
 * trust. Paths below point at where the device's provisioned files
 * live; adjust for your actual provisioning layout. */

#define FOTA_CONFIG_PLATFORM_TAG "GENERIC"

#define FOTA_CONFIG_INSTALL_DIR "/opt/fota-secure/install"
#define FOTA_CONFIG_VERSION_FILE "/etc/fota-secure/version"
#define FOTA_CONFIG_SIGNING_PUBLIC_KEY_FILE "/etc/fota-secure/signing_public.pem"
#define FOTA_CONFIG_DEVICE_PRIVATE_KEY_FILE "/etc/fota-secure/device_private.pem"
#define FOTA_CONFIG_DOWNGRADE_SECRET_HASH_FILE                               \
    "/etc/fota-secure/downgrade_secret.hash"

#endif /* FOTA_SECURE_CONFIG_H */
