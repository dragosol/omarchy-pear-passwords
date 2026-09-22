"""Static identity strings used to impersonate a Mac to Apple's GrandSlam service.

These mirror what AltServer / pypush send. Apple tracks some of these, so they are
kept stable and Mac-like. The volatile per-request machine data (X-Apple-I-MD*) comes
from the anisette server, not from here.
"""

# Sent as the GsService2 User-Agent. Darwin 25.6.0 == macOS 26.6 (Darwin's major runs one
# behind the marketing version, which is also why macOS 26 builds start with 25).
# The CFNetwork build is extrapolated, not confirmed - the published anchors are 1410 with
# Darwin 22.6.0 and 1498.700.2 with Darwin 23.6.0. Apple's rejection cited the OS version,
# which comes from GSA_CLIENT_INFO below, so this field is unlikely to be what is checked.
GSA_USER_AGENT = "akd/1.0 CFNetwork/1640.0.3 Darwin/25.6.0"

# Identifies us as a specific Mac model + OS + AuthKit client.
#
# Must claim macOS 13.1 or later on hardware that can actually run it. The original values
# (<MacBookPro13,2> <Mac OS X;10.15.2>) described a 2016 MacBook Pro on Catalina, and Apple
# refuses the account outright: it answers the 2FA trigger with HTTP 200 whose body is
#   "Your Apple ID can only be used on devices running iOS 16.2 or later, or macOS 13.1 or
#    later. This MacBook Pro can't be updated to the latest software."
# so no code is ever pushed. Bumping the OS alone is not enough - the model is part of what
# Apple checks, and a 2016 MacBook Pro cannot run anything past Monterey.
#
# Current shipping macOS: 26.6, build 25G72 (released 2026-07-27). Mac16,7 is the 16" M4 Pro
# MacBook Pro (Nov 2024). "Mac OS X" is the literal token this header has always used,
# regardless of the marketing name.
#
# The trailing client MUST be com.apple.akd, not com.apple.dt.Xcode. Since early September
# 2026 Apple's GSA edge refuses any POST naming Xcode with a 190-byte HTML 503 before it ever
# looks at the credentials; akd is the daemon that really makes this call on macOS and is
# let through. Same fix as AltServer 1.7.6. Verified here: Xcode -> 503, akd -> 200 plist.
GSA_CLIENT_INFO = (
    "<Mac16,7> <Mac OS X;26.6;25G72> "
    "<com.apple.AuthKit/1 (com.apple.akd/1.0)>"
)

# One source of truth for the impersonated hardware. Apple checks these across calls and
# rejects a device that describes itself differently to GSA, loginDelegates, escrowproxy and
# CloudKit - the values used to be copied into five modules and had already drifted apart.
# Note the OS token differs by endpoint: "Mac OS X" for GSA/iCloud/CloudKit, "macOS" for
# escrowproxy. Only the version and model are shared.
DEVICE_MODEL = "Mac16,7"
OS_VERSION = "26.6"
OS_BUILD = "25G72"
DARWIN_VERSION = "25.6.0"
CFNETWORK_VERSION = "1640.0.3"

# Default anisette server (SideStore ecosystem). Override with ICP_ANISETTE_URL.
DEFAULT_ANISETTE_URL = "http://localhost:6969"

GSA_ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"
