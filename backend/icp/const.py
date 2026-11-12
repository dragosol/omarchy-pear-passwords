"""Static identity strings Pear presents to Apple's account services.

Apple tracks these, so they are kept stable. The volatile per-request machine data
(X-Apple-I-MD*) comes from the anisette server, not from here.
"""

# Who Pear says it is to Apple's account services: iCloud for Windows.
#
# Since October 2026 GrandSlam compares the platform a client names in X-Mme-Client-Info with
# the platform of the ADI library that made its anisette data. The anisette helper runs Apple's
# Windows ADI (CoreADI64.dll from iCloud for Windows 15.10.39, anisette/), so every account call
# names that Windows client. Measured 2026-11-11 with GSA o=init on a nonexistent account:
#   Windows ADI + this identity                         -> -20970 (an ordinary account error)
#   Windows ADI + the Mac identity Pear used before     -> -80044
#   Windows ADI + "<PC> <Windows;...> <...AuthKit/1 (com.apple.akd/1.0)>" -> HTTP 403
#   Android ADI (anisette-v3-server) + any identity     -> -80045 or HTTP 403
# Apple also binds the PET and the tokens derived from it to that platform, so the iCloud setup,
# escrow and CloudKit calls name the same Windows platform, each with its own service.
CLIENT_PLATFORM = "<PC> <Windows;6.2(0,0);9200>"
GSA_USER_AGENT = "com.apple.AuthKitWin/7.3"
GSA_CLIENT_INFO = f"{CLIENT_PLATFORM} <com.apple.AuthKitWin/7.3 (com.apple.iCloud/15.10.0.39)>"
# The services behind the token: X-Mme-Client-Info is CLIENT_PLATFORM plus one of these.
ICLOUD_SERVICE = "com.apple.AOSKit/282 (com.apple.accountsd/113)"
ESCROW_SERVICE = "com.apple.AuthKit/1 (com.apple.sbd/638.100.48)"
CLOUDKIT_SERVICE = "com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"


def client_info(service: str) -> str:
    return f"{CLIENT_PLATFORM} <{service}>"


# The Mac Pear describes inside the keychain itself: the Octagon peer's model and OS, and the
# device fields of CloudKit's protobuf requests. The keychain circle is joined as a Mac, and
# these are not the account-service headers above (which name iCloud for Windows). One source of
# truth, because they used to be copied into several modules and had drifted apart.
DEVICE_MODEL = "Mac16,7"
OS_VERSION = "26.6"
OS_BUILD = "25G72"
DARWIN_VERSION = "25.6.0"
CFNETWORK_VERSION = "1640.0.3"

# Pear's anisette server (anisette/, run by the pear-passwords-anisette user unit).
# Override with ICP_ANISETTE_URL.
DEFAULT_ANISETTE_URL = "http://localhost:6969"

GSA_ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"
