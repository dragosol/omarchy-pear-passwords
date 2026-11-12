#!/usr/bin/env python3
"""Fetch Apple's CoreADI64.dll from the iCloud for Windows package in the Microsoft Store.

Usage: fetch-coreadi.py OUTPUT_DIR

The Store hands packages out through its Windows Update delivery service (FE3): a cookie, a sync
of the product's category, then a short-lived download URL per file. No account is involved. The
URL expires within hours, so it is asked for on each fetch; what is pinned is the package itself:
its moniker, the SHA-1 digest the service lists for it, and the SHA-256 of the package and of the
one DLL taken from it (coreadi.sha256). Anything else is refused before it is written to
OUTPUT_DIR. Only CoreADI64.dll is kept; the rest of the 337 MB package is deleted.

Standard library only. The Store's FE3 host chains to Microsoft Root Certificate Authority 2011,
which most Linux CA bundles leave out, so that one root (microsoft-root-ca-2011.pem) is the only
anchor trusted for it. The catalog lookup uses the system's CA bundle. The package download itself
is plain HTTP on Microsoft's CDN; the digests are what make it safe to use.
"""

import base64
import hashlib
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
PRODUCT_ID = "9PKTQ5699M62"
MONIKER = "AppleInc.iCloud_15.10.39.0_x64__nzyj5cx40ttqa"
PACKAGE_SHA1_B64 = "P1Kpw7IV6KPQTx4bY13iRTC5uyA="
MEMBER = "iCloud/CoreADI64.dll"
PACKAGE_NAME = "AppleInc.iCloud_15.10.39.0_x64.msix"
DLL_NAME = "CoreADI64.dll"

CATALOG = (f"https://displaycatalog.mp.microsoft.com/v7.0/products/{PRODUCT_ID}"
           "?market=US&languages=en-US")
FE3 = "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx"
FE3_SECURED = FE3 + "/secured"
WU_NS = "{http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService}"
UA = "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.0"
# What the sync claims to be: a current Windows 10 desktop. These attributes and the installed-update
# ids below are the ones Store clients send (as StoreLib and store.rg-adguard do); with fewer of
# them the service answers with an empty sync.
DEVICE = ("BranchReadinessLevel=CB;CurrentBranch=rs_prerelease;OEMModel=Virtual Machine;"
          "FlightRing=WIS;AttrDataVer=21;SystemManufacturer=Microsoft Corporation;"
          "InstallLanguage=en-US;OSUILocale=en-US;InstallationType=Client;"
          "FlightingBranchName=external;FirmwareVersion=Hyper-V UEFI Release v2.5;"
          "SystemProductName=Virtual Machine;OSSkuId=48;FlightContent=Branch;App=WU;"
          "OEMName_Uncleaned=Microsoft Corporation;AppVer=10.0.16184.1001;"
          "OSArchitecture=AMD64;SystemSKU=None;UpdateManagementGroup=2;"
          "IsFlightingEnabled=1;IsDeviceRetailDemo=0;TelemetryLevel=3;"
          "OSVersion=10.0.16184.1001;DeviceFamily=Windows.Desktop;")
INSTALLED = (1, 2, 3, 11, 19, 544, 549, 2359974, 2359977, 5169044, 8788830, 23110993, 23110994,
             54341900, 54343656, 59830006, 59830007, 59830008, 60484010, 62450018, 62450019,
             62450020, 66027979, 66053150, 97657898, 98822896, 98959022, 98959023, 98959024,
             98959025, 98959026)


def die(message: str) -> None:
    print(f"fetch-coreadi: {message}", file=sys.stderr)
    sys.exit(1)


def digests() -> dict:
    out = {}
    with open(os.path.join(HERE, "coreadi.sha256")) as f:
        for line in f:
            if line.strip() and not line.lstrip().startswith("#"):
                digest, name = line.split()
                out[name] = digest
    return out


SYSTEM_TLS = ssl.create_default_context()
FE3_TLS = ssl.create_default_context(cafile=os.path.join(HERE, "microsoft-root-ca-2011.pem"))


def request(url: str, *, body: str | None = None, tls=SYSTEM_TLS, timeout: int = 60) -> bytes:
    headers = {"User-Agent": UA}
    if body is not None:
        headers["Content-Type"] = "application/soap+xml; charset=utf-8"
    req = urllib.request.Request(url, data=body.encode() if body is not None else None,
                                 headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=tls) as resp:
        return resp.read()


def soap(action: str, to: str, body: str) -> ET.Element:
    now = time.gmtime()
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", now)
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 300))
    envelope = f"""<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header>
<a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/{action}</a:Action>
<a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID><a:To s:mustUnderstand="1">{to}</a:To>
<o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><Created>{created}</Created><Expires>{expires}</Expires></Timestamp>
<wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization"><TicketType Name="MSA" Version="1.0" Policy="MBI_SSL"><User /></TicketType></wuws:WindowsUpdateTicketsToken>
</o:Security></s:Header><s:Body>{body}</s:Body></s:Envelope>"""
    return ET.fromstring(request(to, body=envelope, tls=FE3_TLS))


def category_id() -> str:
    product = json.loads(request(CATALOG))["Product"]
    for sku in product.get("DisplaySkuAvailabilities") or []:
        data = (sku.get("Sku") or {}).get("Properties", {}).get("FulfillmentData") or {}
        if data.get("WuCategoryId"):
            return data["WuCategoryId"]
    die(f"the Store catalog lists no download category for {PRODUCT_ID}")


def cookie() -> str:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    root = soap("GetCookie", FE3, f"""<GetCookie xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
<oldCookie></oldCookie><lastChange>2015-10-21T17:01:07.1472913Z</lastChange><currentTime>{stamp}</currentTime>
<protocolVersion>1.40</protocolVersion></GetCookie>""")
    for el in root.iter():
        if el.tag.endswith("EncryptedData") and el.text:
            return el.text.strip()
    die("the Store's delivery service gave no cookie")


def update_identity(encrypted: str, category: str) -> tuple[str, str]:
    """The update id and revision of exactly MONIKER within the product's category."""
    root = soap("SyncUpdates", FE3, f"""<SyncUpdates xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
<cookie><Expiration>2045-03-11T02:02:48Z</Expiration><EncryptedData>{encrypted}</EncryptedData></cookie><parameters>
<ExpressQuery>false</ExpressQuery><InstalledNonLeafUpdateIDs>{"".join(f"<int>{i}</int>" for i in INSTALLED)}</InstalledNonLeafUpdateIDs>
<OtherCachedUpdateIDs></OtherCachedUpdateIDs><SkipSoftwareSync>false</SkipSoftwareSync>
<NeedTwoGroupOutOfScopeUpdates>true</NeedTwoGroupOutOfScopeUpdates>
<FilterAppCategoryIds><CategoryIdentifier><Id>{category}</Id></CategoryIdentifier></FilterAppCategoryIds>
<TreatAppCategoryIdsAsInstalled>true</TreatAppCategoryIdsAsInstalled><AlsoPerformRegularSync>false</AlsoPerformRegularSync>
<ComputerSpec/><ExtendedUpdateInfoParameters><XmlUpdateFragmentTypes><XmlUpdateFragmentType>Extended</XmlUpdateFragmentType></XmlUpdateFragmentTypes>
<Locales><string>en-US</string><string>en</string></Locales></ExtendedUpdateInfoParameters><ClientPreferredLanguages><string>en-US</string></ClientPreferredLanguages>
<ProductsParameters><SyncCurrentVersionOnly>false</SyncCurrentVersionOnly><DeviceAttributes>{DEVICE}</DeviceAttributes>
<CallerAttributes>Interactive=1;IsSeeker=0;</CallerAttributes><Products/></ProductsParameters></parameters></SyncUpdates>""")
    for info in root.iter(WU_NS + "UpdateInfo"):
        xml = info.find(WU_NS + "Xml")
        if xml is None or not xml.text:
            continue
        inner = ET.fromstring("<r>" + xml.text + "</r>")
        identity = inner.find("UpdateIdentity")
        monikers = {e.get("PackageMoniker") for e in inner.iter("AppxMetadata")}
        if identity is not None and MONIKER in monikers and inner.find(".//SecuredFragment") is not None:
            return identity.get("UpdateID"), identity.get("RevisionNumber")
    die(f"the Store no longer offers {MONIKER}; a newer iCloud needs its digests re-recorded "
        "(docs/anisette-provenance.md)")


def package_url(update: str, revision: str) -> str:
    root = soap("GetExtendedUpdateInfo2", FE3_SECURED, f"""<GetExtendedUpdateInfo2 xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
<updateIDs><UpdateIdentity><UpdateID>{update}</UpdateID><RevisionNumber>{revision}</RevisionNumber></UpdateIdentity></updateIDs>
<infoTypes><XmlUpdateFragmentType>FileUrl</XmlUpdateFragmentType></infoTypes><deviceAttributes>{DEVICE}</deviceAttributes></GetExtendedUpdateInfo2>""")
    for location in root.iter(WU_NS + "FileLocation"):
        if location.findtext(WU_NS + "FileDigest") == PACKAGE_SHA1_B64:
            url = location.findtext(WU_NS + "Url") or ""
            if url.startswith(("http://", "https://")) and ".delivery.mp.microsoft.com/" in url:
                return url
    die(f"the Store gave no download for {MONIKER} with SHA-1 {PACKAGE_SHA1_B64}")


def download(url: str, path: str) -> tuple[str, str]:
    sha1, sha256 = hashlib.sha1(), hashlib.sha256()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as resp, open(path, "wb") as out:
        while chunk := resp.read(1 << 20):
            sha1.update(chunk)
            sha256.update(chunk)
            out.write(chunk)
    return base64.b64encode(sha1.digest()).decode(), sha256.hexdigest()


def main() -> None:
    if len(sys.argv) != 2:
        die("usage: fetch-coreadi.py OUTPUT_DIR")
    out_dir = sys.argv[1]
    pinned = digests()
    print(f"fetch-coreadi: asking the Microsoft Store for {MONIKER}", file=sys.stderr)
    update, revision = update_identity(cookie(), category_id())
    url = package_url(update, revision)
    with tempfile.TemporaryDirectory(dir=out_dir) as tmp:
        package = os.path.join(tmp, PACKAGE_NAME)
        print("fetch-coreadi: downloading the package (337 MB)", file=sys.stderr)
        sha1, sha256 = download(url, package)
        if sha1 != PACKAGE_SHA1_B64 or sha256 != pinned[PACKAGE_NAME]:
            die(f"the package does not match coreadi.sha256 (sha256 {sha256}); nothing was installed")
        with zipfile.ZipFile(package) as z, z.open(MEMBER) as src:
            data = src.read()
        os.remove(package)
        if hashlib.sha256(data).hexdigest() != pinned[DLL_NAME]:
            die(f"{MEMBER} does not match coreadi.sha256; nothing was installed")
        staged = os.path.join(tmp, DLL_NAME)
        with open(staged, "wb") as f:
            f.write(data)
        os.chmod(staged, 0o444)
        os.replace(staged, os.path.join(out_dir, DLL_NAME))
    print(f"fetch-coreadi: installed {DLL_NAME} (sha256 {pinned[DLL_NAME]})", file=sys.stderr)


if __name__ == "__main__":
    main()
