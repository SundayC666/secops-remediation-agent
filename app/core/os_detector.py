"""
OS Detection from HTTP User-Agent Header
Parses the User-Agent string to identify the client's operating system
"""

import re
from typing import Optional, List
from dataclasses import dataclass


@dataclass
class BrowserInfo:
    """Detected browser information"""
    name: str                   # Browser name (Chrome, Firefox, Safari, Edge)
    version: Optional[str]      # Browser version
    engine: Optional[str]       # Rendering engine (Blink, Gecko, WebKit)


@dataclass
class OSInfo:
    """Detected OS information"""
    raw: str                    # Original User-Agent string
    family: str                 # OS family (Windows, macOS, Linux, iOS, Android)
    version: Optional[str]      # OS version if detected
    normalized: str             # Human-readable name for display
    tags: List[str]             # Tags for CVE matching (e.g., ['windows', 'windows_10'])
    browser: Optional[BrowserInfo] = None  # Detected browser info


def detect_os_from_user_agent(user_agent: str) -> OSInfo:
    """
    Parse User-Agent header to detect operating system

    Args:
        user_agent: The User-Agent header string from HTTP request

    Returns:
        OSInfo with detected OS details and tags for CVE filtering
    """
    if not user_agent:
        return OSInfo(
            raw="",
            family="Unknown",
            version=None,
            normalized="Unknown System",
            tags=[]
        )

    ua = user_agent.lower()

    # Detect browser first (will be added to all OS results)
    browser = detect_browser(user_agent)

    # Windows detection
    if "windows" in ua:
        version = None
        normalized = "Windows"
        tags = ["windows"]

        if "windows nt 10.0" in ua:
            # Windows 10 or 11 - check for Windows 11 indicators
            if "windows nt 10.0; win64" in ua and _is_windows_11(user_agent):
                version = "11"
                normalized = "Windows 11"
                tags.extend(["windows_11", "windows_10_11"])
            else:
                version = "10"
                normalized = "Windows 10"
                tags.extend(["windows_10", "windows_10_11"])
        elif "windows nt 6.3" in ua:
            version = "8.1"
            normalized = "Windows 8.1"
            tags.append("windows_8")
        elif "windows nt 6.2" in ua:
            version = "8"
            normalized = "Windows 8"
            tags.append("windows_8")
        elif "windows nt 6.1" in ua:
            version = "7"
            normalized = "Windows 7"
            tags.append("windows_7")
        elif "windows nt 6.0" in ua:
            version = "Vista"
            normalized = "Windows Vista"
            tags.append("windows_vista")
        elif "windows nt 5.1" in ua or "windows xp" in ua:
            version = "XP"
            normalized = "Windows XP"
            tags.append("windows_xp")
        elif "windows server" in ua:
            version = "Server"
            normalized = "Windows Server"
            tags.append("windows_server")

        return OSInfo(
            raw=user_agent,
            family="Windows",
            version=version,
            normalized=normalized,
            tags=tags,
            browser=browser
        )

    # iOS detection - Must be checked BEFORE macOS because iOS User-Agent contains "like Mac OS X"
    if "iphone" in ua or "ipad" in ua or "ipod" in ua:
        device = "iPhone" if "iphone" in ua else ("iPad" if "ipad" in ua else "iPod")
        version = None
        tags = ["ios", "apple_mobile"]

        match = re.search(r"os (\d+)[_.](\d+)", ua)
        if match:
            version = f"{match.group(1)}.{match.group(2)}"
            tags.append(f"ios_{match.group(1)}")

        return OSInfo(
            raw=user_agent,
            family="iOS",
            version=version,
            normalized=f"iOS ({device})" if version is None else f"iOS {version} ({device})",
            tags=tags,
            browser=browser
        )

    # macOS detection
    if "mac os x" in ua or "macos" in ua:
        version = None
        normalized = "macOS"
        tags = ["macos", "darwin", "unix"]

        # Try to extract version (e.g., "Mac OS X 10_15_7" or "Mac OS X 14_0")
        match = re.search(r"mac os x[_ ](\d+)[_.](\d+)", ua)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))

            if major >= 11 or (major == 10 and minor >= 16):
                # macOS 11+ uses different versioning
                if major == 10 and minor >= 16:
                    version = "11+"
                    normalized = "macOS Big Sur+"
                else:
                    version = str(major)
                    version_names = {
                        11: "Big Sur",
                        12: "Monterey",
                        13: "Ventura",
                        14: "Sonoma",
                        15: "Sequoia",
                        26: "Tahoe",
                    }
                    name = version_names.get(major, "")
                    normalized = f"macOS {major} {name}".strip()
                tags.append(f"macos_{major}")
            elif major == 10 and minor == 15:
                # IMPORTANT: macOS 10.15 (Catalina) in User-Agent is often a LIE!
                # Since macOS 11 Big Sur (2020), browsers freeze the reported version at 10_15_7
                # for compatibility, even when running on newer macOS versions.
                # We'll assume the user is running the latest macOS (Tahoe 26)
                version = "26"
                normalized = "macOS 26 Tahoe"
                tags.append("macos_26")
            else:
                version = f"10.{minor}"
                normalized = f"macOS 10.{minor}"
                tags.append(f"macos_10_{minor}")

        return OSInfo(
            raw=user_agent,
            family="macOS",
            version=version,
            normalized=normalized,
            tags=tags,
            browser=browser
        )

    # Android detection
    if "android" in ua:
        version = None
        tags = ["android", "linux", "mobile"]

        match = re.search(r"android[_ ](\d+)(?:\.(\d+))?", ua)
        if match:
            version = match.group(1)
            if match.group(2):
                version += f".{match.group(2)}"
            tags.append(f"android_{match.group(1)}")

        return OSInfo(
            raw=user_agent,
            family="Android",
            version=version,
            normalized=f"Android {version}" if version else "Android",
            tags=tags,
            browser=browser
        )

    # Linux detection
    if "linux" in ua:
        tags = ["linux", "unix"]
        distro = None

        if "ubuntu" in ua:
            distro = "Ubuntu"
            tags.append("ubuntu")
        elif "debian" in ua:
            distro = "Debian"
            tags.append("debian")
        elif "fedora" in ua:
            distro = "Fedora"
            tags.append("fedora")
        elif "centos" in ua:
            distro = "CentOS"
            tags.append("centos")
        elif "red hat" in ua or "rhel" in ua:
            distro = "Red Hat"
            tags.append("rhel")
        elif "arch" in ua:
            distro = "Arch Linux"
            tags.append("arch")

        return OSInfo(
            raw=user_agent,
            family="Linux",
            version=None,
            normalized=distro if distro else "Linux",
            tags=tags,
            browser=browser
        )

    # ChromeOS detection
    if "cros" in ua:
        return OSInfo(
            raw=user_agent,
            family="ChromeOS",
            version=None,
            normalized="ChromeOS",
            tags=["chromeos", "linux"],
            browser=browser
        )

    # FreeBSD detection
    if "freebsd" in ua:
        return OSInfo(
            raw=user_agent,
            family="FreeBSD",
            version=None,
            normalized="FreeBSD",
            tags=["freebsd", "bsd", "unix"],
            browser=browser
        )

    # Unknown OS
    return OSInfo(
        raw=user_agent,
        family="Unknown",
        version=None,
        normalized="Unknown System",
        tags=[],
        browser=browser
    )


def _is_windows_11(user_agent: str) -> bool:
    """
    Attempt to detect Windows 11 from User-Agent
    Note: This is not always reliable as Windows 11 often reports as Windows 10
    """
    # Windows 11 sometimes includes platform version hint
    # or specific build numbers >= 22000
    if "windows nt 10.0" in user_agent.lower():
        # Check for Chrome's Sec-CH-UA hints if available
        # For now, we can't reliably distinguish without client hints
        # Return False to default to Windows 10
        return False
    return False


def detect_browser(user_agent: str) -> Optional[BrowserInfo]:
    """
    Detect browser from User-Agent string
    """
    if not user_agent:
        return None

    ua = user_agent.lower()

    # Edge (must check before Chrome as Edge includes Chrome in UA)
    if "edg/" in ua or "edge/" in ua:
        match = re.search(r'edg[e]?/(\d+)', ua)
        version = match.group(1) if match else None
        return BrowserInfo(name="Edge", version=version, engine="Blink")

    # Chrome (must check before Safari)
    if "chrome/" in ua and "chromium" not in ua:
        match = re.search(r'chrome/(\d+)', ua)
        version = match.group(1) if match else None
        return BrowserInfo(name="Chrome", version=version, engine="Blink")

    # Firefox
    if "firefox/" in ua:
        match = re.search(r'firefox/(\d+)', ua)
        version = match.group(1) if match else None
        return BrowserInfo(name="Firefox", version=version, engine="Gecko")

    # Safari (check after Chrome/Edge)
    if "safari/" in ua and "chrome" not in ua:
        match = re.search(r'version/(\d+)', ua)
        version = match.group(1) if match else None
        return BrowserInfo(name="Safari", version=version, engine="WebKit")

    # Opera
    if "opr/" in ua or "opera" in ua:
        match = re.search(r'(?:opr|opera)/(\d+)', ua)
        version = match.group(1) if match else None
        return BrowserInfo(name="Opera", version=version, engine="Blink")

    # Brave
    if "brave" in ua:
        return BrowserInfo(name="Brave", version=None, engine="Blink")

    # Vivaldi
    if "vivaldi" in ua:
        match = re.search(r'vivaldi/(\d+)', ua)
        version = match.group(1) if match else None
        return BrowserInfo(name="Vivaldi", version=version, engine="Blink")

    return None


# Popular OS options for quick selection
QUICK_OS_OPTIONS = [
    {"id": "macos_26", "label": "macOS 26 Tahoe", "query": "macOS 26 Tahoe vulnerabilities"},
    {"id": "macos_15", "label": "macOS 15 Sequoia", "query": "macOS 15 Sequoia vulnerabilities"},
    {"id": "windows_11", "label": "Windows 11", "query": "Windows 11 vulnerabilities"},
    {"id": "windows_10", "label": "Windows 10", "query": "Windows 10 vulnerabilities"},
    {"id": "ubuntu_24", "label": "Ubuntu 24.04", "query": "Ubuntu 24.04 vulnerabilities"},
    {"id": "ubuntu_22", "label": "Ubuntu 22.04", "query": "Ubuntu 22.04 vulnerabilities"},
    {"id": "ios_18", "label": "iOS 18", "query": "iOS 18 vulnerabilities"},
    {"id": "ios_17", "label": "iOS 17", "query": "iOS 17 vulnerabilities"},
    {"id": "android_15", "label": "Android 15", "query": "Android 15 vulnerabilities"},
    {"id": "android_14", "label": "Android 14", "query": "Android 14 vulnerabilities"},
    {"id": "chrome", "label": "Chrome Browser", "query": "Google Chrome vulnerabilities"},
    {"id": "firefox", "label": "Firefox Browser", "query": "Mozilla Firefox vulnerabilities"},
]
