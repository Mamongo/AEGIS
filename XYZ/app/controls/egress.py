import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import quote, urlsplit
from app.models import finding


class EgressDenied(ValueError):
    """A destination cannot be used under the current egress policy."""


@dataclass(frozen=True)
class Address:
    family: int
    ip: str


@dataclass(frozen=True)
class Destination:
    scheme: str
    host: str
    port: int
    target: str
    addresses: tuple[Address, ...]


def _domains(values):
    return {value.lower().rstrip(".") for value in values}


def validate_destination(url, policy, domains=None, *, resolve=False, resolver=None):
    """Validate every DNS answer once; adapters connect only to returned addresses."""
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
            raise EgressDenied("Unsupported scheme, missing host, or URL credentials")
        if parsed.port not in {None, 80, 443} or "\\" in url or "%" in host:
            raise EgressDenied("Unsupported port or ambiguous URL encoding")
        if any(ord(character) < 33 or ord(character) == 127 for character in url):
            raise EgressDenied("Whitespace or control characters in destination")
        host = host.encode("idna").decode("ascii")
    except (ValueError, UnicodeError) as error:
        if isinstance(error, EgressDenied):
            raise
        raise EgressDenied("Malformed destination URL") from None
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        raise EgressDenied("Loopback destination is prohibited")
    if host not in _domains(policy.egress.allow_domains):
        raise EgressDenied("Destination is not allowlisted")
    if domains and host not in _domains(domains):
        raise EgressDenied("Destination is outside this tool's domain grant")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        literal = ipaddress.ip_address(host)
        addresses = [Address(socket.AF_INET6 if literal.version == 6 else socket.AF_INET, str(literal))]
    except ValueError:
        addresses = []
        if host.replace(".", "").isdigit() or host.startswith("0x"):
            raise EgressDenied("Ambiguous numeric IP notation is prohibited")
        if resolve:
            lookup = resolver or socket.getaddrinfo
            try:
                answers = lookup(host, port, type=socket.SOCK_STREAM)
                for family, _, _, _, sockaddr in answers:
                    if family not in {socket.AF_INET, socket.AF_INET6}:
                        raise EgressDenied("Unsupported resolved address family")
                    address = Address(family, str(ipaddress.ip_address(sockaddr[0])))
                    if (family == socket.AF_INET) != (ipaddress.ip_address(address.ip).version == 4):
                        raise EgressDenied("Resolved address family does not match address")
                    if address not in addresses:
                        addresses.append(address)
            except (OSError, ValueError, TypeError, IndexError):
                raise EgressDenied("Destination could not be safely resolved") from None
            if not addresses:
                raise EgressDenied("Destination could not be safely resolved")
    for resolved in addresses:
        address = ipaddress.ip_address(resolved.ip)
        address = getattr(address, "ipv4_mapped", None) or address
        if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast or address.is_reserved:
            raise EgressDenied("Loopback, metadata, link-local, or special-use address prohibited")
        if not address.is_global and host not in _domains(policy.egress.allow_private_domains):
            raise EgressDenied("Private network destination is not explicitly permitted")
    target = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if parsed.query:
        target += "?" + quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
    return Destination(parsed.scheme, host, port, target, tuple(addresses))


def inspect(url, policy, domains=None, resolve=False):
    try:
        validate_destination(url, policy, domains, resolve=resolve)
    except EgressDenied as error:
        return [finding("egress", "SEC-EGRESS-001", str(error), severity="critical")]
    return []
