import re
from typing import Iterable
from dataclasses import dataclass


def split(s):
    for x, y in re.findall(r'(\d*)(\D*)', s):
        yield '', int(x or '0')
        yield y, 0


def natural_keys(c):
    return tuple(split(c))


def human_sorted(iterable: Iterable):
    return sorted(iterable, key=natural_keys)


@dataclass(frozen=True)
class IPAddressInfo:
    """A unified way to represent IP address information and permissions"""
    id: int
    address: str
    tenant_id: int = None
    tenant_name: str = ""
    tenant_permissions: str = ""
    tenant_permissions_ro: str = ""
    
    def __hash__(self):
        return hash((self.id, self.address))
    
    def __eq__(self, other):
        return self.id == other.id and self.address == other.address


@dataclass(frozen=True)
class PrefixInfo:
    """Represents prefix information and its permissions"""
    id: int
    prefix: str
    tenant_id: int = None
    tenant_name: str = ""
    tenant_permissions: str = ""
    tenant_permissions_ro: str = ""