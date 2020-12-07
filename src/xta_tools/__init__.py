# (c) FFRI Security, Inc., 2020 / Koh M. Nakagawa: FFRI Security, Inc.

__version__ = "0.1.0"

from .xta_cache import AddressPair, XtaCache
from .xta_manip import RelocInfo, XtaCacheManipulator

__all__ = ["XtaCache", "XtaCacheManipulator", "AddressPair"]
