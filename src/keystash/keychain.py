"""macOS credential protection for keystash.

Two layers, pure ctypes (no third-party dependencies):

1. The master password is stored as a plain login-keychain generic-password
   item (process-ACL protected, same trust model as `gh`, `ssh` and git).
2. Every read is gated by a LocalAuthentication prompt (Touch ID / Apple Watch
   / device passcode) *before* the keychain is touched.

Touch-ID-ACL'd keychain items would be marginally stronger, but macOS refuses
to create them from unsigned CLI processes (errSecMissingEntitlement), so the
LocalAuthentication gate is the equivalent UX available to a pip-installed
tool. On non-macOS platforms, or when no lock-screen auth is configured, the
gate is skipped and the keychain behaves like any system credential helper.
"""

from __future__ import annotations

import ctypes
import sys
import time
from typing import Optional

AVAILABLE = sys.platform == "darwin"
DEFAULT_TIMEOUT = 120.0

STORE_BIOMETRIC = "Touch ID"
STORE_PLAIN = "keychain"


class KeychainError(Exception):
    """Security framework returned an unexpected status."""

    def __init__(self, status: int, what: str = "operation") -> None:
        super().__init__(f"keychain {what} failed (status {status})")
        self.status = status


if AVAILABLE:  # pragma: no branch
    _vp = ctypes.c_void_p

    _cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    _sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    _la = ctypes.CDLL("/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication")
    _objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")

    _kCFStringEncodingUTF8 = 0x08000100
    _errSecSuccess = 0
    _errSecDuplicateItem = -25299
    _errSecItemNotFound = -25300

    # --- CoreFoundation -------------------------------------------------
    _cf.CFStringCreateWithCString.restype = _vp
    _cf.CFStringCreateWithCString.argtypes = [_vp, ctypes.c_char_p, ctypes.c_uint32]
    _cf.CFDataCreate.restype = _vp
    _cf.CFDataCreate.argtypes = [_vp, ctypes.c_char_p, ctypes.c_long]
    _cf.CFDataGetLength.restype = ctypes.c_long
    _cf.CFDataGetLength.argtypes = [_vp]
    _cf.CFDataGetBytePtr.restype = _vp
    _cf.CFDataGetBytePtr.argtypes = [_vp]
    _cf.CFRelease.argtypes = [_vp]
    _cf.CFRunLoopRunInMode.restype = ctypes.c_int32
    _cf.CFRunLoopRunInMode.argtypes = [_vp, ctypes.c_double, ctypes.c_bool]

    class _CFDictCallbacks(ctypes.Structure):
        _fields_ = [
            ("version", ctypes.c_long),
            ("retain", _vp),
            ("release", _vp),
            ("copyDescription", _vp),
            ("equal", _vp),
            ("hash", _vp),
        ]

    # Apple's own callback tables — hand-rolling these invites subtle breakage.
    _KEY_CB = _CFDictCallbacks.in_dll(_cf, "kCFTypeDictionaryKeyCallBacks")
    _VAL_CB = _CFDictCallbacks.in_dll(_cf, "kCFTypeDictionaryValueCallBacks")

    _cf.CFDictionaryCreateMutable.restype = _vp
    _cf.CFDictionaryCreateMutable.argtypes = [_vp, ctypes.c_long, _vp, _vp]
    _cf.CFDictionarySetValue.argtypes = [_vp, _vp, _vp]

    # --- Security ---------------------------------------------------------
    _sec.SecItemAdd.restype = ctypes.c_int
    _sec.SecItemAdd.argtypes = [_vp, _vp]
    _sec.SecItemCopyMatching.restype = ctypes.c_int
    _sec.SecItemCopyMatching.argtypes = [_vp, ctypes.POINTER(_vp)]
    _sec.SecItemDelete.restype = ctypes.c_int
    _sec.SecItemDelete.argtypes = [_vp]

    def _ksec(name: str) -> _vp:
        return _vp(ctypes.c_void_p.in_dll(_sec, name).value)
    _kSecClass = _ksec("kSecClass")
    _kSecClassGenericPassword = _ksec("kSecClassGenericPassword")
    _kSecAttrService = _ksec("kSecAttrService")
    _kSecAttrAccount = _ksec("kSecAttrAccount")
    _kSecAttrAccessible = _ksec("kSecAttrAccessible")
    _kSecAttrAccessibleWhenUnlockedThisDeviceOnly = _ksec(
        "kSecAttrAccessibleWhenUnlockedThisDeviceOnly"
    )
    _kSecValueData = _ksec("kSecValueData")
    _kSecReturnData = _ksec("kSecReturnData")
    _kSecMatchLimit = _ksec("kSecMatchLimit")
    _kSecMatchLimitOne = _ksec("kSecMatchLimitOne")
    _kCFBooleanTrue = _vp(ctypes.c_void_p.in_dll(_cf, "kCFBooleanTrue").value)

    def _cfstring(text: str) -> _vp:
        ref = _cf.CFStringCreateWithCString(None, text.encode("utf-8"), _kCFStringEncodingUTF8)
        if not ref:
            raise KeychainError(-65535, "CFStringCreateWithCString")
        return ref

    def _cfdict() -> _vp:
        return _cf.CFDictionaryCreateMutable(None, 0, ctypes.byref(_KEY_CB), ctypes.byref(_VAL_CB))

    def _set(d: _vp, key: _vp, value: _vp) -> None:
        _cf.CFDictionarySetValue(d, key, value)

    # --- LocalAuthentication (ObjC) ---------------------------------------
    # objc_msgSend is bound directly and re-typed before each call — wrapping
    # the raw _FuncPtr in CFUNCTYPE() produces a broken trampoline that
    # segfaults on arm64 (verified empirically).
    _objc.objc_getClass.restype = _vp
    _objc.objc_getClass.argtypes = [ctypes.c_char_p]
    _objc.sel_registerName.restype = _vp
    _objc.sel_registerName.argtypes = [ctypes.c_char_p]

    def _msg(restype, *argtypes):
        """Bind objc_msgSend for one call signature (single-threaded CLI)."""
        fn = _objc.objc_msgSend
        fn.restype = restype
        fn.argtypes = [_vp, _vp, *argtypes]
        return fn

    _LA_CTX = _objc.objc_getClass(b"LAContext")
    _sel_new = _objc.sel_registerName(b"new")
    _sel_can = _objc.sel_registerName(b"canEvaluatePolicy:error:")
    _sel_eval = _objc.sel_registerName(b"evaluatePolicy:localizedReason:reply:")
    _sel_invalidate = _objc.sel_registerName(b"invalidate")
    _LAPolicyDeviceOwnerAuthentication = 2  # biometry with passcode fallback

    class _BlockDescriptor(ctypes.Structure):
        _fields_ = [("reserved", ctypes.c_ulong), ("size", ctypes.c_ulong)]

    class _Block(ctypes.Structure):
        _fields_ = [
            ("isa", _vp),
            ("flags", ctypes.c_int),
            ("reserved", ctypes.c_int),
            ("invoke", _vp),
            ("descriptor", ctypes.POINTER(_BlockDescriptor)),
        ]

    _NSConcreteGlobalBlock = _vp(
        ctypes.c_void_p.in_dll(_objc, "_NSConcreteGlobalBlock").value
    )
    _kCFRunLoopDefaultMode = _vp(ctypes.c_void_p.in_dll(_cf, "kCFRunLoopDefaultMode").value)

    _BLOCK_IS_GLOBAL = 1 << 28

else:  # non-macOS: sentinels so tests can fake AVAILABLE without the ObjC runtime
    _LA_CTX = _sel_new = _sel_can = _sel_eval = _sel_invalidate = None
    _msg = None


def store(service: str, account: str, secret: str) -> str:
    """Store the secret in the login keychain (replaces any previous item).

    Returns the protection label for display purposes.
    """
    if not AVAILABLE:
        raise KeychainError(-1, "unsupported platform")
    d = _cfdict()
    _set(d, _kSecClass, _kSecClassGenericPassword)
    _set(d, _kSecAttrService, _cfstring(service))
    _set(d, _kSecAttrAccount, _cfstring(account))
    _set(d, _kSecValueData, _cf.CFDataCreate(None, secret.encode("utf-8"), len(secret)))
    _set(d, _kSecAttrAccessible, _kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
    status = _sec.SecItemAdd(d, None)
    if status == _errSecDuplicateItem:
        _sec.SecItemDelete(d)
        status = _sec.SecItemAdd(d, None)
    if status != _errSecSuccess:
        raise KeychainError(status, "SecItemAdd")
    return STORE_BIOMETRIC if biometric_available() else STORE_PLAIN


def retrieve(service: str, account: str) -> Optional[str]:
    """Read the stored secret, gated behind a LocalAuthentication prompt.

    Returns None when nothing is stored; raises KeychainError when the gate
    is dismissed or the read fails.
    """
    if not AVAILABLE:
        raise KeychainError(-1, "unsupported platform")
    if biometric_available():
        if not biometric_gate():
            raise KeychainError(-128, "authentication declined")
    d = _cfdict()
    _set(d, _kSecClass, _kSecClassGenericPassword)
    _set(d, _kSecAttrService, _cfstring(service))
    _set(d, _kSecAttrAccount, _cfstring(account))
    _set(d, _kSecMatchLimit, _ksec("kSecMatchLimitOne"))
    _set(d, _kSecReturnData, _kCFBooleanTrue)
    result = _vp()
    status = _sec.SecItemCopyMatching(d, ctypes.byref(result))
    if status == _errSecItemNotFound:
        return None
    if status != _errSecSuccess:
        raise KeychainError(status, "SecItemCopyMatching")
    try:
        length = _cf.CFDataGetLength(result)
        ptr = _cf.CFDataGetBytePtr(result)
        return ctypes.string_at(ptr, length).decode("utf-8")
    finally:
        _cf.CFRelease(result)


def delete(service: str, account: str) -> bool:
    """Remove the stored item; True when it existed."""
    if not AVAILABLE:
        raise KeychainError(-1, "unsupported platform")
    d = _cfdict()
    _set(d, _kSecClass, _kSecClassGenericPassword)
    _set(d, _kSecAttrService, _cfstring(service))
    _set(d, _kSecAttrAccount, _cfstring(account))
    return _sec.SecItemDelete(d) == _errSecSuccess


def biometric_available() -> bool:
    """True when the Mac has a lock-screen auth method Touch ID can use."""
    if not AVAILABLE or _LA_CTX is None:
        return False
    ctx = _msg(_vp)(_LA_CTX, _sel_new)
    if not ctx:
        return False
    try:
        return _msg(ctypes.c_bool, ctypes.c_long, ctypes.POINTER(_vp))(
            ctx, _sel_can, _LAPolicyDeviceOwnerAuthentication, None
        )
    finally:
        _msg(_vp)(ctx, _sel_invalidate)


def biometric_gate(reason: str = "keystash 需要验证才能访问密钥库", timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Show the Touch ID / passcode prompt and block until resolved.

    Returns True on success. When no auth method is configured (headless,
    CI), returns True without prompting — matching system credential helpers.
    """
    if not AVAILABLE or _LA_CTX is None:
        return False
    ctx = _msg(_vp)(_LA_CTX, _sel_new)
    if not ctx:
        return False
    if not _msg(ctypes.c_bool, ctypes.c_long, ctypes.POINTER(_vp))(
        ctx, _sel_can, _LAPolicyDeviceOwnerAuthentication, None
    ):
        _msg(_vp)(ctx, _sel_invalidate)
        return True  # nothing to gate with; behave like a credential helper

    state = {"done": False, "ok": False}

    @ctypes.CFUNCTYPE(None, _vp, ctypes.c_bool, _vp)
    def _reply(_block: _vp, success: ctypes.c_bool, _error: _vp) -> None:
        state["ok"] = bool(success)
        state["done"] = True

    desc = _BlockDescriptor(0, ctypes.sizeof(_Block))
    block = _Block(_NSConcreteGlobalBlock, _BLOCK_IS_GLOBAL, 0,
                   ctypes.cast(_reply, _vp), ctypes.pointer(desc))
    reason_ref = _cfstring(reason)
    _msg(None, ctypes.c_long, _vp, _vp)(
        ctx, _sel_eval, _LAPolicyDeviceOwnerAuthentication, reason_ref,
        ctypes.cast(ctypes.byref(block), _vp),
    )
    deadline = time.monotonic() + timeout
    try:
        while not state["done"]:
            if time.monotonic() > deadline:
                _msg(_vp)(ctx, _sel_invalidate)
                return False
            _cf.CFRunLoopRunInMode(_kCFRunLoopDefaultMode, 0.05, False)
        return state["ok"]
    finally:
        _msg(_vp)(ctx, _sel_invalidate)
