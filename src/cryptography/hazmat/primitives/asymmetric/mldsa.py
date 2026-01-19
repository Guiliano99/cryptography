# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import abc
from typing import Literal

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import _serialization
from cryptography.utils import Buffer

_MLDSAAlgorithmName = Literal["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]


def _check_supported(alg_name: _MLDSAAlgorithmName) -> None:
    """
    Check whether *alg_name* is supported by the active backend.

    Only the following names are accepted:

    - ``"ML-DSA-44"``
    - ``"ML-DSA-65"``
    - ``"ML-DSA-87"``
    """
    from cryptography.hazmat.backends.openssl.backend import backend

    # Centralize gating in backend predicates.
    if alg_name == "ML-DSA-44":
        ok = backend.mldsa44_supported()
    elif alg_name == "ML-DSA-65":
        ok = backend.mldsa65_supported()
    else:  # "ML-DSA-87"
        ok = backend.mldsa87_supported()

    if not ok:
        raise UnsupportedAlgorithm(
            f"{alg_name} is not supported by this backend.",
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
        )


class MLDSA65PublicKey(metaclass=abc.ABCMeta):
    @classmethod
    def from_public_bytes(cls, data: bytes) -> MLDSA65PublicKey:
        _check_supported("ML-DSA-65")
        return rust_openssl.mldsa.mldsa65_from_public_bytes(data)

    @abc.abstractmethod
    def public_bytes(
            self,
            encoding: _serialization.Encoding,
            format: _serialization.PublicFormat,
    ) -> bytes:
        """
        The serialized bytes of the public key.
        """

    @abc.abstractmethod
    def public_bytes_raw(self) -> bytes:
        """
        The raw bytes of the public key.
        Equivalent to public_bytes(Raw, Raw).
        """

    @abc.abstractmethod
    def verify(self, signature: Buffer, data: Buffer) -> None:
        """
        Verify the signature.
        """

    @abc.abstractmethod
    def __eq__(self, other: object) -> bool:
        """
        Checks equality.
        """

    @abc.abstractmethod
    def __copy__(self) -> MLDSA65PublicKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> MLDSA65PublicKey:
        """
        Returns a deep copy.
        """


MLDSA65PublicKey.register(rust_openssl.mldsa.MLDSA65PublicKey)


class MLDSA65PrivateKey(metaclass=abc.ABCMeta):
    @classmethod
    def generate(cls) -> MLDSA65PrivateKey:
        _check_supported("ML-DSA-65")
        return rust_openssl.mldsa.generate_mldsa65_key()

    @classmethod
    def from_seed_bytes(cls, data: Buffer) -> MLDSA65PrivateKey:
        _check_supported("ML-DSA-65")
        return rust_openssl.mldsa.mldsa65_from_seed_bytes(data)

    @abc.abstractmethod
    def public_key(self) -> MLDSA65PublicKey:
        """
        The MLDSA65PublicKey derived from the private key.
        """

    @abc.abstractmethod
    def private_bytes(
            self,
            encoding: _serialization.Encoding,
            format: _serialization.PrivateFormat,
            encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        The serialized bytes of the private key.
        """

    @abc.abstractmethod
    def private_bytes_raw(self) -> bytes:
        """
        The raw bytes of the private key seed.
        Equivalent to a 32-byte seed for deterministic reconstruction (e.g., Composite Signatures).
        """

    @abc.abstractmethod
    def sign(self, data: Buffer) -> bytes:
        """
        Signs the data.
        """

    @abc.abstractmethod
    def __copy__(self) -> MLDSA65PrivateKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> MLDSA65PrivateKey:
        """
        Returns a deep copy.
        """

MLDSA65PrivateKey.register(rust_openssl.mldsa.MLDSA65PrivateKey)
