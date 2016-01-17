# coding: utf-8


class ShellCommandError(Exception):
    """Ошибки из stderr"""


class CertificateChainNotChecked(ShellCommandError):
    """Цепочка сертификатов не проверена"""


class InvalidSignature(ShellCommandError):
    """Подпись не верна"""
