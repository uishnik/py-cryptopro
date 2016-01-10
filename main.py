# coding: utf-8

from subprocess import Popen, PIPE


class ShellCommand(object):
    """
    Класс, содержащий метод исполнения shell команд
    """

    binary = None

    def run_command(self, command, **kwargs):
        """
        Выполняет комманду shell
        """
        params = ' '.join(['-%s %s' % (k, v) for k, v in kwargs.items() if v is not None])
        cmd = ' '.join([self.binary, command, params])
        proc = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
        content, stderr = proc.communicate()

        return content, stderr


class Certmgr(ShellCommand):
    """
    Обертка над утилитой certmgr, входящей в состав Крипто-Про CSP (для UNIX-платформ).
    """

    binary = '/opt/cprocsp/bin/amd64/certmgr'

    def list(self, **kwargs):
        """
        Возвращает список сертификатов
        """
        return self.run_command('-list', **kwargs)

    def inst(self, **kwargs):
        """
        Устанавливает сертификат
        """
        return self.run_command('-inst', **kwargs)

    def delete(self, **kwargs):
        """
        Удаляет сертификат
        """
        return self.run_command('-delete', **kwargs)

    def cert_info(self, thumbprint):
        """
        Возвращает информацию о сертификате
        """


class Cryptcp(ShellCommand):
    """
    Обертка над утилитой cryptcp, входящей в состав Крипто-Про CSP (для UNIX-платформ).
    """

    binary = '/opt/cprocsp/bin/amd64/cryptcp'

    def vsignf(self, filename, dir=None):
        """
        Проверяет электронную подпись
        """


if __name__ == '__main__':
    certmgr = Certmgr()
    # stdout, stderr = certmgr.delete(thumbprint='5B0345AE6874A205DC78333928FF3F1189B3BFA8'.lower(), store='root')
    stdout, stderr = certmgr.list(store='My')
    # stdout, stderr = certmgr.inst(file='/home/uishnik/root_cert.cer', store='root')
    print stdout
    print stderr
