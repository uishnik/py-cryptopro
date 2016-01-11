# coding: utf-8

from subprocess import Popen, PIPE
import re


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

    def __init__(self, binary='/opt/cprocsp/bin/amd64/certmgr'):
        self.binary = binary

    def list(self, **kwargs):
        """
        Возвращает список сертификатов
        """
        stdout, stderr = self.run_command('-list', **kwargs)
        if stderr:
            return [], stderr
        return self._parse(stdout), None

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

    def _parse(self, text):
        """
        Преобразует текстовые данные в словарь
        """
        res = []
        sep = re.compile(r'\d-{7}')

        for item in sep.split(text)[1:]:
            cert_data = {}
            for line in item.split('\n'):
                if line == '':
                    continue

                if line.startswith('=='):
                    break

                key, val = self._get_key_and_val(line)
                cert_data[key] = val

            res.append(cert_data)

        return res

    @staticmethod
    def _get_key_and_val(line):
        """
        Преобразует строку в пару ключ:значение
        """
        key, val = line.split(':', 1)
        key = key.strip().lower().replace(' ', '_')
        val = val.strip()

        if key in ('sha1_hash', 'serial'):
            val = val.replace('0x', '')

        return key, val


class Cryptcp(ShellCommand):
    """
    Обертка над утилитой cryptcp, входящей в состав Крипто-Про CSP (для UNIX-платформ).
    """

    def __init__(self, binary='/opt/cprocsp/bin/amd64/cryptcp'):
        self.binary = binary

    def vsignf(self, filename, dir=None):
        """
        Проверяет электронную подпись
        """


if __name__ == '__main__':
    certmgr = Certmgr()
    # stdout, stderr = certmgr.delete(thumbprint='5B0345AE6874A205DC78333928FF3F1189B3BFA8'.lower(), store='root')
    r, e = certmgr.list(store='root')
    # stdout, stderr = certmgr.inst(file='/home/uishnik/root_cert.cer', store='root')
    import json
    print json.dumps(r, indent=4, ensure_ascii=False)
    print e
