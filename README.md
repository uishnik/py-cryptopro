# py-cryptopro
Обертка над утилитами cryptcp и certmgr, входящими в состав Крипто-Про CSP (для UNIX-платформ), позволяющая устанавливать и удалять сертификаты, создавать и проверять ЭЦП и т.д.

```python
from pycryptopro.utils import Certmgr, Cryptcp

certmgr = Certmgr()

# список сертификатов в хранилище My
certificates = certmgr.list(store='My', limit=100)

# установить сертификат
certmgr.inst(store='My', file='/path/to/certificate/cert.crt')

# получить сертификат по отпечатку
certmgr.get(thumbprint='8cae88bbfd404a7a53630864f9033606e1dc45e2', store='My')

# удалить сертификат
certmgr.delete(thumbprint='8cae88bbfd404a7a53630864f9033606e1dc45e2', store='My')

cryptcp = Cryptcp()

# проверить отделенную подпись файла file.txt используя сертификат, хранящийся в подписи signature.sgn
# подпись находится в каталоге /path/to/directory/with/signature
cryptcp.verify(
    sgn_dir='/path/to/directory/with/signature',
    cert_filename='/path/to/directory/with/signature/file.txt.sgn',
    filename='/path/to/file.txt')
```
