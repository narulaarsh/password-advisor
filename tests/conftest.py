"""Deterministic offline fixtures. Unit tests never query real breach services or clipboard."""
import hashlib
from urllib.parse import urlparse
import pytest
import requests

@pytest.fixture(autouse=True)
def offline_services(monkeypatch):
    from modules.syntactic import clear_hibp_cache
    import pyperclip
    clipboard={'text':''}
    monkeypatch.setattr(pyperclip,'copy',lambda value:clipboard.update(text=value))
    monkeypatch.setattr(pyperclip,'paste',lambda:clipboard['text'])
    import vault.clipboard
    monkeypatch.setattr(vault.clipboard,'_mac_concealed_copy',lambda text:False)  # never touch the real pasteboard
    clear_hibp_cache()
    known={'password':4000000,'123456':5000000,'password123':2000000,'password123!':1000000}
    original_get=requests.get
    def deny_send(*args, **kwargs):
        raise AssertionError("Unexpected network request in unit tests")
    monkeypatch.setattr(requests.Session,"send",deny_send)
    def get(url, **kwargs):
        if urlparse(url).hostname != 'api.pwnedpasswords.com':
            return original_get(url, **kwargs)
        prefix=url.rsplit('/',1)[-1]
        lines=[]
        for password,count in known.items():
            digest=hashlib.sha1(password.encode()).hexdigest().upper()
            if digest[:5]==prefix:lines.append(f'{digest[5:]}:{count}')
        response=requests.Response();response.status_code=200
        response._content=('\n'.join(lines) if lines else '0'*35+':0').encode()
        return response
    monkeypatch.setattr(requests,'get',get)
    yield
    clear_hibp_cache()
