import ctypes
import ssl
import threading

from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

from api.settings import IS_TEST

thread_dict = dict()
threading_dict = []

def run_thread(target, name, args):
    global thread_dict
    if IS_TEST:
        target(*args)
        return None
    else:
        t = threading.Thread(target=thread_target, args=(target, name, *args))
        thread_dict[name] = t.getName()
        # threading.currentThread()
        # threading.Event()
        threading_dict.append(t)

        t.start()
        return t


def terminate_thread(thread):
    """Terminates a python thread from another thread.

    :param thread: a threading.Thread instance
    """
    if not thread.isAlive():
        return

    exc = ctypes.py_object(SystemExit)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(thread.ident), exc)
    if res == 0:
        raise ValueError("nonexistent thread id")
    elif res > 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


def stop_thread():
    # for item in threading_dict:
    #     print(item)
    #     item.ident
    # item.set()
    # t = threading.Thread(target=do_work)
    # t.daemon = True
    # t.start()
    for item in threading_dict:
        terminate_thread(item)


def thread_target(main_target, name, *args):
    try:
        main_target(*args)
    finally:
        if name in thread_dict.keys():
            thread_dict.pop(name)


def get_thread_status(name):
    if name in thread_dict.keys():
        return True
    else:
        return False


def get_tun_interface():
    from parser_utils.mod_resource.utils import get_map_tun_interfaces, get_pppoe_interfaces_map

    tuns = get_map_tun_interfaces()
    pppoe_map = get_pppoe_interfaces_map()
    if pppoe_map is not None:
        tuns.update(pppoe_map)
    return tuns


def print_if_debug(msg, debug=False):
    debug = True
    if debug:
        print(msg)


FORCED_CIPHERS = (
    'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH !DHE-RSA-AES256-GCM-SHA384 !DHE-RSA-AES128-GCM-SHA256'
)


class TLSAdapter(HTTPAdapter):
    """
    A TransportAdapter that re-enables 3DES support in Requests.
    """

    def create_ssl_context(self):
        ctx = ssl.create_default_context()
        ctx = create_urllib3_context(ciphers=FORCED_CIPHERS, ssl_version=ssl.PROTOCOL_TLSv1_2)
        return ctx

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.create_ssl_context()
        return super(TLSAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs['ssl_context'] = self.create_ssl_context()
        return super(TLSAdapter, self).proxy_manager_for(*args, **kwargs)
