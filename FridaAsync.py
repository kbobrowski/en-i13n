import asyncio
from frida.core import Session, Device, Script
from asyncio.futures import Future


class FridaAsync:
    def __init__(self, device: Device, session: Session, pid: int = None):
        self.device = device
        self.session = session
        self.pid = pid

    def readjs(self, path: str) -> Script:
        with open(path) as f:
            code = f.read()
        return self.session.create_script(code)

    @staticmethod
    def attach(device: Device, app_name: str):
        session: Session = device.attach(app_name)
        return FridaAsync(device, session)

    @staticmethod
    def spawn(device: Device, app_name: str):
        pid: int = device.spawn(app_name)
        session: Session = device.attach(pid)
        return FridaAsync(device, session, pid)

    def resume(self) -> None:
        self.device.resume(self.pid)

    def inject(self, js_file: str) -> Script:
        script: Script = self.readjs(js_file)
        script.load()
        return script

    def inject_callback(self, js_file: str, callback=lambda message, data: None) -> Script:
        script: Script = self.readjs(js_file)
        script.on('message', callback)
        script.load()
        return script

    async def inject_future(self, js_file: str, future: Future) -> None:
        script: Script = self.readjs(js_file)

        def callback(message, data):
            if message['type'] == 'send':
                future.set_result(message['payload'])

        script.on('message', callback)
        script.load()

    async def inject_async(self, js_file: str):
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        loop.create_task(self.inject_future(js_file, future))
        return await future
