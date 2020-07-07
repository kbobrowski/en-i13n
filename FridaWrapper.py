from frida.core import Session, Device, Script


class FridaWrapper:
    def __init__(self, device: Device, session: Session):
        self.device = device
        self.session = session

    @staticmethod
    def attach(device: Device, app_name: str):
        session: Session = device.attach(app_name)
        return FridaWrapper(device, session)

    def readjs(self, path: str) -> Script:
        with open(path) as f:
            code = f.read()
        return self.session.create_script(code)

    def inject(self, js_file: str) -> Script:
        script: Script = self.readjs(js_file)
        script.load()
        return script
