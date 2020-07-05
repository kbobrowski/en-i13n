import click
import asyncio
import frida
import os
from FridaAsync import FridaAsync


allow_script = "js/allow.js"
signature_script = "js/signature.js"
patche10_script = "js/patch_e10.js"
all_scripts = [allow_script, signature_script, patche10_script]


def scripts_exist(*args):
    if False in map(os.path.isfile, args):
        print("Error: required js file missing, compile with npm install")
        return False
    return True


def launch_app(device, package):
    app = FridaAsync.spawn(device, package)
    app.resume()
    return app


async def get_app(device, package, relaunch):
    if relaunch:
        app = launch_app(device, package)
    else:
        try:
            app = FridaAsync.attach(device, package)
        except frida.ProcessNotFoundError:
            app = launch_app(device, package)
    await asyncio.sleep(2)
    return app


def run_just_list(package):
    if not scripts_exist(allow_script):
        return
    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    gms.inject(allow_script)

    launch_app(device, package)

    input()


async def run_just_signature(package, **kwargs):
    if not scripts_exist(signature_script):
        return
    relaunch = kwargs.get("relaunch", False)

    device = frida.get_usb_device()

    app = await get_app(device, package, relaunch)

    payload = await app.inject_async(signature_script)
    print(f"[sign.py] extracted signature: {payload['signatureSha']}")


async def run_with_signature(package, signature, **kwargs):
    if not scripts_exist(allow_script):
        return
    relaunch = kwargs.get("relaunch", False)
    patche10 = kwargs.get("patche10", False)
    if patche10 and not scripts_exist(patche10_script):
        return

    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    allow = gms.inject(allow_script)
    if patche10:
        gms.inject(patche10_script)

    payload = {"packageName": package,
               "signatureSha": signature}

    print(f"[sign.py] providing payload: {payload}")
    allow.post({"type": "signature", "payload": payload})
    
    await get_app(device, package, relaunch)

    input()


async def run_auto_signature(package, **kwargs):
    if not scripts_exist(allow_script, signature_script):
        return
    relaunch = kwargs.get("relaunch", False)
    patche10 = kwargs.get("patche10", False)
    if patche10 and not scripts_exist(patche10_script):
        return

    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    allow = gms.inject(allow_script)
    if patche10:
        gms.inject(patche10_script)

    app = await get_app(device, package, relaunch)

    payload = await app.inject_async(signature_script)
    print(f"[sign.py] providing payload: {payload}")
    allow.post({"type": "signature", "payload": payload})

    input()


@click.command()
@click.option("-p", "--package", "package", help="Package name (has to be one of the allowed apps)", required=True)
@click.option("-s", "--signature", "signature", help="SHA-256 of the app signature (optional)")
@click.option("-g", "--get-signature", "just_signature", is_flag=True, help="Get SHA-256 of the app signature")
@click.option("-a", "--allowed-packages", "just_allowed", is_flag=True, help="List all allowed packages")
@click.option("-r", "--relaunch", "relaunch", is_flag=True, help="Force re-launch of the app")
@click.option("-e", "--patch-e10", "patche10", is_flag=True, help="Patch bug in Play Services causing error 10")
def main(package, signature, just_signature, just_allowed, relaunch, patche10):
    kwargs = {"relaunch": relaunch, "patche10": patche10}
    if just_signature:
        asyncio.run(run_just_signature(package, **kwargs))
    elif just_allowed:
        run_just_list(package)
    elif signature:
        asyncio.run(run_with_signature(package, signature, **kwargs))
    else:
        asyncio.run(run_auto_signature(package, **kwargs))


if __name__ == "__main__":
    main()
