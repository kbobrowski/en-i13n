import click
import asyncio
import frida
from FridaAsync import FridaAsync


def launch_app(device, package):
    app = FridaAsync.spawn(device, package)
    app.resume()
    return app


def get_app(device, package, relaunch):
    if relaunch:
        return launch_app(device, package)
    try:
        return FridaAsync.attach(device, package)
    except frida.ProcessNotFoundError:
        return launch_app(device, package)


def run_just_list(package):
    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    gms.inject("allow.js")

    launch_app(device, package)

    input()


async def run_just_signature(package, **kwargs):
    relaunch = kwargs.get("relaunch", False)

    device = frida.get_usb_device()

    app = get_app(device, package, relaunch)

    payload = await app.inject_async("signature.js")
    print(f"[sign.py] extracted signature: {payload['signatureSha']}")


def run_with_signature(package, signature, **kwargs):
    relaunch = kwargs.get("relaunch", False)
    patche10 = kwargs.get("patche10", False)

    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    allow = gms.inject("allow.js")
    if patche10:
        gms.inject("patch_e10.js")

    payload = {"packageName": package,
               "signatureSha": signature}

    print(f"[sign.py] providing payload: {payload}")
    allow.post({"type": "signature", "payload": payload})
    
    get_app(device, package, relaunch)

    input()


async def run_auto_signature(package, **kwargs):
    relaunch = kwargs.get("relaunch", False)
    patche10 = kwargs.get("patche10", False)

    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    allow = gms.inject("allow.js")
    if patche10:
        gms.inject("patch_e10.js")

    app = get_app(device, package, relaunch)

    payload = await app.inject_async("signature.js")
    print(f"[sing.py] providing payload: {payload}")
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
        run_with_signature(package, signature, **kwargs)
    else:
        asyncio.run(run_auto_signature(package, **kwargs))


if __name__ == "__main__":
    main()
