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


async def run_just_signature(package, relaunch):
    device = frida.get_usb_device()

    app = get_app(device, package, relaunch)

    payload = await app.inject_async("signature.js")
    print(f"[sign.py] extracted signature: {payload['signatureSha']}")


def run_with_signature(package, signature, relaunch):
    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    allow = gms.inject("allow.js")

    payload = {"packageName": package,
               "signatureSha": signature}

    print(f"[sign.py] providing payload: {payload}")
    allow.post({"type": "signature", "payload": payload})
    
    get_app(device, package, relaunch)

    input()


async def run_auto_signature(package, relaunch):
    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    allow = gms.inject("allow.js")

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
def main(package, signature, just_signature, just_allowed, relaunch):
    if just_signature:
        asyncio.run(run_just_signature(package, relaunch))
    elif just_allowed:
        run_just_list(package)
    elif signature:
        run_with_signature(package, signature, relaunch)
    else:
        asyncio.run(run_auto_signature(package, relaunch))


if __name__ == "__main__":
    main()
