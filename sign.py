import click
import asyncio
import frida
from FridaAsync import FridaAsync


def run_just_list(package):
    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    gms.inject("allow.js")

    app = FridaAsync.spawn(device, package)
    app.resume()

    input()


async def run_just_signature(package):
    device = frida.get_usb_device()

    app = FridaAsync.spawn(device, package)
    app.resume()

    payload = await app.inject_async("signature.js")
    print(f"[sign.py] extracted signature: {payload['signatureSha']}")


def run_just_patch(package, signature):
    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    allow = gms.inject("allow.js")

    payload = {"packageName": package,
               "signatureSha": signature}

    print(f"[sign.py] providing payload: {payload}")
    allow.post({"type": "signature", "payload": payload})

    input()


def run_with_signature(package, signature):
    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    allow = gms.inject("allow.js")

    payload = {"packageName": package,
               "signatureSha": signature}

    print(f"[sign.py] providing payload: {payload}")
    allow.post({"type": "signature", "payload": payload})

    app = FridaAsync.spawn(device, package)
    app.resume()

    input()


async def run_auto_signature(package):
    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    allow = gms.inject("allow.js")

    app = FridaAsync.spawn(device, package)
    app.resume()

    payload = await app.inject_async("signature.js")
    print(f"[sing.py] providing payload: {payload}")
    allow.post({"type": "signature", "payload": payload})

    input()


@click.command()
@click.option("-p", "--package", "package", help="Package name (has to be one of the allowed apps)", required=True)
@click.option("-s", "--signature", "signature", help="SHA-256 of the app signature (optional)")
@click.option("-g", "--get-signature", "just_signature", is_flag=True, help="Get SHA-256 of the app signature")
@click.option("-a", "--allowed-packages", "just_allowed", is_flag=True, help="List all allowed packages")
@click.option("-j", "--just-patch", "just_patch", is_flag=True, help="Just apply patch to GMS, without launching the app (requires -s)")
def main(package, signature, just_signature, just_allowed, just_patch):
    if just_patch:
        if not signature:
            click.echo(f"\nError: just patch option requires signature. Get it with:\n\npipenv run python sign.py -p {package} -g")
        else:
            run_just_patch(package, signature)
    elif just_signature:
        asyncio.run(run_just_signature(package))
    elif just_allowed:
        run_just_list(package)
    elif signature:
        run_with_signature(package, signature)
    else:
        asyncio.run(run_auto_signature(package))


if __name__ == "__main__":
    main()
