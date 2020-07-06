import click
import asyncio
import frida
import os
from FridaAsync import FridaAsync


allow_script = "js/allow.js"
signature_script = "js/signature.js"
patche10_script = "js/patch_e10.js"
all_scripts = [allow_script, signature_script, patche10_script]

this_name = "sign.py"
default_delay = 1


def scripts_exist(*args):
    if False in map(os.path.isfile, args):
        print("Error: required js file missing, compile with npm install")
        return False
    return True


def launch_app(device, package):
    app = FridaAsync.spawn(device, package)
    app.resume()
    return app


async def get_app(device, package, relaunch, delay):
    if relaunch:
        app = launch_app(device, package)
    else:
        try:
            app = FridaAsync.attach(device, package)
        except frida.ProcessNotFoundError:
            app = launch_app(device, package)
    await asyncio.sleep(delay)
    return app


def run_just_list(package, **kwargs):
    if not scripts_exist(allow_script):
        return
    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    gms.inject(allow_script)

    launch_app(device, package)

    input()


async def run_just_signature(package, relaunch, delay, **kwargs):
    if not scripts_exist(signature_script):
        return

    device = frida.get_usb_device()

    app = await get_app(device, package, relaunch, delay)

    payload = await app.inject_async(signature_script)
    print(f"[{this_name}] extracted signature: {payload['signatureSha']}")


async def run_allow(package, signature, relaunch, patche10, forcedk, unlimiteddk, delay, auto_sign, **kwargs):
    if not scripts_exist(allow_script, signature_script, patche10_script):
        return

    device = frida.get_usb_device()

    gms = FridaAsync.attach(device, "com.google.android.gms.persistent")
    allow = gms.inject(allow_script)
    if patche10:
        gms.inject(patche10_script)

    additional_features = {
        "forcedk": forcedk,
        "unlimiteddk": unlimiteddk
    }

    if auto_sign:
        app = await get_app(device, package, relaunch, delay)
        payload = await app.inject_async(signature_script)
    else:
        payload = {"packageName": package,
                   "signatureSha": signature}

    payload.update(additional_features)

    print(f"[{this_name}] providing payload: {payload}")
    allow.post({"type": "signature", "payload": payload})

    if not auto_sign:
        await get_app(device, package, relaunch, delay)

    input()


@click.command()
@click.option("-p", "--package", "package", help="Package name (has to be one of the allowed apps)", required=True)
@click.option("-s", "--signature", "signature", help="SHA-256 of the app signature (optional)")
@click.option("-f", "--force-dk", "forcedk", is_flag=True, help="Force Diagnosis Keys signature validation")
@click.option("-u", "--unlimited-dk", "unlimiteddk", is_flag=True,
              help="Limit on number of calls to provideDiagnosisKeys resets every 1ms instead of 24h")
@click.option("-e", "--patch-e10", "patche10", is_flag=True,
              help="Patch bug in Play Services causing error 10 (Pipe is closed, affects Android 6)")
@click.option("-g", "--get-signature", "just_signature", is_flag=True, help="Get SHA-256 of the app signature")
@click.option("-a", "--allowed-packages", "just_allowed", is_flag=True, help="List all allowed packages")
@click.option("-r", "--relaunch", "relaunch", is_flag=True, help="Force re-launch of the app")
@click.option("-d", "--delay", "delay", type=click.INT, default=default_delay,
              help=f"Delay between launching the app and submitting scripts (optional, default={default_delay})")
def main(**kwargs):
    if kwargs.get('just_signature'):
        asyncio.run(run_just_signature(**kwargs))
    elif kwargs.get('just_allowed'):
        run_just_list(**kwargs)
    elif kwargs.get('signature'):
        kwargs["auto_sign"] = False
        asyncio.run(run_allow(**kwargs))
    else:
        kwargs["auto_sign"] = True
        asyncio.run(run_allow(**kwargs))


if __name__ == "__main__":
    main()
