import click
import frida
from FridaWrapper import FridaWrapper


allow_script = "js/allow.js"
signature_script = "js/signature.js"
patche10_script = "js/patch_e10.js"


@click.group()
def list_allowed_group():
    pass


@click.group()
def get_signature_group():
    pass


@click.group()
def sign_group():
    pass


@list_allowed_group.command("list-allowed")
def list_allowed():
    device = frida.get_usb_device()

    gms = FridaWrapper.attach(device, "com.google.android.gms.persistent")
    gms.inject(allow_script)

    input()


@get_signature_group.command("get-signature")
@click.option("-p", "--package", "package", help="Package name", required=True)
def get_signature(package):
    device = frida.get_usb_device()
    app = FridaWrapper.attach(device, package)
    app.inject(signature_script)

    input()


@sign_group.command("sign")
@click.option("-p", "--package", "package", help="Package name (has to be one of the allowed apps)", required=True)
@click.option("-s", "--signature", "signature", help="SHA-256 of the app signature", required=True)
@click.option("-f", "--force-dk", "forcedk", is_flag=True, help="Force Diagnosis Keys signature validation")
@click.option("-u", "--unlimited-dk", "unlimiteddk", is_flag=True,
              help="Limit on number of calls to provideDiagnosisKeys resets every 1ms instead of 24h")
@click.option("-e", "--patch-e10", "patche10", is_flag=True,
              help="Patch bug in Play Services causing error 10 (Pipe is closed, affects Android 6)")
def sign(package, signature, patche10, forcedk, unlimiteddk):
    device = frida.get_usb_device()

    gms = FridaWrapper.attach(device, "com.google.android.gms.persistent")
    allow = gms.inject(allow_script)
    if patche10:
        gms.inject(patche10_script)

    payload = {
        "packageName": package,
        "signatureSha": signature,
        "forcedk": forcedk,
        "unlimiteddk": unlimiteddk
    }

    allow.post({"type": "signature", "payload": payload})

    input()


cli = click.CommandCollection(sources=[list_allowed_group, get_signature_group, sign_group])


if __name__ == "__main__":
    cli()
