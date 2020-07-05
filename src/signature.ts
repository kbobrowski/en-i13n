Java.perform(() => {
    const scriptName = "signature.js"
    console.log(`[${scriptName}] injecting`);
    try {
        const context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        const md = Java.use('java.security.MessageDigest');
        const hex = Java.use('org.apache.commons.codec.binary.Hex');
        const str = Java.use('java.lang.String');

        const packageName = context.getPackageName();
        const signaturesObject = context.getPackageManager().getPackageInfo(packageName, 0x40).signatures;
        const signatureBytes = signaturesObject.value[0].toByteArray();
        const mdInstance = md.getInstance('SHA-256');
        const signatureSha = str.$new(hex.encodeHex(mdInstance.digest(signatureBytes))).toUpperCase();
        send({
            signatureSha,
            packageName
        });
    } catch (e) {
        console.log(e);
    }
})