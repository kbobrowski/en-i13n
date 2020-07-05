Java.perform(() => {
    const scriptName = "allow.js"
    console.log(`[${scriptName}] injecting`);
    try {
        const stringClass = Java.use('java.lang.String');
        let payload: {signatureSha: string; packageName: string} | null = null;
        let warningPrinted = false;

        recv("signature", (message: any) => {
            payload = message.payload;
            if (payload) {
                console.log(`[${scriptName}] received payload`);
            }
        })

        stringClass.split.overload('java.lang.String').implementation = function(separator: string) {
            if (separator === ":") {
                const splitted: string[] = this.split(separator);
                if (splitted.length === 2) {
                    if (!payload) {
                        if (!warningPrinted) {
                            warningPrinted = true;
                            console.log(`[${scriptName}] Signature checking has already started, but package name and signature` +
                                " not received yet. Listing possible package names.");
                        }
                        console.log(`[${scriptName}] possible package name: ${splitted[0]}`);
                    } else {
                        if (splitted[0] === payload.packageName) {
                            console.log(`[${scriptName}] overriding signature`);
                            return Java.array('java.lang.String', [payload.packageName, payload.signatureSha]);
                        }
                    }
                }
            }
            return this.split(separator);
        }
    } catch (e) {
        console.log(e);
    }
})