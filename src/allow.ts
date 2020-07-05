Java.perform(() => {
    const scriptName = "allow.js"
    console.log(`[${scriptName}] injecting`);
    try {
        const stringClass = Java.use('java.lang.String');
        const signatureClass = Java.use('java.security.Signature');
        let payload: {signatureSha: string; packageName: string; forcedk: boolean} | null = null;
        let warningPrinted = false;

        recv("signature", (message: any) => {
            payload = message.payload;
            if (payload) {
                console.log(`[${scriptName}] received payload`);
            }
        })

        signatureClass.verify.overload('[B').implementation = function(signature: number[]) {
            const result = this.verify(signature);
            if (payload) {
                if (!result && payload.forcedk) {
                    console.log(`[${scriptName}] ${this} :: verify(byte[]) -> forcing true`);
                    return true;
                }
            } else {
                console.log(`[${scriptName}] Diagnosis Keys signature checking has already started, but instruction to override` +
                    " not received yet. Run with -s option.");
            }
            return result;
        }

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