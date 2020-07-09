
interface Payload {
    signatureSha: string;
    packageName: string;
    forcedk: boolean;
    unlimiteddk: boolean;
}

const scriptName = "allow.js"
let payload: Payload | null = null;

rpc.exports.init = function(stage: any, parameters: Payload) {
    const emptyPayload = {
        signatureSha: "",
        packageName: "",
        forcedk: false,
        unlimiteddk: false
    }
    payload = {...emptyPayload, ...parameters};
    console.log(`[${scriptName}] payload: ${JSON.stringify(payload)}`)
}

Java.perform(() => {
    const payloadWarning = `[${scriptName}] payload not yet received`
    console.log(`[${scriptName}] injecting`);
    try {
        const stringClass = Java.use('java.lang.String');
        const signatureClass = Java.use('java.security.Signature');
        const timeUnitHoursClassName = Java.use('java.util.concurrent.TimeUnit').HOURS.value.getClass().getName();
        const timeUnitHoursClass = Java.use(timeUnitHoursClassName);
        let warningPrinted = false;

        recv("signature", (message: any) => {
            payload = message.payload;
            if (payload) {
                console.log(`[${scriptName}] received payload`);
            }
        })

        timeUnitHoursClass.toMillis.overload('long').implementation = function(duration: number) {
            if (duration == 24) {
                if (payload) {
                    if (payload.unlimiteddk) {
                        console.log(`[${scriptName}] TimeUnit.HOURS :: toMillis(duration=${duration}) -> forcing 1`);
                        return 1;
                    }
                } else if (!warningPrinted) {
                    warningPrinted = true;
                    console.log(payloadWarning);
                }
            }
            return this.toMillis(duration);
        }

        signatureClass.verify.overload('[B').implementation = function(signature: number[]) {
            const result = this.verify(signature);
            if (payload) {
                if (!result && payload.forcedk) {
                    console.log(`[${scriptName}] Signature :: verify(byte[]) -> forcing true`);
                    return true;
                }
            } else if (!warningPrinted) {
                warningPrinted = true;
                console.log(payloadWarning);
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
                            console.log(payloadWarning);
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