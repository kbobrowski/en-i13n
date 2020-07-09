// usage:
// /data/local/tmp/frida-inject-12.8.12-android-arm64 -n com.google.android.gms.persistent -s /data/local/tmp/scripts/allow_args.js --parameters '{"packageName":"de.rki.coronawarnapp.dev", "signatureSha":"0FFD2502F3DF76D9F4032A5085BA9267A1712670518A05AA8BB71D9E79218210", "forcedk":""}'

let signatureSha: string = "";
let packageName: string = "";
let forceDk: boolean = false;
let unlimitedDk: boolean = false;

rpc.exports = {
    init: function (stage: any, parameters: any) {
        signatureSha = parameters["signatureSha"];
        packageName = parameters["packageName"];
        forceDk = parameters["forcedk"] != undefined;
        unlimitedDk = parameters["unlimiteddk"] != undefined;
    },
}

Java.perform(() => {
    const scriptName = "allow.js"
    console.log(`[${scriptName}] injecting overloads`);
    try {
        const stringClass = Java.use('java.lang.String');
        const signatureClass = Java.use('java.security.Signature');
        const timeUnitHoursClassName = Java.use('java.util.concurrent.TimeUnit').HOURS.value.getClass().getName();
        const timeUnitHoursClass = Java.use(timeUnitHoursClassName);

        timeUnitHoursClass.toMillis.overload('long').implementation = function (duration: number) {
            if (duration == 24) {
                if (unlimitedDk) {
                    console.log(`[${scriptName}] TimeUnit.HOURS :: toMillis(duration=${duration}) -> forcing 1`);
                    return 1;
                }
            }
            return this.toMillis(duration);
        }

        signatureClass.verify.overload('[B').implementation = function (signature: number[]) {
            const result = this.verify(signature);
            if (!result && forceDk) {
                console.log(`[${scriptName}] Signature :: verify(byte[]) -> forcing true`);
                return true;
            }
            return result;
        }

        stringClass.split.overload('java.lang.String').implementation = function (separator: string) {
            if (separator === ":") {
                const splitValues: string[] = this.split(separator);
                if (splitValues.length === 2) {
                    if (splitValues[0] === packageName) {
                        console.log(`[${scriptName}] overriding app signature`);
                        return Java.array('java.lang.String', [packageName, signatureSha]);
                    }
                }
            }
            return this.split(separator);
        }
    } catch (e) {
        console.log(e);
    }
})

