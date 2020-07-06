Java.perform(() => {
    const scriptName = "patch_e10.js"
    console.log(`[${scriptName}] injecting`);
    try {
        const inputStream = Java.use("java.io.InputStream");
        inputStream.read.overload('[B').implementation = function(buffer: number[]) {
            let bufferIndex = 0;
            // patch only PipedInputStream
            if (this.toString().includes("Piped")) {
                let readResult = 0;
                while (bufferIndex < buffer.length) {
                    readResult = this.read();
                    if (readResult >= 0) {
                        buffer[bufferIndex] = readResult;
                        bufferIndex += 1;
                    } else {
                        break;
                    }
                }
                console.log(`[${scriptName}] PipedInputStream :: read(byte[]) = ${bufferIndex}`)
            } else {
                bufferIndex = this.read(buffer);
            }
            return bufferIndex;
        }

    } catch (e) {
        console.log(e);
    }
});