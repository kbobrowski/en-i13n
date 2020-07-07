## en-i13n

This project is allowing anyone with rooted Android device to access
Exposure Notifications framework with custom / forked app. The purpose is to
provide community support for developing and debugging national apps.


### Quick start

- Start [frida](https://frida.re/docs/android/) server on Android (make sure to use
the same version as in Pipfile - download from [here](https://github.com/frida/frida/releases/download/12.8.12/frida-server-12.8.12-android-arm.xz)).

- Execute in this repo:

```bash
$ npm install
$ pipenv install
```

#### Run custom app with Exposure Notifications framework

- Execute:

```bash
$ pipenv run python en.py list-allowed
```

- Start covid app which is using Exposure Notifications and navigate to a place
where Exposure Notifications API is accessed (usually main screen of the app). Pick
one name from the list of apps printed:

```bash
[allow.js] injecting
[allow.js] Payload not yet received.
[allow.js] possible package name: com.google.android.apps.apollo
[allow.js] possible package name: com.google.android.apps.exposurenotification
[allow.js] possible package name: com.google.location.nearby.apps.contacttracer
...
```

- Assign chosen package name (e.g. `de.rki.coronawarnapp.dev`) to your custom app (note: your app should include `implementation "commons-codec:commons-codec:1.13"` in `build.gradle`), run the custom app on the device, and execute:

```bash
$ pipenv run python en.py get-signature -p de.rki.coronawarnapp.dev
[signature.js] injecting
[signature.js] signature = 854528796DB85A3155FAAF92043CD3C42163CB9FA3C6709324A7F39DF4158462
```

- Patch Play Services by executing (note: this is independent from the custom app running or not):

```bash
$ pipenv run python en.py sign -p de.rki.coronawarnapp.dev -s 854528796DB85A3155FAAF92043CD3C42163CB9FA3C6709324A7F39DF4158462
[allow.js] injecting
[allow.js] received payload
[allow.js] overriding signature
```

See `pipenv run python en.py sign --help` for more options:

```
Usage: en.py sign [OPTIONS]

Options:
  -p, --package TEXT    Package name (has to be one of the allowed apps)
                        [required]

  -s, --signature TEXT  SHA-256 of the app signature  [required]
  -f, --force-dk        Force Diagnosis Keys signature validation
  -u, --unlimited-dk    Limit on number of calls to provideDiagnosisKeys
                        resets every 1ms instead of 24h (careful - going back
                        to the previous behavior after using this option
                        requires cleaning all the app data)

  -e, --patch-e10       Patch bug in Play Services causing error 10 (Pipe is
                        closed, affects Android 6)
```

#### Just patching a bug in Play Services affecting Android 6

Execute:

```bash
pipenv run python en.py patch
```

and launch original corona app.

### Compatibility notes

- Confirmed to be working with Play Services 20.21.17

### Disclaimer

This software does not exploit any vulnerability, and it does not
allow to deploy custom / forked apps to the Play Store. Using this method requires
deliberate action on the user side and rooted phone. Any information that can be
extracted from Exposure Notifications framework using this method is already
available to the user with rooted phone anyway, as data stored by Exposure Notifications
framework are unencrypted.
