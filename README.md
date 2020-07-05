## en-i13n

This project is allowing anyone with rooted Android device to access
Exposure Notifications framework with custom / forked app. The purpose is to
provide community support for developing and debugging national apps
(severity of the issues are visible e.g. in case of German app:
[#774](https://github.com/corona-warn-app/cwa-app-android/issues/774),
[#737](https://github.com/corona-warn-app/cwa-app-android/issues/737)).

#### Compatibility notes

- Confirmed to be working with Play Services 20.21.17

- Devices with Android 6 (and perhaps others as well) need to use `-e` option
to patch a bug in Play Services 20.21.17

- If package name defined in file with Diagnosis Keys is not matching
package name of the app then `-f` option has to be used to force validation
of Diagnosis Keys file

#### How is it working

The trick is to override app signature on the fly while Play Services is parsing
list of allowed apps. It does not exploit any vulnerability, and it does not
allow to deploy custom / forked apps to the Play Store. Using this method requires
deliberate action on the user side and rooted phone. Any information that can be
extracted from Exposure Notifications framework using this method is already
available to the user with rooted phone anyway, as data stored by Exposure Notifications
framework are unencrypted.

#### How to use

- Start [frida](https://frida.re/) server on Android device using adb shell. Tested with
version `12.8.12` - new versions did not work on my device with Android 6. Server can be downloaded
from [here](https://github.com/frida/frida/releases/download/12.8.12/frida-server-12.8.12-android-arm.xz).
- Compile typescript scripts in this repo: `npm install`
- Set up pipenv environment: `pipenv install` (make sure that frida client has the same
version as frida server in [Pipfile](Pipfile))
- List all allowed package names by launching package which is already allowed and
navigating to the Activity which requires Exposure Notifications:
`pipenv run python sign.py -p de.rki.coronawarnapp -a`
- Pick one of the names in the list and assign it to the application ID of the custom app, e.g. `de.rki.coronawarnapp.dev`
- Install custom app with any signature  
  Note: The app should include `implementation "commons-codec:commons-codec:1.13"` in `build.gradle`
- Spawn custom app with `pipenv run python sign.py -p de.rki.coronawarnapp.dev`

Following log indicates that everything went OK:

```
[allow.js] injecting
[signature.js] injecting
[sign.py] providing payload: {'signatureSha': '854528796DB85A3155FAAF92043CD3C42163CB9FA3C6709324A7F39DF4158462', 'packageName': 'de.rki.coronawarnapp.dev'}
[allow.js] received payload
[allow.js] overriding signature
```

See `pipenv run python sign.py --help` for more options.

#### Troubleshooting

##### Exposure Notifications initialized before signing

In case Exposure Notifications framework is initialized before signature could be provided - try to decrease delay between launching app and executing scripts with `-d` option (current default value: 1), or execute:

`pipenv run python sign.py -p de.rki.coronawarnapp.dev -g`

to just retrieve signature:

```
[signature.js] injecting
[sign.py] extracted signature: 854528796DB85A3155FAAF92043CD3C42163CB9FA3C6709324A7F39DF4158462
```

and then:

`pipenv run python sign.py -p de.rki.coronawarnapp.dev -s 854528796DB85A3155FAAF92043CD3C42163CB9FA3C6709324A7F39DF4158462`

##### Scripts injected before app is initialized

Increase delay with option `-d`, or execute commands only when the app is already running.

##### 39508 error

This happens when `provideDiagnosisKeys` is called more than 20 times a day - it's a limit imposed by Google.