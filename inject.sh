#!/system/bin/sh
fridaserver=/data/local/tmp/frida-server-12.8.12-android-arm
fridainject=/data/local/tmp/frida-inject-12.8.12-android-arm
allowscript=/data/local/tmp/allow.js

scriptname="inject.sh"
echo "[$scriptname] starting"

while true
do
  fridarunning=`ps -e | grep frida-server | wc -l`
  scriptrunning=`ps -e | grep frida-inject | wc -l`
  if [ $fridarunning -ne 1 ]
  then
    if [ $scriptrunning -eq 1 ]
    then
      echo "[$scriptname] killing inject"
      ps -e | grep frida-inject | xargs sh -c 'kill -9 $1'
    fi
    echo "[$scriptname] starting frida"
    $fridaserver -D
  fi

  sleep 10
  scriptrunning=`ps -e | grep frida-inject | wc -l`
  if [ $scriptrunning -ne 1 ]
  then
    echo "[$scriptname] starting inject"
    $fridainject -n com.google.android.gms.persistent -s $allowscript -P '{"packageName":"de.rki.coronawarnapp.dev","signatureSha":"854528796DB85A3155FAAF92043CD3C42163CB9FA3C6709324A7F39DF4158462","forcedk":"true","unlimiteddk":"true"}' &
  fi
  sleep 10
done
