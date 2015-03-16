encrypted-userprefs
===================

An encrypted and slightly less insecure wrapper for [SharedPreferences](http://developer.android.com/reference/android/content/SharedPreferences.html) for Android. 
[SharedPreferences](http://developer.android.com/reference/android/content/SharedPreferences.html) on Android stores all of your values in "plain text", simply protected by the user-restricted file system on Android.
If you gain root access to an Android device you have full read/write access to the application preferences of all of the applications installed.

Many applications store some kind of application secret (e.g. a communication token, last used account number) using SharedPreferences. 

By using this class you'll protect your preferences with a strong and proven symmetric cipher (AES) which will make it harder for anyone wishing to extract information from your application. 

PS: This will not make your application bulletproof, just better :)

#### Example:
A regular shared preference file looks like this from adb shell:

    cat /data/data/your.package.application/shared_prefs/prefs-test.xml
    <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
    <map>
    <string name="hemmelighet">dette er en hemmelighet</string>
    </map>
    
With encryption you get a less obvious version:

	cat /data/data/your.package.application/shared_prefs/prefs-test.xml
    <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
    <map>
    <string name="JopRH053b7Ogw17Yxmh7Og==">0AB7Y28XEvbQcnXpEZ4j9PtqzFLtm2V3KBXjTO1V704=</string>
    </map>

    The key is "hemmelighet" and the value is "dette er en hemmelighet".

#### Usage:
	// Init
    SecurePreferences preferences = new SecurePreferences(context, "my-preferences",
    "SometopSecretKey1235", "randomSalt", true);
    // Put a String value(all puts are automatically committed)
    preferences.putString("userId", "User1234");
    // Get a String value
    String user = preferences.getString("userId");
    // Put a boolean value
    preferences.putBoolean("boolKey", true);
    // Get a boolean value
    String user = preferences.getBoolean("booleanKey", true/false);
    
#### Requirements and limitation:
Android API Level 10 (for SecureRandom).
