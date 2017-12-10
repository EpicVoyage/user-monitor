# User Monitor
The UserMonitor Project was sponsored by [Cogent Innovators, LLC](http://www.cogentinnovators.com/), and has been released under the terms of Version 2 of the GNU General Public License.

This program runs as a service under Windows 2000 and up (or as a background process for Windows 98/ME) and keeps track of which users are logged on to the computer. It reports that list along with the user's domain and computer IP addresses to a MySQL database of your choosing.

It can also log to a central syslog server. It was developed for use with the Squid proxy server due to limitations in proxy logins. The lowest-credentialed user is being used to restrict all internet access to the machine.

# Current minimum requirements:

* Windows 98
* libmysql.dll - MySQL 5.1 or above is required for Vista compatibility
* tools/server-*.pem - for the built-in certificates to work

Windows 9x has a couple caveats. The first is that this program does not shut down
gracefully. I have been unsuccessful at getting it to read WM_QUIT messages so far.
For now when the system is shut off the corresponding MySQL entries are not
cleared. They are if the user logs off, however. The second is that it reads the
domain name from

> HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MSNP32\NetworkProvider\AuthenticatingAgent

(which only works for "Microsoft Networks") and falls back to the machine name if
that key does not exist.

Windows 2000 and up are now fully supported as multi-user environments.

The MySQL library is the only non-standard file required to make this work. It needs
to either be in the same directory as usermonitor.exe or in the System32 directory.

The information used to create the database tables is stored in usermonitor.sql. If
you do not wish to use SSL, please remove the "REQUIRE SSL" portion from the line
controlling user permissions.

There is a special case in the code so that if "/log=0" or "/log=2" is the first
parameter passed to the program then a log file will not be created. A log file also
should not be created when this program is run as a service.

# Here is what I used to compile this project:

* Visual C++ 2005 (2008/Express should also work)
* MySQL 5.1, including developer files

There is a project file which should handle all of the environment requirements for
a proper build in VC++ 2005 and up.

# Command line arguments:

> usermonitor.exe /install /uninstall /test /server=localhost /port=3306 /etc
>
> /install		- Installs the binary as a service in its current location
>
> /uninstall	- Removes itself from being a service
>
> /server=		- Set MySQL server					[Default: localhost]
>
> /port=			- Set server port to use		[Default: 3306]
>
> /db=				- Set the MySQL database		[Default: usermap]
>
> /user=			- Set login username				[Default: monitor]
>
> /password=	- Set remote password for reporting
>
> /ssl=				- 0 = off, 1 = on						[Default: 0]
>
> /logserver=	- RFC3164 syslog server			[Default: localhost]
>
> /logport=		- UDP port for syslog messages	[Default: 514]
>
> /log=				- Log type. 0 = none, 1 = UserMonitor.txt, 2 = syslog, 3 = both [Default: 3]
>
> /test			- Perform one user check and exit

# Legal notices:

This product includes software developed by the OpenSSL Project for use in the
OpenSSL Toolkit (http://www.openssl.org). This product includes cryptographics
software written by Eric Young (eay@cryptsoft.com). This product includes software
written by Tim Hudson (tjh@cryptsoft.com).
