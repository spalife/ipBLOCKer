# :: ipBLOCKer ::
```
Category blocking using 
iptables and ipsets

Blocks IPs & CIDR's tagged as 
Adware Country Custom ETF
Malware Shalla(exp) Spam
Tor-Exits
```
#### :: Features ::
```
- Command Line Driven with Menu
  Assist
- Category based Blocking
- Select Categories to Block
- Incremental Updates
- Turn on/off Blocking temporarily
- Blocking Status
- Configurable System
- Control how much data gets into
  Categories with Buckets and
  Maximum Entries.
  System seeds with Max Entries of
  65500 and 10 Buckets.
- Scheduled and Manually triggered
  Refreshes
- White-listing of ips,cidrs,urls
- Custom category to add any
  requried ips,cidrs,urls
- Supports additions to existing
  Filters & Categories
- Check system for Blocking Status
  of a ips,cidrs,urls
- Backup and Restore
- Uninstall a Category or System
```
#### :: System Requirements ::
```
bash(4.3+) diff(3.3+) grep(2.26+)
sort(8.2+) split(8.2+) xargs(5.2+)
kernel (2.4+) ipset (4.5+)
iptables (1.3+)
```
#### :: Installation ::
```
1. On Asuswrt-Merlin Install
   [Entware-ng](https://www.hqt.ro/how-to-install-new-generation-entware/)

2. After Entware Installation
   Install below packages with command

   opkg install bash diffutils grep \
   coreutils-sort coreutils-split \
   findutils

3. Download ipBLOCKer Instructions

   mkdir -P ipBLOCKer; cd ipBLOCKer;
   curl git-url
   chmod +x *.sh;
   ./ipBLOCKer.sh setup
   ( now select categories to block )

4. exit out of ssh/telnet
   ssh/telnet again for alias to work
   cd ipBLOCKer

   If you want to add to an existing
   category  filters or delete from
   them, you can do them now.
   We can wait for refresh schedule
   to  update selected categories
   or can start a refresh manually.
   Start off with some seeded
   blocks by running command

   block refresh custom
```
#### :: Files Changed ::
```
(uninstall all will remove this
changes)

/jffs/scripts/firewall-start
~/.profile
~/.bash_profile
crontab

Appreciate
Feedback and Suggestions
```
#### :: Thanks to ::
```
@RMerlin  (Asuswrt-Merlin)
@thiggins (snbforums.com)

Inspiring contributions
Knowledge and Sharing
@john9527 @ryzhov_al  @kvic
@Adamm    @Martineau  @thelonelycoder
@TeHashX  @bigeyes0x0 @swetoast
@redhat27 @joegreat   @sfx2000   
@tomsk    @Zirescu    @ColinTaylor
```
#### :: Usage ::
 ```
ipBLOCKer.sh [option] [parameter]
block [option] [parameter]

**Example:**
ipBLOCKer.sh status
ipBLOCKer.sh refresh
ipBLOCKer.sh add white-list
block add custom
block refresh malware
block check
```

##### Options:
```
help      - Shows available options
setup     - Configures System
status    - Shows blocking and
            system information
refresh   - Manual trigger refresh
            of a category or all
add       - Add to a category
            ips, urls, cidrs
delete    - Delete from a category
            or all  - ips, urls, cidrs
check     - check system to see if
            ips, urls, cidrs are
            blocked
backup    - Makes a backup
restore   - Restores from backup
off       - Turns off blocking
on        - Turns on blocking
synch     - Recreate necessary
            iptable rules if missing or
            deleted
uninstall - Uninstalls a category or
            system
version   - Displays version
            information
```
#### :: Limitations ::
```
- Currentlly only ip version 4 ips
  and cidrs  are suported
- The maximum number of buckets
  aka sets  which can be created per
  category is 26. Theoretically about
  1.7 million entries  per category.  
  System defaults to 10
- Shalla filtering currently is limited
  to  any ip’s and cidr’s available in
  the  filter
- White listing an ip or cidr or url for
  security reasons is  currently ONLY
  on tcp protocol  and on ports
  80 and 443
- As a precaution Local aka
  Private Addresses are not blocked
```
#### :: Upcoming (few) Features ::
```
- Turn off/on blocking by Category
- DROP/REJECT choice per Category
- Top 10 blocks by Category
- Top 10 blocks by IP
- CLI additional param for IP/CIDR/URL
  i.e.,
  block [add/del] category [ip/cidr/url/file]
```
#### :: Categories Blocking Filters Info ::
```
ADWARE
( feeds from yoyo hphosts )

COUNTRY
( feeds from ipdeny )
- Current filters
  Brazil, Latvia, Moldova, Nigeria,
  North Korea, Pakistan, Peru,
  Philippines,  Romania, Spain, Taiwan,
  Thailand, Turkey, Ukraine, Vietnam

( IMHO  if you are from the country or
  visit them  on the net,  delete them.
  Add/Delete based on your
  preference. )

EMERGING-THREATS aka ETF
( feeds from talos snort shunlist
  malc0de bruteforceblocker
  dshield-30 days )

MALWARE
( feeds from openbl_all, threatcrowd,
  myip, blocklist_de, c2-ipmasterlist,
  ransomwaretracker,  zeustracker,
  feodotracker, alientvault_reputation,
  malwaredomainlist, abuseat )

SHALLA (experimental)
( feeds from shallalist ) - Current filters
  Advertisement, Spyware, Trackers

SPAM
( feeds from spamhaus_drop,
  spamhaus_edrop,
  firehol_webclient )

TOR-EXITS
( feeds from firehol_et_tor )
```
#### :: Refresh Schedule ::
```
Adware    - Daily at 8:00
Country   - Every Wednesday at 12:00
ETF       - Every 8 hrs on minute 45
Malware   - Daily at 9:00
Shalla    - Daily at 9:30
Spam      - Daily at 10:00
Tor-Exits - Daily at 10:30

( refresh can be started when needed )

```
#### :: FAQ ::
**Why the caps in filename ?**
```
Given a hammer .... 
.... everything looks like a nail 
(says the old one)

Every path leads to the ether ....
.... the ether leads to you
(says the wise one)

Pun apart,
To avoid conflict with other existing
files and as a identifiable tag.
As a convenience an alias block can
be used.
```
**Is it white-list, unlist or delist ?**
```
Is tomato a fruit or vegetable ?
```
**What’s with all the french, greek,
latin ?**
```
Category    = Refers to Malware,
              Spam, Adware,
              Emerging Threats,
              Country, Tor-Exits
Filters     = Refers to url’s from
              which tagged blocking
              data is downloaded
Url’s       = The web source of the
              tagged data
Buckets     = aka ipset sets which
              contain the block data.
              System Defaults to 10
              ( can be changed )
Max Entries = The number of entries
              per bucket.
              System MAX is 65500
```
**How can I white-list ip or cidr or a
web site?**
```
Two options are available:
1.  Remove ip or cidr through the
    delete option, which removes
    them  from specified categories.
    Note: ip or cidr might be blocked
    again  as part of future refreshes,
    this approach could be ineffective
    for CIDR blocks.
2.  White list the ip or cidr or web site
    through white-list option.
    It is the recommended approach
    more so In situations when an ip is
    being blocked  through a cidr.
```
**What is this Custom Category ?**
```
Any website url, ips or cidrs which are
currently not blocked by the system,
which you desire to block can be added
to this category.
```
**How long does it take to update
aka refresh ?**
```
The First run of any category could be
long, between 5-30 minutes depending
on your  bandwidth and tagged blocking
data available  from the feeds of the
Category.  
Subsequent Incremental refreshes
should be between 1-5 minutes.
```
**White-list hit count is getting reset ?**
```
White lists are lazy to stand in a Q
aka line.
They have to be first in line.
They have to be pampered and served
first,  so that an  ip or cidr is not
blocked.
Repositioning the white lists to the
top leads  to hit count reset.
```
**Removed a category but ip or cidr
or url are  still blocked ?**
```
Steps:
1. Use the check option to see if the
   ip or cidr or url are still part of any
   other category and  are part of
   ipBLOCKer
2. Look in syslog and see if the ip or
   cidr or url  are blocked by any other
   services
3. Use white-list option to white list
   the ip or  cidr or url
4. Post in forum for further help
```
**Removed a category filter aka url
but the ip or cidr are still blocked ?**
```
Removing a filter from a category will
prevent future updates to the category
from the filter.
Most likely a refresh has run before the
filter deletion. The filter might not be
the source of the blocked ip.
Any blocked ip or cidr from the
deleted filter can be removed through
options:
1. delete ip or cidr or url
2. white-list ip or cidr or url
3. uninstall the category and re-install
   the category  (if the issue is severe)
```
**How do I Uninstall ipBLOCKer ?**
```
1. Uninstall available via two options
   block uninstall categoryName
   or
   block uninstall all
2. Go to Setup and Unselect the
   category i.e., block setup
   ( Choose Select Categories Option
     and
     Unselect what you want to remove )
   white-list and custom categories
   can only  be uninstalled with
   block uninstall white-list
   block uninstall custom
```
![ScreenShot](/ipBLOCKer1SystemCheck.jpeg) 
![ScreenShot](/ipBLOCKer2InvalidOption.jpeg) 
![ScreenShot](/ipBLOCKer3SetupandCategoriesMenus.jpeg)
![ScreenShot](/ipBLOCKer4RefreshMenu.jpeg) 
![ScreenShot](/ipBLOCKer5RefreshCustom.jpeg) 
![ScreenShot](/ipBLOCKer6RefreshSpamMalware.jpeg) 
![ScreenShot](/ipBLOCKer7Check.jpeg) 
![ScreenShot](/ipBLOCKer8UninstallCustom.jpeg) 
![ScreenShot](/ipBLOCKer9Status.jpeg) 


