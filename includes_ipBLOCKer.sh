#!/usr/bin/env bash
################################################################################
# Contains System Constants.
# Any changes here will modify system onfiguration and behaviour
# CAUTION ADVISED.
# Make changes through Menu's or through CLI
################################################################################
IPBLOCKER_DIR="${IPBLOCKER_DIR:-$PWD}"; IPBLOCKER_DIR="${IPBLOCKER_DIR%/}"

VERSION="1.1"

# Location of the Program from which filters and refresh directory is derived
# Make sure directory name does not contain any spaces
DIR_SCRIPTS=$IPBLOCKER_DIR

# Naming Convention for filters, refreshes and backup
FILTERS_TAG="filters"
REFRESH_TAG="refresh"
BACKUP_TAG="backup"

# Naming Convention and Directory to store filters and refreshes
DIR_FILTERS="$DIR_SCRIPTS/$FILTERS_TAG"
DIR_REFRESH="$DIR_SCRIPTS/$REFRESH_TAG"
DIR_BACKUP="$DIR_SCRIPTS/$BACKUP_TAG"
LOG_FILE="/tmp/syslog.log"

# For ipset version higher than 4.5 where maxelem can be Increased to more than
# 65K change the value here. Unchanged for compatability btw Version 4 & 6
declare -i MAX_ENTRIES_LIMIT=65500

# DROP or REJECT the interaction of a Blocked IP.
# Recommended and Default Value is DROP
DROP_OR_REJECT="DROP"

# ACCEPT or RETURN the interaction of a white-listed IP.
# ACCEPT allows the interaction to continue.
# RETURN moves the packet to a different chain in ipset.
# Useful for debugging and auditing purpose, otherwise usage is mute.
# In case of ipBLOCKer RETURN will result in the IP being DROP or REJECT.
# Recommended and Default Value is ACCEPT
ACCEPT_OR_RETURN="ACCEPT"

# The Naming convention for defining categories and filters
# Seeded Filter Categories and master category tag's
# DO NOT CHANGE SEEDED VALUES
# Recommended if needed to change the naming convention after setup
# in filters directory
CATEGORIES_TAG="categories"
ADWARE_TAG="adware"
COUNTRY_TAG="country"
CUSTOM_TAG="custom"
ETF_TAG="etf"
MALWARE_TAG="malware"
SHALLA_TAG="shalla"
SPAM_TAG="spam"
TOR_EXITS_TAG="tor-exits"
WHITE_LIST_TAG="white-list"

###########################################################
#
# CAUTION WHILE CHANGING SYSTEM DEFAULT VALUES FROM HERE ON
#
###########################################################
# Max Number of Prallel Processes to use when needed
declare -i NUM_PROCS=10

# White List needs to be at the top of the rule chain for it to be effective.
# There is an overhead associated with pushing it to top after every refresh.
# Hit counts are also lost.
# Currently there exists an option to delete white listed
# elements from other categories.
# Turn it ON i.e., to 1 if a little overhead and loosing of hit counts is
# not an issue.
# When the push to top is off i.e., 0,
# white listed elements may be blocked(temporarily) if they are part of an
# ongoing refresh, till the system clears them from refreshed categories.
declare -i PUSH_TO_TOP=1

# Maximum Number of buckets to create per Category (Sytem Maximum is 26)
# Recommended and default Value is 10
declare -i MAX_BUCKETS=10

# Default Max Number of Elements in a Set is 65536 after which ipset keeps
# silently Dropping. Seen erratic behavior past 65500 elements in a set.
# Recommended Maximum Number of IP's in a Bucket is 65500.
# Change it through setup menu
declare -i MAX_ENTRIES=65500

# Default overall Max Number of Elements which can be refreshed
declare -i SYSTEM_MAX_ENTRIES=$MAX_ENTRIES*$MAX_BUCKETS

# File Extensions used
FILTER_FILE_EXT=".urls"
REFRESH_FILE_EXT=".txt"
CIDR_FILE_EXT=".cidr"
CONFIG_FILE_EXT=".config"
BACKUP_FILE_EXT=".backup"
ERROR_FILE_EXT=".error"
ENABLED_FILE_EXT=".off"
DISABLED_FILE_EXT=".on"
TEMP_FILE_EXT=".temp"
SORT_FILE_EXT=".sort"
DIFF_FILE_EXT=".diff"
LOCK_FILE_EXT=".lock"

####
# Section: Configuring Filters and refreshes file names and locations
# EXTREME CAUTION CHANGING THE BELOW VALUES
# DO NOT CHANGE THE DEFAULT VALUES
####
CATEGORY_LIST="$DIR_FILTERS/$CATEGORIES_TAG$REFRESH_FILE_EXT"

ADWARE_FILTERS="$DIR_FILTERS/$ADWARE_TAG$FILTER_FILE_EXT"
COUNTRY_FILTERS="$DIR_FILTERS/$COUNTRY_TAG$FILTER_FILE_EXT"
ETF_FILTERS="$DIR_FILTERS/$ETF_TAG$FILTER_FILE_EXT"
MALWARE_FILTERS="$DIR_FILTERS/$MALWARE_TAG$FILTER_FILE_EXT"
SHALLA_FILTERS="$DIR_FILTERS/$SHALLA_TAG$FILTER_FILE_EXT"
SPAM_FILTERS="$DIR_FILTERS/$SPAM_TAG$FILTER_FILE_EXT"
TOR_EXITS_FILTERS="$DIR_FILTERS/$TOR_EXITS_TAG$FILTER_FILE_EXT"

CUSTOM_REFRESH_TEMP="$DIR_REFRESH/$CUSTOM_TAG$REFRESH_FILE_EXT$TEMP_FILE_EXT"
CUSTOM_REFRESH="$DIR_REFRESH/$CUSTOM_TAG$REFRESH_FILE_EXT"
CUSTOM_REFRESH_CIDR="$DIR_REFRESH/$CUSTOM_TAG$CIDR_FILE_EXT"

WHITE_LIST_REFRESH_TEMP="$DIR_REFRESH/$WHITE_LIST_TAG$REFRESH_FILE_EXT$TEMP_FILE_EXT"
WHITE_LIST_REFRESH="$DIR_REFRESH/$WHITE_LIST_TAG$REFRESH_FILE_EXT"
WHITE_LIST_REFRESH_CIDR="$DIR_REFRESH/$WHITE_LIST_TAG$CIDR_FILE_EXT"

#SHALLA_URL="http://www.shallalist.de/Downloads/shallalist.tar.gz"
SHALLA_DIR_TAG="BL"
SHALLA_DOMAINS_TAG="domains"
SHALLA_CATEGORY_LIST="$DIR_FILTERS/$SHALLA_TAG$REFRESH_FILE_EXT"

# 0 = OFF 1 = ON CAUTION Turning it on will white-list all aws ip's & cidr's
declare -i AWS_CIDR_WHITE_LIST=0
AWS_TAG="aws"
AWS_CIDR_URL="https://ip-ranges.amazonaws.com/ip-ranges.json"
AWS_IP_EXPR="ip_prefix"
AWS_CIDR_REFRESH="$DIR_REFRESH/$AWS_TAG$CIDR_FILE_EXT"

# 0 = OFF 1 = ON CAUTION Turning it on will white-list all cloudfare ip's & cidr's
declare -i CLOUDFARE_CIDR_WHITE_LIST=0
CLOUDFARE_TAG="cloudfare"
CLOUDFARE_CIDR_URL="https://www.cloudflare.com/ips-v4"
CLOUDFARE_CIDR_REFRESH="$DIR_REFRESH/$CLOUDFARE_TAG$CIDR_FILE_EXT"

# 0 = OFF 1 = ON CAUTION Turning it on will white-list all git ip's & cidr's
declare -i GIT_CIDR_WHITE_LIST=0
GIT_TAG="git"
GIT_CIDR_URL="https://help.github.com/articles/github-s-ip-addresses/"
GIT_CIDR_REFRESH="$DIR_REFRESH/$GIT_TAG$CIDR_FILE_EXT"

declare -i CACHE_CLEAR_NORMAL=1
declare -i CACHE_CLEAR_MEDIUM=2
declare -i CACHE_CLEAR_AGGRESSIVE=3
declare -i CACHE_CLEAR_LEVEL=$CACHE_CLEAR_AGGRESSIVE

# System wide Banner tag used in logging, config, profile and filtering
# DO NOT CHANGE THE DEFAULT VALUES
BLOCK_APPLN_TAG="ipBLOCKer"

# Name of alias
ALIAS_NAME="block"

FIRE_SCRIPT="/jffs/scripts/firewall-start"
IPBLOCKER_CONFIG=$IPBLOCKER_DIR"/."$BLOCK_APPLN_TAG"$CONFIG_FILE_EXT"

# Processing Tag's for IP and CIDR  DO NOT CHANGE THE DEFAULT VALUES
IP_TAG="IP"
CIDR_TAG="CIDR"

# Default size of an empty IPSet = 6
declare -i DEFAULT_SETSIZE=6

# Refresh retries
declare -i RETRIES=10

# 0 = OFF 1 = ON DO NOT CHANGE THE DEFAULT VALUES
# Show  Status
declare -i SHOW_STATUS_ENABLED=1

STATUS_LINE_SEPERATOR_1="#"
STATUS_LINE_SEPERATOR_2='_'

declare -i SUCCESS=0
declare -i EXIT_NORMAL=0
declare -i EXIT_ERROR=1
declare -i EXIT_ALERT=2
declare -i EXIT_ABORT=3
declare -i EXIT_CODE=$EXIT_NORMAL
EXIT_MESSAGE="Done"

SIG_HUP=1
SIG_INT=2
SIG_QUIT=3
SIG_KILL=9
SIG_TERM=15
SIG_STOP=18

LOCK_FILE="$IPBLOCKER_DIR"/"$BLOCK_APPLN_TAG$LOCK_FILE_EXT"

# Wait in Seconds
WAIT_TIME=300

# Time in minutes
LOCK_STALE_TIME=60

# Maximum cli params supported by the system Currently
MAX_PARAMS=2

# Temporarily Turn On(1)/Off(0) ipBLOCKer for trouble-shooting
declare -i IPBLOCKER_DISABLED=0

declare -i ON=1
declare -i OFF=0

# 0 = OFF 1 = ON DO NOT CHANGE THE DEFAULT VALUES
declare -i CUSTOM_PROC_ON=0
declare -i WHITE_LIST_PROC=0

# Maximum length of a category
declare -i MAX_CATEGORY_LENGTH=14

TAR_CMD="tar -zxvOf"

# current date and time
TIME_NOW=$(date +"%Y%m%d-%H%M%S")

####
# Section: Commands and parameter options used in the system
# DO NOT CHANGE THE DEFAULT VALUES
####
[ -e  /proc/sys/kernel/hostname ] && DEVICE_NAME=$(cat /proc/sys/kernel/hostname) || DEVICE_NAME=""

CURLOPT="--show-error --retry $RETRIES --progress-bar"
WGETOPT="-q --show-progress --retry-connrefused --tries=$RETRIES --no-dns-cache --no-cache"
SORT_IPS_OPT='-n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'
SEDEXP='s/^[[:space:]]*//'
REMOVE_EMPTY_LINES='sed -i "/^$/d"'

DIFF_CMD_EXP="diff --suppress-common-lines "
DIFF_ADD_PATTERN="^>"
DIFF_DEL_PATTERN="^<"

IP_PATTERN=`echo "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"`
CIDR_PATTERN='[0-9]{1,3}(\.[0-9]{1,3}){0,3}/[0-9]+'
PVT_IP_PATTERN='(^10\.)|(^127\.)|(^169\.254\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)'
NUMBER_PATTERN='^[-+]?([0-9]+\.?|[0-9]*\.[0-9]+)$'
IP_RANGE_PATTERN="(([0-9]{1,3}\.){3}[0-9]{1,3})-(([0-9]{1,3}\.){3}[0-9]{1,3})"

ACCEPT_PROTO_PORTS='-p tcp -m multiport --sports 80,443'

IPSET_SAVE_FILE="$DIR_REFRESH/ipset.save"
IPTABLES_SAVE_FILE="$DIR_REFRESH/iptables.save"

IPTABLES_CHAIN_TAG='[cC]hain'
IPTABLES_SET_TAG='[sS]et'

IPSET_VERSION=$(ipset -v 2> /dev/null | grep -oE "ipset v[0-9]")

MATCH_SET=''; HASH_IP=''; HASH_NET=''; CREATE=''; SWAP=''; DESTROY='';
FLUSH='';     ADD='';     DELETE='';   SAVE='';   LIST=''; TEST='';
RESTORE=''    COMMENT=''; OPTIONAL='';

[[ "$IPSET_VERSION" == *"v6"* ]] && \
{
  MATCH_SET='--match-set';
  HASH_IP='hash:ip';
  HASH_NET='hash:net';
  CREATE='create';
  SWAP='swap';
  DESTROY='destroy';
  FLUSH='flush';
  ADD='add';
  DELETE='del';
  SAVE='save';
  LIST='list';
  TEST='test';
  RESTORE='restore'
  COMMENT='comment';
  OPTIONAL="family inet hashsize 2048 maxelem $MAX_ENTRIES";
}

[[ "$IPSET_VERSION" == *"v4"* ]] && \
{
  MATCH_SET='--set';
  HASH_IP='iphash';
  HASH_NET='nethash';
  CREATE='--create';
  SWAP='--swap';
  DESTROY='--destroy';
  FLUSH='--flush';
  ADD='--add';
  DELETE='--del';
  SAVE='--save';
  LIST='--list';
  TEST='--test';
  RESTORE='--restore';
  COMMENT='--comment';
  OPTIONAL='';
}

declare -a IPV4_MODULES=(
  "ipt_set"
  "ip_set"
  "ip_set_nethash"
  "ip_set_iphash"
)

declare -a IPV6_MODULES=(
  "xt_set"
  "ip_set"
  "ip_set_hash_net"
  "ip_set_hash_ip"
)

BUCKETS_TAG="buckets"
FIREWALL_TAG="firewall"

IPSET_SAVE="ipset $SAVE"
IPTABLES_SAVE="iptables-save -c"

IPSET_RESTORE="ipset $RESTORE"
IPTABLES_RESTORE="iptables-restore -c"

IPSET_SAVE_CMD="$IPSET_SAVE             > $IPSET_SAVE_FILE    &"
IPTABLES_SAVE_CMD="$IPTABLES_SAVE       > $IPTABLES_SAVE_FILE"

IPSET_RESTORE_CMD="$IPSET_RESTORE       < $IPSET_SAVE_FILE    2> /dev/null &"
IPTABLES_RESTORE_CMD="$IPTABLES_RESTORE < $IPTABLES_SAVE_FILE 2> /dev/null"

IPBLOCKER_OFF_CMD="grep -v $BLOCK_APPLN_TAG $IPTABLES_SAVE_FILE | $IPTABLES_RESTORE > /dev/null 2>&1 || EXIT_CODE=$EXIT_ALERT"

ALL="all"
NONE="none"
declare -i SHOW_ALL=1

####
# Section: Seeding Cron Jobs default values
####
declare -A REFRESH_SCHEDULE=()
REFRESH_SCHEDULE["$ADWARE_TAG"]="0 8 * * *"
REFRESH_SCHEDULE["$COUNTRY_TAG"]="0 12 * * 3"
REFRESH_SCHEDULE["$ETF_TAG"]="45 */8 * * *"
REFRESH_SCHEDULE["$MALWARE_TAG"]="0 9 * * *"
REFRESH_SCHEDULE["$SHALLA_TAG"]="30 9 * * *"
REFRESH_SCHEDULE["$SPAM_TAG"]="0 10 * * *"
REFRESH_SCHEDULE["$TOR_EXITS_TAG"]="30 10 * * *"
REFRESH_SCHEDULE["$ALL"]="0 16 * * *"

declare -i FIREWALL_ENABLE_VALUE=1
FIREWALL_CHECK_CMD="nvram get fw_enable_x 2> /dev/null | grep -qwx $FIREWALL_ENABLE_VALUE"
FIREWALL_ENABLE_CMD="nvram set fw_enable_x=$FIREWALL_ENABLE_VALUE"
CONFIRM_CONFIG_CMD="nvram commit"

PACKET_LOGGING_ENABLE_VALUE="both"
PACKET_LOGGING_CHECK_CMD="nvram get fw_log_x 2> /dev/null | grep -qwx $PACKET_LOGGING_ENABLE_VALUE"
PACKET_LOGGING_ENABLE_CMD="nvram set fw_log_x=$PACKET_LOGGING_ENABLE_VALUE"

PACKAGE_NAME="Entware-ng"
PACKAGE_INSTALL_CMD="opkg"
PACKAGE_INSTALL_OPTION="install"
PACKAGE_INSTALL_LOCATION="/opt/bin"

declare -a coreFails=() packageFails=() ipArray=() cidrArray=() webArray=() fndIpArray=()
declare -a CORE_DEPENDS=(
    "awk"
    "curl"
    "cut"
    "crontab"
    "free"
    "insmod"
    "ipset"
    "iptables"
    "iptables-save"
    "lsmod"
    "logger"
    "modprobe"
    "sed"
    "tee"
    "touch"
    "tr"
    "wc"
)

declare -a PACKAGE_DEPENDS=(
   "bash"
   "diff"
   "grep"
   "opkg"
   "sort"
   "split"
   "xargs"
)

# Display Width
declare -i COLUMNS=12

####
# Section: Text and Color Terminal Codes
# DO NOT CHANGE THE DEFAULT VALUES
####

# Formating text
BOLD_BRIGHT='\033[1m'
DIM='\033[2m'
UNDERLINED='\033[4m'
BLINK='\033[5m'
INVERSE='\033[7m'
HIDDEN='\033[8m'

# Reset all attributes
RESET='\033[0m'

# Color Codes for Text
BLACK='\033[30m'
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
MAGENTA='\033[35m'
CYAN='\033[36m'
LIGHTGREY='\033[37m'
DEFAULT='\033[39m'
WHITE='\033[97m'


# Color Codes for Background
DEFAULT_BG='\033[49m'
BLACK_BG='\033[40m'
RED_BG='\033[41m'
GREEN_BG='\033[42m'
YELLOW_BG='\033[43m'
BLUE_BG='\033[44m'
MAGENTA_BG='\033[45m'
CYAN_BG='\033[46m'
WHITE_BG='\033[107m'

APP_BANNER=""$DEFAULT"ip"$RED"BLOCK"$RESET""$DEFAULT"er"$RESET""

# Unicode Check Mark (U+2713) in Hex
CHECK_MARK="\xE2\x9C\x93"

####
# Section: Seeding categories and category filters with default Values
# The values below CAN BE changed as per requirement
# Recommended to leave the default as they are
# Run ipBLOCKer setup
# Change the values per requirement in the seeded filters in filters directory
####
declare -a CATEGORY_LIST_ARRAY=(
  "$ADWARE_TAG"
  "$COUNTRY_TAG"
  "$ETF_TAG"
  "$MALWARE_TAG"
  "$SHALLA_TAG"
  "$SPAM_TAG"
  "$TOR_EXITS_TAG"
)

declare -a CATEGORY_LIST_SELECTED_ARRAY=("${CATEGORY_LIST_ARRAY[@]-}")

# Countries List
declare -a COUNTRY_FILTERS_ARRAY=(
  "http://www.ipdeny.com/ipblocks/data/countries/br.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/lv.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/md.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/kp.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/ng.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/pk.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/pe.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/ph.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/ro.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/es.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/tw.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/th.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/tr.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/ua.zone"
  "http://www.ipdeny.com/ipblocks/data/countries/vn.zone"
)

# Default seeded Shalla Categories we are interested in
declare -a SHALLA_CATEGORIES_LIST_ARRAY=(
  "adv"
  "spyware"
  "tracker"
)

declare -a SHALLA_FILTERS_ARRAY=(
  "http://www.shallalist.de/Downloads/shallalist.tar.gz"
)

declare -a MALWARE_FILTERS_ARRAY=(
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/openbl_all.ipset"
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/threatcrowd.ipset"
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/myip.ipset"
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de.ipset"
  "https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt"
  "https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt"
  "https://zeustracker.abuse.ch/blocklist.php?download=badips"
  "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist"
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/alienvault_reputation.ipset"
  "https://www.malwaredomainlist.com/hostslist/ip.txt"
  "http://www.abuseat.org/iotcc.txt"
)

declare -a TOR_EXITS_FILTERS_ARRAY=(
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/et_tor.ipset"
)

declare -a ADWARE_FILTERS_ARRAY=(
  "https://pgl.yoyo.org/as/iplist.php"
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/hphosts_ats.ipset"
)

declare -a SPAM_FILTERS_ARRAY=(
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset"
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_edrop.netset"
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webclient.netset"
)

declare -a ETF_FILTERS_ARRAY=(
  "http://www.talosintelligence.com/feeds/ip-filter.blf"
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/snort_ipfilter.ipset"
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/shunlist.ipset"
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/malc0de.ipset"
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bruteforceblocker.ipset"
  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield_30d.netset"
)

####
# Section: Seeding custom and white-list refreshes with default values
# The values below CAN BE changed as per requirement
###
declare -a CUSTOM_REFRESH_TEMP_ARRAY=(
  "40.77.226.250"
  "64.4.54.22"
  "85.25.43.94"
  "85.25.103.50"
  "104.16.49.93"
  "104.16.50.93"
  "104.16.51.93"
  "104.16.52.93"
  "104.16.53.93"
  "104.96.4.198"
  "104.131.0.69"
  "114.80.68.223"
  "131.253.14.153"
  "134.170.115.60"
  "157.56.96.58"
  "172.217.23.230"
  "172.217.23.238"
  "185.52.170.10"
  "185.52.170.25"
  "188.138.9.50"
  "198.20.99.130"
  "207.68.166.254"
  "209.126.110.38"
  "216.58.201.98"
  "216.58.201.104"
  "216.58.203.228"
  "216.117.2.180"
)

declare -a WHITE_LIST_REFRESH_TEMP_ARRAY=(
  "23.21.77.86"
  "54.235.135.158"
  "64.78.193.234"
  "72.21.81.200"
  "72.21.91.29"
  "72.21.206.80"
  "87.248.114.12"
  "87.248.116.11"
  "87.248.116.12"
  "88.198.26.2"
  "93.184.220.29"
  "93.184.221.133"
  "93.184.221.200"
  "104.16.104.123"
  "104.16.105.123"
  "104.16.106.123"
  "104.16.107.123"
  "104.16.108.123"
  "104.24.31.113"
  "109.201.134.51"
  "140.211.11.105"
  "151.101.1.34"
  "151.101.65.34"
  "151.101.129.34"
  "151.101.193.34"
  "173.194.66.100"
  "173.194.66.101"
  "173.194.66.102"
  "173.194.66.113"
  "173.194.66.138"
  "192.0.79.32"
  "192.0.79.33"
  "213.230.210.230"
  "216.239.34.10"
  "217.12.15.37"
)
