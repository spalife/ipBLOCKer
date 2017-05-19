#!/usr/bin/env bash
################################################################################
# ipBLOCKer blocks IP's & CIDR's tagged as
# Malware/ETF/Spam/Tor-Exits/Shalla/Adware/Country/Custom
#
# Recommendations::
# - Install the program on a attached USB drive
# - Define IPBLOCKER_DIR in .profile or .bash_profile
#   Example :
#   IPBLOCKER_DIR=/tmp/mnt/USBDRIVE1/ipBLOCKer
################################################################################
set   -u
shopt -s extglob
shopt -u huponexit

IPBLOCKER_DIR="${IPBLOCKER_DIR:-$PWD}"; IPBLOCKER_DIR="${IPBLOCKER_DIR%/}";
[ ! -f "$IPBLOCKER_DIR/includes_ipBLOCKer.sh" ]          && \
{ echo "ABORT: includes_ipBLOCKer.sh file not found. Exiting ...."; exit 3; } || \
source "$IPBLOCKER_DIR/includes_ipBLOCKer.sh"

[ ! -f "$IPBLOCKER_DIR/flib_ipBLOCKer.sh" ] && \
{ echo "ABORT: flib_ipBLOCKer.sh file not found. Exiting ....";     exit 3; } || \
source "$IPBLOCKER_DIR/flib_ipBLOCKer.sh";

[ -f "$IPBLOCKER_CONFIG" ] && source "$IPBLOCKER_CONFIG"

[ $# -gt $MAX_PARAMS ]     && { echo -e "ERROR: $APP_BANNER too many parameters"; echo; exit 1; }

# 0 = OFF 1 = ON
option1="${1:-}"
option2="${2:-}"
optHelp=$OFF   optCheck=$OFF     optSetup=$OFF     optStatus=$OFF optRefresh=$OFF
optCustom=$OFF optWhiteList=$OFF optUninstall=$OFF optAdd=$OFF    optDelete=$OFF
optBackup=$OFF optRestore=$OFF   optVersion=$OFF
optOff=$OFF    optOn=$OFF        optSynch=$OFF
optSynchAll=$OFF
selectedCategory="" reply="" lst=""
SYSTEM_MAX_ENTRIES=$MAX_ENTRIES*$MAX_BUCKETS

ipArray=() fndIpArray=() cidrArray=() webArray=()

prgName=$(basename ${0})

# Display program options
usage ()
{
    echo
    echo -e "$APP_BANNER blocks IPs & CIDRs"
    echo "tagged as Adware Country Custom ETF Malware Shalla(exp) Spam Tor-Exits"
    echo
    echo "Usage: $prgName [option] [parameter]"
    echo "   Ex: $prgName status; $prgName refresh; $prgName add white-list;"
    echo "   Ex:        $ALIAS_NAME status;        $ALIAS_NAME refresh;        $ALIAS_NAME add white-list;"
    echo
    echo "    Options:"
    echo "      help : Shows      this help"
    echo "     setup : Configures ipBLOCKer"
    echo "    status : Shows      Status"
    echo "   refresh : Refreshes  Categories with Updates"
    echo "       add : Adds       IPs and CIDRs to     a Category"
    echo "    delete : Deletes    IPs and CIDRs from   a Category"
    echo "     check : Checks     IPs and CIDRs are blocked by ipBLOCKer"
    echo "    backup : Backsup    System"
    echo "   restore : Restores   System from backup"
    echo "       off : Turns      OFF ipBLOCKer temporarily"
    echo "        on : Turns      ON ipBLOCKer"
    echo "     synch : Restores   Missing ipBLOCKer Firewall rules      (trouble-shooting)"
    echo " synch_all : Restores   Firewall and Buckets from saved state (trouble-shooting)"
    echo " uninstall : Removes    ipBLOCKer (all) or a Category"
    echo "   version : Shows      Version Information"
    echo
}

# Display program help information
help       () { usage; exit $EXIT_NORMAL; }

version    () { echo -e "$APP_BANNER Version: $VERSION"; echo; exit $EXIT_NORMAL; }

# Create required directories/filters/files
setup      ()
{
  menu_setup "Setup Menu"
  printf "%-80s" "Please wait applying changes ....."
  update_config; [ $EXIT_CODE -ne $EXIT_NORMAL ] && printf "Error: $EXIT_CODE" || printf "$EXIT_MESSAGE"
  [ -f $IPBLOCKER_CONFIG ] && source $IPBLOCKER_CONFIG
  printf "\b%.0s" {1..80}

  return $EXIT_CODE
}

# Print Categorywise status
status     () { show_status;    return $EXIT_CODE; }

# Refresh configured Filters
refresh    ()
{
  #log "Refresh $CATEGORIES_TAG: Started"
  EXIT_CODE=$EXIT_NORMAL

  [ -z "$option2" ] && cli_select_category "Refresh Menu" || selectedCategory=$option2
  case $selectedCategory in
       "$NONE") return $EXIT_CODE
                ;;
       "$ALL")  for lst in $(cat "$CATEGORY_LIST" 2> /dev/null)
                do
                   refresh_filters_and_categories  $lst
                done
                custom_or_white_list               $CUSTOM_TAG
                status
                ;;
       "$CUSTOM_TAG"|"$WHITE_LIST_TAG")
                custom_or_white_list               $selectedCategory
                ;;
       *)       is_valid_category                  $selectedCategory
                [ $EXIT_CODE -ne $EXIT_NORMAL ] && return $EXIT_CODE
                refresh_filters_and_categories     $selectedCategory
                custom_or_white_list               $WHITE_LIST_TAG
                #remove_category_from_category $WHITE_LIST_TAG $selectedCategory
                ;;
  esac
  save_net_filters

  #printf "Refresh $EXIT_MESSAGE\n" | log
  return $EXIT_CODE
}

# Refresh custom and white-list categories
custom_or_white_list    ()
{
  refresh_custom_white_list "$1";
  #remove_category_from_category $WHITE_LIST_TAG "$1"
  return $EXIT_CODE;
}

# Add User specified IP's & CIDR's to a category
add_delete ()
{
  local menuT="Delete from"
  local addDel="${1:-}";  [ $addDel -eq 1 ] && { SHOW_ALL=$OFF; menuT="Add to"; }
  EXIT_CODE=$EXIT_NORMAL

  [ -z "$option2" ] && cli_select_category "$menuT a Category Menu" || selectedCategory=$option2

  [ "$selectedCategory" == "$NONE" ] && return $EXIT_CODE
  is_valid_category   $selectedCategory; [ $EXIT_CODE -ne $EXIT_NORMAL ] && return $EXIT_CODE

  cli_add_del_ip_cidr $selectedCategory $addDel
  save_net_filters
  SHOW_ALL=$ON

  return $EXIT_CODE
}

# Checks ip/cidr in ipBLOCKer
check      () { cli_check;  return $EXIT_CODE; }

# Backups System and Configuration
backup     ()
{
  printf "%-60b" "Please wait backing up $APP_BANNER"
  # wait for Background Processes to complete
  #wait
  backup_system; [ $EXIT_CODE -ge $EXIT_ALERT ]       && printf " Error: $EXIT_CODE" || printf ".... $EXIT_MESSAGE"
  echo;echo;

  return $EXIT_CODE
}

# Restores System and Configuration from Backup
restore    ()
{
  printf "%-60b" "Please wait restoring $APP_BANNER"
  restore_from_backup; [ $EXIT_CODE -ge $EXIT_ALERT ] && printf " Error: $EXIT_CODE" || printf ".... $EXIT_MESSAGE"
  echo;echo;

  return $EXIT_CODE
}

unInstall  ()
{
  EXIT_CODE=$EXIT_NORMAL

  [ -z "$option2" ] && cli_select_category "Uninstall Menu" || selectedCategory=$option2
  case $selectedCategory in
       "$NONE") return $EXIT_CODE ;;
       *)       is_valid_category $selectedCategory
                [ $EXIT_CODE -eq $EXIT_NORMAL ] && un_install $selectedCategory ;;
  esac

  return $EXIT_CODE
}

# Temporarily turn off ipBLOCKer for trouble-shooting
off      ()
{
  EXIT_CODE=$EXIT_NORMAL

  eval "${IPBLOCKER_OFF_CMD}";
  IPBLOCKER_DISABLED=$ON
  echo;echo -e "$APP_BANNER is switched OFF.";echo;
  replace_config $IPBLOCKER_CONFIG "IPBLOCKER_DISABLED=$OFF" "IPBLOCKER_DISABLED=$ON";

  exit $EXIT_CODE
}

# Temporarily turn off ipBLOCKer for trouble-shooting
on      ()
{
  EXIT_CODE=$EXIT_NORMAL

  eval "${IPTABLES_RESTORE_CMD}";
  IPBLOCKER_DISABLED=$OFF
  echo;echo -e "$APP_BANNER is switched ON.";echo;
  replace_config $IPBLOCKER_CONFIG "IPBLOCKER_DISABLED=$ON" "IPBLOCKER_DISABLED=$OFF";

  exit $EXIT_CODE
}

cleanup ()
{
  remove_remnants;
  clear_caches;
  trap - $SIG_HUP $SIG_INT $SIG_QUIT $SIG_TERM EXIT

  return $EXIT_CODE;
}

# Restores buckets
synch      ()  { synch_net_filters;       return $EXIT_CODE; }

# Restores buckets and firewall rules from saved state
synch_all  ()  { synch_all_net_filters;   return $EXIT_CODE; }

check_simultaneous_run ()
{
  declare -i ctr=0

  while [ -f "$LOCK_FILE" ] && kill -0 $(cat "$LOCK_FILE") 2> /dev/null
  do
    printf "%-80b" "ALERT: $APP_BANNER another instance running. CTRL+C to Cancel. Waiting: $ctr ...."
    printf "\b%.0s" {1..80}

    [ $ctr -ge $WAIT_TIME ] && \
    {
      printf "%-80b" "ABORT: $APP_BANNER another instance still running. Waited Seconds: $WAIT_TIME ....     \n\n";
      printf "\b%.0s" {1..80};
      exit $EXIT_ABORT;
    }
    sleep 1; ctr+=1;
  done
}

system_check; [ $EXIT_CODE -eq $EXIT_ABORT ] && exit $EXIT_CODE

case $option1 in
     ?(-)?(-)help)         optHelp=$ON      ;;
     ?(-)?(-)setup)        optSetup=$ON     ;;
     ?(-)?(-)status)       optStatus=$ON    ;;
     ?(-)?(-)refresh)      optRefresh=$ON   ;;
     ?(-)?(-)add)          optAdd=$ON       ;;
     ?(-)?(-)del?(ete))    optDelete=$ON    ;;
     ?(-)?(-)check)        optCheck=$ON     ;;
     ?(-)?(-)backup)       optBackup=$ON    ;;
     ?(-)?(-)restore)      optRestore=$ON   ;;
     ?(-)?(-)off)          optOff=$ON       ;;
     ?(-)?(-)on)           optOn=$ON        ;;
     ?(-)?(-)synch)        optSynch=$ON     ;;
     ?(-)?(-)synch_all)    optSynchAll=$ON  ;;
     ?(-)?(-)un[iI]nstall) optUninstall=$ON ;;
     ?(-)?(-)version)      optVersion=$ON   ;;
     *) usage; echo -e "$RED"Invalid Option"$RESET"; echo; exit $EXIT_ALERT ;;
esac


(( $optHelp ))        && help
(( $optVersion ))     && version

trap cleanup $SIG_HUP $SIG_INT $SIG_QUIT $SIG_TERM EXIT

clear_caches
check_simultaneous_run
echo $$ >> "$LOCK_FILE"

printf "%-60b" "Option: $option1 $option2\n"
printf "\b%.0s" {1..60}

check_setup_config; [ $EXIT_CODE -eq $EXIT_ABORT ] && exit $EXIT_CODE

(( $optOff ))         && off
(( $optOn ))          && on

(( $IPBLOCKER_DISABLED )) && \
{
  echo;echo -e "$APP_BANNER is switched OFF. Turn it ON to continue ....";echo;
  exit $EXIT_ABORT;
}

# To support users who have not subscribed to any categories
# Check is included here.
# Users can use ipBLOCKer with minimal setup custon and white-list
# till they decide which categories they want to subscribe to
(( ! $optSynchAll )) && \
{
  check_setup_restore_buckets;
  check_setup_restore_firewall;
}

(( $optSetup ))       && setup

categories_subscribed
if [ $EXIT_CODE -eq $EXIT_NORMAL ]
then
  system_setup; [ $EXIT_CODE -eq $EXIT_ABORT ] && exit $EXIT_CODE
else
  log "ALERT: $CATEGORIES_TAG not selected. Select $CATEGORIES_TAG in Setup Menu ....";
fi

(( $optStatus ))      && status
(( $optRefresh ))     && refresh
(( $optAdd ))         && add_delete 1
(( $optDelete ))      && add_delete 0
(( $optCheck ))       && check
(( $optBackup ))      && backup
(( $optRestore ))     && restore
(( $optSynch ))       && synch
(( $optSynchAll ))    && synch_all
(( $optUninstall ))   && unInstall

#cleanup
printf "\n"
printf "\nOption: $option1 $option2 .... $EXIT_MESSAGE\n"

exit $EXIT_CODE
