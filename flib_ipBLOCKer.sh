#!/usr/bin/env bash
################################################################################
# Contains System Function Library.
# Any changes here will modify system onfiguration and behaviour
# CAUTION Advised.
# Make changes through Menu's or through CLI
################################################################################
####
# Refresh ipBLOCKer filters
# Parameters Expected
# $1 = ipBLOCKer Filter Name  ex: malware
####
refresh_filters ()
{
   local filterName="${1:-}" filterFile="" outputFile="" tempFile="" sortFile="" diffFile=""
   local cidrOutputFile="" cidrTempFile="" cidrSortFile="" cidrDiffFile=""
   declare -i downIps=0 ctr=0

   filterFile="$DIR_FILTERS/$filterName$FILTER_FILE_EXT"
   outputFile="$DIR_REFRESH/$filterName$REFRESH_FILE_EXT"
   cidrOutputFile="$DIR_REFRESH/$filterName$CIDR_FILE_EXT"
   tempFile="$outputFile$TEMP_FILE_EXT"
   sortFile="$outputFile$SORT_FILE_EXT"
   diffFile="$outputFile$DIFF_FILE_EXT"
   cidrTempFile="$cidrOutputFile$TEMP_FILE_EXT"
   cidrSortFile="$cidrOutputFile$SORT_FILE_EXT"
   cidrDiffFile="$cidrOutputFile$DIFF_FILE_EXT"
   EXIT_CODE=$EXIT_NORMAL

   printf "%-40s %-10s" "Processing" ":: $filterName ::" | log

   if [ ! -f "$filterFile"  -a  $CUSTOM_PROC_ON -eq 0 ]
   then
      printf "ABORT: Refresh Filters File Not Found. Cannot continue ...." | log
      touch "$diffFile" "$cidrDiffFile"
      EXIT_CODE=$EXIT_ABORT
      return $EXIT_CODE
   fi

   if [ $CUSTOM_PROC_ON -eq 0 ]
   then
     rm -rf $outputFile.* $cidrOutputFile.*
     xargs -E END -n1 -a"$filterFile" curl $CURLOPT > "$tempFile"
   else
     # NOT Custom First Run. Subsequent Runs, extract custom data from ipset
     if [ ! -f "$tempFile" ]
     then
       ctr=1
       for letter in $(echo {a..z})
       do
         ctr+=1
         ipset $LIST $BLOCK_APPLN_TAG"-""$filterName"$letter          2>/dev/null | grep -oE "$IP_PATTERN"   >> "$tempFile"
         ipset $LIST $BLOCK_APPLN_TAG"-""$filterName"$CIDR_TAG$letter 2>/dev/null | grep -oE "$CIDR_PATTERN" >> "$tempFile"
         [ $ctr -gt $MAX_BUCKETS ] && break
       done
     fi
   fi

   # Check if the refreshed filter is a Shalla tar file
   [ "$filterName" == "$SHALLA_TAG" ] && extract_categories_shalla $filterName

   downIps=$(wc -l "$tempFile" 2> /dev/null | awk '{print $1}')
   #printf "%-40s %-10s" "Total Downloaded IP's & CIDR's:" $downIps | log

   if [ $EXIT_CODE -ne $EXIT_NORMAL -o $downIps -le 0 ]
   then
     #printf "ALERT: Refreshed Filters Empty" | log
     touch "$diffFile" "$cidrDiffFile";
     return $EXIT_CODE;
   fi

   printf "%-60s" "Please wait processing downloads ...."
   printf "\b%.0s" {1..60}

   # Extract CIDR Ranges from refreshed file
   grep -oE "$CIDR_PATTERN" "$tempFile" | grep -vE "$PVT_IP_PATTERN" | sort $SORT_IPS_OPT -o        "$cidrSortFile"

   # Remove CIDR + LOCAL IP Ranges & Grab ONLY IP's from refreshed file
   grep -vE "$CIDR_PATTERN" "$tempFile" | grep -oE "$IP_PATTERN"     | grep -vE "$PVT_IP_PATTERN" > "$sortFile"

   # Compare and Split the refreshed with the present
   compare_split "$outputFile"     $IP_TAG
   compare_split "$cidrOutputFile" $CIDR_TAG

   #log "END Refresh Filters: $filterFile"
   return $EXIT_CODE
}

extract_categories_shalla ()
{
  local filterName="${1:-}" outputFile="" tempFile="" shallaTempFile="" catName="" catList=""
  declare -i ctr=0

  # For Shalla create a shalla.txt file to hold the categories to extract from the tar file
  outputFile="$DIR_REFRESH/$filterName$REFRESH_FILE_EXT"
  tempFile="$outputFile$TEMP_FILE_EXT"
  shallaTempFile="$tempFile$TEMP_FILE_EXT"
  EXIT_CODE=$EXIT_NORMAL

  rm -rf "$shallaTempFile";
  [ ! -f "$SHALLA_CATEGORY_LIST" ] &&
  { printf "ABORT: $SHALLA_TAG file not found. Please run Setup ...." | log;
    EXIT_CODE=$EXIT_ABORT; return $EXIT_CODE; }

  for catName in $(cat "$SHALLA_CATEGORY_LIST" 2> /dev/null)
  do
    catList=$SHALLA_DIR_TAG"/"$catName"/"$SHALLA_DOMAINS_TAG

    #log "Extracting $catList from $tempFile to $shallaTempFile"
    $TAR_CMD "$tempFile" "$catList" | grep -oE $IP_PATTERN >> "$shallaTempFile"
  done

  # Overwrite the refreshed tempFile (tar arhive) with extracted domain ips from shella temp file
  mv "$shallaTempFile" "$tempFile" 2> /dev/null

  #log "END Processing $filterName"
  return $EXIT_CODE
}

compare_split ()
{
   local outputFile="${1:-}" tag="${2:-}" sortFile="" diffFile="" grabExpr=""
   declare -i addIps=0 sortIps=0 diffIps=0 firstRun=0

   sortFile="$outputFile$SORT_FILE_EXT"
   diffFile="$outputFile$DIFF_FILE_EXT"
   EXIT_CODE=$EXIT_NORMAL

   #log "START $tag's CompareSplit: $outputFile"
   [ ! -f "$outputFile" ] && { touch "$outputFile"; firstRun=1; }

   printf "%-60s" "Please wait deduplication underway ...."
   printf "\b%.0s" {1..60}

   sort $SORT_IPS_OPT "$sortFile"   -o "$sortFile"
   sort $SORT_IPS_OPT "$outputFile" -o "$outputFile"

   sortIps=$(wc -l "$sortFile"  2> /dev/null | awk '{print $1}')
   addIps=$(wc -l "$outputFile" 2> /dev/null | awk '{print $1}')

   printf "%-40s %-10s" "Total Downloaded & Deduplicated $tag's:" $sortIps | log
   printf "%-40s %-10s" "Total Existing $tag's:"                   $addIps | log

   case "$tag" in
       "$IP_TAG") grabExpr=$IP_PATTERN   ;;
     "$CIDR_TAG") grabExpr=$CIDR_PATTERN ;;
               *) EXIT_CODE=$EXIT_ERROR; return $EXIT_CODE; ;;
   esac

   printf "%-60s" "Please wait estimating Incremental $REFRESH_TAG ...."
   printf "\b%.0s" {1..60}

   if [ $CUSTOM_PROC_ON -eq 0  -o  $firstRun -gt 0 ]
   then
      $DIFF_CMD_EXP "$outputFile" "$sortFile" | grep $DIFF_ADD_PATTERN | grep -oE $grabExpr > "$diffFile"
   else
      $DIFF_CMD_EXP "$sortFile" "$outputFile" | grep $DIFF_ADD_PATTERN | grep -oE $grabExpr > "$diffFile"
   fi

   sort $SORT_IPS_OPT "$diffFile" -o "$diffFile"

   diffIps=$(wc -l "$diffFile" 2> /dev/null | awk '{print $1}')
   [ $diffIps -gt 0 ] && \
   { printf "%-40s %-10s" "Incremental $REFRESH_TAG $tag's:" $diffIps | log; }

   if [ $diffIps -gt $MAX_ENTRIES ]
   then
      printf "%-40s %-10s" "SPLITING $tag's Exceed MAX_ENTRIES:" "$diffIps gt $MAX_ENTRIES" | log
      split -a1 -l$MAX_ENTRIES "$diffFile" "$diffFile"
   fi

   [ $diffIps -gt $SYSTEM_MAX_ENTRIES ] && \
   { printf "%-40s %-10s" "ALERT: System Limit Entries: $SYSTEM_MAX_ENTRIES ignore:" "$((diffIps-SYSTEM_MAX_ENTRIES))" | log; }

   #log "END $tag's CompareSplit: $outputFile"
   return $EXIT_CODE
}

# Refresh Categories with refreshed filters
refresh_categories ()
{
  local categoryName="${1:-}" diffFile="" errorFile="" dExt="" tag=""
  declare -i ctr=0 addIps=0 errCnt=0

  for tag in $IP_TAG $CIDR_TAG
  do
    [ "$tag" == "$IP_TAG" ]   && { dExt=$REFRESH_FILE_EXT; }
    [ "$tag" == "$CIDR_TAG" ] && { dExt=$CIDR_FILE_EXT;    }

    printf "%-60s" "Please wait $REFRESH_TAG $tag $CATEGORIES_TAG will begin ...."
    printf "\b%.0s" {1..60}

    diffFile="$DIR_REFRESH/$categoryName$dExt$DIFF_FILE_EXT"
    errorFile="$DIR_REFRESH/$categoryName$dExt$ERROR_FILE_EXT"

    EXIT_CODE=$EXIT_NORMAL
    [ ! -f "$diffFile" ]                && { continue; }

    # Total Refresh Size to update categories
    addIps=$(wc -l "$diffFile" 2> /dev/null | awk '{print $1}')
    [ $addIps -le 0 ]                   && { EXIT_CODE=$EXIT_ERROR; continue; }
    [ $addIps -gt $SYSTEM_MAX_ENTRIES ] && { addIps=$SYSTEM_MAX_ENTRIES; }

    # Check if Refresh is split across files
    if [ $addIps -gt $MAX_ENTRIES ]
    then
      printf "%-40s %-10s" "Multi-Bucket-Refresh: " "ON" | log

      # Find Split Files to Refresh buckets
      ctr=0
      for letter in $(echo {a..z})
      do
        [ -f "$diffFile$letter" ] && { refresh_buckets $categoryName $diffFile$letter $tag; }
        ctr+=1; [ $ctr -ge $MAX_BUCKETS ] && break
      done
    else
      refresh_buckets $categoryName $diffFile $tag
    fi
    [ $EXIT_CODE -eq $EXIT_ALERT ] && \
    { printf "ALERT: Unable to Refresh ANY Buckets. Increase MAX_BUCKETS or uninstall and refresh\n" | log; }

    [ $EXIT_CODE -eq $EXIT_ERROR ] && \
    { errCnt=$(wc -l "$errorFile" 2> /dev/null | awk '{print $1}');
      [ $errCnt -gt 0 ] && \
      { printf "%-40s %-10s" "ERROR: Refreshing Buckets. Error $tag's:" "$errCnt/$addIps" | log; };
    }
  done

  [ -f "$errorFile" ] && sort $SORT_IPS_OPT "$errorFile" -o "$errorFile"
  #log "END Refresh Categories: $categoryName tag: $tag"
  return $EXIT_CODE
}

###
# Refresh buckets with updated filters
###
refresh_buckets ()
{
  local categoryName="${1:-}" ipsFile="${2:-}" tag="${3:-}"
  local outputFile="" errorFile=""
  local dExt="" grabExpr="" name="" elem="" nfCatg="" currentBucket="" ltr=""
  declare -i ctr=0 lCtr=0 added=0 changeBucket=0 addIps=0 totalAdded=0 errored=0 dummy=0
  declare -a buckets=() sizes=()

  printf "%-80s" "Please wait $REFRESH_TAG buckets will begin shortly ...."
  printf "\b%.0s" {1..80}

  #log "START Update Bucket: $categoryName Type: $tag"
  case "$tag" in
      "$IP_TAG") grabExpr=$IP_PATTERN
                 dExt=$REFRESH_FILE_EXT
                 nfCatg=$BLOCK_APPLN_TAG"-"$categoryName          ;;
    "$CIDR_TAG") grabExpr=$CIDR_PATTERN
                 dExt=$CIDR_FILE_EXT
                 nfCatg=$BLOCK_APPLN_TAG"-"$categoryName$CIDR_TAG ;;
              *) EXIT_CODE=$EXIT_ERROR; return $EXIT_CODE         ;;
  esac

  [ ! -f $ipsFile ]  && { EXIT_CODE=$EXIT_ALERT; return $EXIT_CODE; }

  # Total Refresh Size to update buckets
  addIps=$(wc -l "$ipsFile" 2> /dev/null | awk '{print $1}')
  [ $addIps -le 0 ]  && { EXIT_CODE=$EXIT_ALERT; return $EXIT_CODE; }

  outputFile="$DIR_REFRESH/$categoryName$dExt"
  errorFile="$outputFile$ERROR_FILE_EXT"

  clear_caches
  buckets=($(ipset $LIST | grep $nfCatg"[a-z]" | sort -u | awk {'print $2'}))

  ctr=0
  for name in ${buckets[@]-}
  do
    sizes[$ctr]=$(ipset $LIST $name 2> /dev/null | grep -oEc $grabExpr)
    ctr+=1
  done

  ctr=0
  for elem in $(cat "$ipsFile" 2> /dev/null)
  do
    currentBucket="${buckets[$ctr]-}"
    printf "%-80s" "Added: $totalAdded Errored: $errored Tasked: $addIps"

    [ -z "$currentBucket" ]                       && { changeBucket=1; }
    [[ ${sizes[$ctr]-}+$added -ge $MAX_ENTRIES ]] && { changeBucket=1; }
    [ $ctr -ge $MAX_BUCKETS ]                     && { break; }
    [ $totalAdded -ge $addIps ]                   && { break; }

    (( changeBucket )) && \
    {
      while true;
      do \
        changeBucket=0;added=0;
        ((ctr++))
        [ $ctr -ge ${#sizes[@]} ]   && \
        {
          [ ${#sizes[@]} -eq 0 ]    && { ((ctr--)); };
          [ $ctr -ge $MAX_BUCKETS ] && { break 2; };
          lCtr=0; ltr="";
          for letter in $(echo {a..z}); do ltr=$letter; lCtr+=1; [ $lCtr -gt $ctr ] && break; done;
          buckets[$ctr]=$nfCatg$ltr;
          sizes[$ctr]=$added;
          currentBucket="${buckets[$ctr]-}";
          printf "\b%.0s" {1..80}
          create_net_filters $currentBucket $tag;
          [ $EXIT_CODE -ne $EXIT_NORMAL ] && { log "ERROR: Creating Bucket: $currentBucket"; continue; };
        };
        [[ ${sizes[$ctr]-}+$added -ge $MAX_ENTRIES ]] && { continue; };
        break;
      done;
    };

    ipset $ADD $currentBucket $elem > /dev/null 2>&1
    [ $? -eq $EXIT_NORMAL ]                                   && \
    { echo $elem >> "$outputFile"; added+=1; totalAdded+=1; } || \
    { echo $elem >> "$errorFile";  errored+=1; }
    printf "\b%.0s" {1..80}

  done

  clear_caches

  EXIT_CODE=$EXIT_NORMAL
  [ $totalAdded -eq 0 ]       && { EXIT_CODE=$EXIT_ALERT; }
  [ $errored -gt 0 ]          && { EXIT_CODE=$EXIT_ERROR; }
  [ $totalAdded -ne $addIps ] && { EXIT_CODE=$EXIT_ERROR; }
  #[ $totalAdded -eq 0 ]       && { log "ALERT: Unable to Refresh ANY Buckets. Increase MAX_BUCKETS or uninstall and refresh"; EXIT_CODE=$EXIT_ALERT; }
  #[ $totalAdded -ne $addIps ] && { printf "%-40s %-10s" "ERROR: Refreshing Buckets. Added $tag's:" "$totalAdded/$addIps" | log; EXIT_CODE=$EXIT_ERROR; }
  #[ $errCnt -gt 0 ]           && { printf "%-40s %-10s" "ERROR: Refreshing Buckets. Error $tag's:" "$errored/$addIps"    | log; EXIT_CODE=$EXIT_ERROR; }
  #log "END Update Bucket: $categoryName Type: $tag"
  return $EXIT_CODE
}

remove_remnants ()
{
  local categoryName="" ipFile="" cidrFile=""
  declare -i ctr=0 cnt=0

  EXIT_CODE=$EXIT_NORMAL
  for categoryName in $(cat "$CATEGORY_LIST" 2> /dev/null) $CUSTOM_TAG $WHITE_LIST_TAG
  do
    ipFile="$DIR_REFRESH/$categoryName$REFRESH_FILE_EXT"
    cidrFile="$DIR_REFRESH/$categoryName$CIDR_FILE_EXT"

    rm -rf   $ipFile$TEMP_FILE_EXT*   $ipFile$SORT_FILE_EXT*   $ipFile$DIFF_FILE_EXT*
    rm -rf $cidrFile$TEMP_FILE_EXT* $cidrFile$SORT_FILE_EXT* $cidrFile$DIFF_FILE_EXT*
  done

  remove_lock_file_stales
  return $EXIT_CODE
}

# remove stale pids from the lock file
remove_lock_file_stales ()
{
  declare -i ctr=0 cnt=0 elem=0

  EXIT_CODE=$EXIT_NORMAL
  [ ! -f "$LOCK_FILE" ] && return $EXIT_CODE
  # Lock file exists even after hrs unusual!
  # kill the process if any and remove the file
  [ "$(find "$LOCK_FILE" -mmin +$LOCK_STALE_TIME 2> /dev/null)" ] && \
  {
    kill -$SIG_KILL $(cat "$LOCK_FILE") 2> /dev/null;
    rm -rf "$LOCK_FILE";
    return $EXIT_CODE;
  }

  # Well it exists and is not 2 hrs older,
  # remove stale Processes if any from file including self
  for elem in $(cat "$LOCK_FILE" 2> /dev/null)
  do
     EXIT_CODE=$EXIT_NORMAL
     kill -0 $elem 2> /dev/null || EXIT_CODE=$EXIT_ERROR
     [ $EXIT_CODE -eq $EXIT_ERROR -o $elem -eq $$ ] && \
     { replace_config "$LOCK_FILE" "$elem" ""; }
  done
  EXIT_CODE=$EXIT_NORMAL

  remove_blanks "$LOCK_FILE"

  cnt=$(wc -l "$LOCK_FILE" 2> /dev/null | awk '{print $1}')
  [ $cnt -le 0 ] && { rm -rf "$LOCK_FILE"; }

  return $EXIT_CODE
}

###
# Create Set to store ipBLOCKer IP's action=DROP or ACCEPT or RETURN or REJECT
###
create_net_filters ()
{
  local netFilterName="${1:-}" tag="${2:-$IP_TAG}"
  local action=""   portsProto="" setType="" pattern=""

  #log "START Create Net Filter: $netFilterName for: $tag pattern: $pattern"
  [ -z "$netFilterName" ] && \
  { printf "ABORT: Empty FireWall Chain/Rule/Bucket Name. Cannot continue ...." | log;
    EXIT_CODE=$EXIT_ABORT; return $EXIT_CODE; }

  EXIT_CODE=$EXIT_NORMAL
  case "$tag" in
      "$IP_TAG") setType=$HASH_IP;  pattern=$IP_PATTERN;   ;;
    "$CIDR_TAG") setType=$HASH_NET; pattern=$CIDR_PATTERN; ;;
              *) EXIT_CODE=$EXIT_ERROR; return $EXIT_CODE  ;;
  esac

  (( $WHITE_LIST_PROC )) && \
  { action=$ACCEPT_OR_RETURN; portsProto=$ACCEPT_PROTO_PORTS; } || \
  { action=$DROP_OR_REJECT;   portsProto=""; }

  iptables -L $netFilterName 2> /dev/null | grep -oEq "$IPTABLES_CHAIN_TAG $netFilterName"
  if [ $? -ne $EXIT_NORMAL ]
  then
     printf "%-40s %-10s" "CREATING $action Chain:" "$netFilterName" #| log
     printf "\b%.0s" {1..60}
     #log "CREATING Firewall Chain: $netFilterName for: $action"
     iptables -N $netFilterName
     iptables -A $netFilterName -m limit --limit 2/min -j LOG --log-prefix $netFilterName":"
     iptables -A $netFilterName -j $action
  fi

  # Check if set exists by testing it with a test value
  ipset $TEST $netFilterName $BUCKET_TEST_IP /dev/null 2>&1 | grep -Ewq "$NO_FIND_TAG"
  if [ $? -eq $EXIT_NORMAL ]
  then
    printf "%-40s %-10s" "CREATING $tag Bucket:" "$netFilterName"  #| log
    printf "\b%.0s" {1..60}

    ipset $CREATE $netFilterName $setType $OPTIONAL 2>/dev/null
    if [ $? -ne $EXIT_NORMAL ]
    then
        printf "%-40s %-10s" "ABORT: CREATING $tag Bucket:" "$netFilterName" | log
        EXIT_CODE=$EXIT_ABORT
        return $EXIT_CODE
    fi
  fi

  iptables -L FORWARD 2> /dev/null | grep -oEq "$IPTABLES_SET_TAG $netFilterName"
  if [ $? -ne $EXIT_NORMAL ]
  then
      #log "INSERTING Firewall Rule: $netFilterName"
      printf "%-40s %-10s" "INSERTING Firewall Rule:" "$netFilterName" #| log
      printf "\b%.0s" {1..60}
      iptables -I FORWARD $portsProto -m set $MATCH_SET $netFilterName src,dst -j $netFilterName
      EXIT_CODE=$EXIT_NORMAL
  fi

  #log "END Create Net Filters for : $netFilterName"
  return $EXIT_CODE
}

refresh_custom_white_list ()
{
  local tag="${1:-$CUSTOM_TAG}"
  CUSTOM_PROC_ON=1
  EXIT_CODE=$EXIT_NORMAL

  #log "START refresh_custom_white_list Processing $filterName"
  # Add User Defined Custom IP & CIDR's (Telemetry/Privacy/Custom IP/CIDR etc.,)
  [ "$tag" == "$CUSTOM_TAG" ] && { refresh_filters_and_categories $tag; }

  WHITE_LIST_PROC=1
  [ $EXIT_CODE -ne $EXIT_ABORT ] && refresh_filters_and_categories $WHITE_LIST_TAG
  [ $EXIT_CODE -ne $EXIT_ABORT ] && push_filter_to_top             $WHITE_LIST_TAG
  WHITE_LIST_PROC=0  CUSTOM_PROC_ON=0  EXIT_CODE=$EXIT_NORMAL

  #log "END refresh_custom_white_list Processing $filterName"
  return $EXIT_CODE;
}

push_filter_to_top ()
{
  local filterName="${1:-}" ipUpdateSet="" cidrUpdateSet="" ipChainName="" cidrChainName="" letter=""
  declare -i ctr=0

  #log "START Processing push_filter_to_top $filterName"
  (( ! PUSH_TO_TOP )) && return $EXIT_NORMAL

  ctr=1
  for letter in $(echo {a..z})
  do
    ctr+=1

    ipUpdateSet=$BLOCK_APPLN_TAG"-"$filterName"$letter"
    cidrUpdateSet=$BLOCK_APPLN_TAG"-"$filterName$CIDR_TAG$letter

    ipChainName=$ipUpdateSet
    cidrChainName=$cidrUpdateSet

    remove_insert_filter $ipUpdateSet   $ipChainName
    remove_insert_filter $cidrUpdateSet $cidrChainName

    [ $ctr -gt $MAX_BUCKETS ] && break
  done

  #log "END Processing push_filter_to_top $filterName"
  return $EXIT_CODE;
}

remove_insert_filter ()
{
  local filterName="${1:-}" chainName="${2:-}" portsProto=""

  EXIT_CODE=$EXIT_NORMAL

  #log "START Processing remove_insert_filter $filterName"
  (( $WHITE_LIST_PROC )) && portsProto=$ACCEPT_PROTO_PORTS

  iptables -L FORWARD | grep $filterName > /dev/null 2>&1 || EXIT_CODE=$EXIT_ERROR
  if [ $EXIT_CODE -eq $EXIT_NORMAL ]
  then
      iptables -D FORWARD $portsProto -m set $MATCH_SET $filterName src,dst -j $chainName
      iptables -I FORWARD $portsProto -m set $MATCH_SET $filterName src,dst -j $chainName
  fi

  #log "END Processing remove_insert_filter $filterName"
  return $EXIT_CODE;
}

# Refresh filters and sets for specified category filter
refresh_filters_and_categories ()
{
   local filterName="${1:-}" outputFile="" tempFile="" sortFile="" diffFile=""
   local cidrOutputFile="" cidrTempFile="" cidrSortFile="" cidrDiffFile=""

   outputFile="$DIR_REFRESH/$filterName$REFRESH_FILE_EXT"
   tempFile="$outputFile$TEMP_FILE_EXT"
   cidrOutputFile="$DIR_REFRESH/$filterName$CIDR_FILE_EXT"

   #log "START Custom Processing $filterName"
   (( CUSTOM_PROC_ON )) && \
   { is_refresh_ready $filterName; [ $EXIT_CODE -eq $EXIT_ABORT ] && return $EXIT_CODE; }

   # Refresh category filters
   EXIT_CODE=$EXIT_NORMAL
   clear_caches
   refresh_filters $filterName

   # Refresh Categories with filters
   EXIT_CODE=$EXIT_NORMAL
   clear_caches
   refresh_categories $filterName

   #log "END Custom Processing $filterName"
   return $EXIT_CODE
}

check_setup_restore_buckets ()
{
  printf "%-80s" "Check $BUCKETS_TAG need to be restored ...."
  printf "\b%.0s" {1..80}

  declare -i bucketCnt=0 catgCnt=0
  EXIT_CODE=$EXIT_NORMAL

  bucketCnt=$(ipset -L 2> /dev/null | grep $BLOCK_APPLN_TAG | wc -l)
  catgCnt=$(wc -l "$CATEGORY_LIST" 2> /dev/null | awk '{print $1}')

  # if buckets count is less than category count, restore from saved state
  [[ $bucketCnt -lt $catgCnt ]] && { synch_all_net_filters "$BUCKETS_TAG"; }

  return $EXIT_CODE
}

check_setup_restore_firewall ()
{
  printf "%-80s" "Check $FIREWALL_TAG needs to be restored ...."
  printf "\b%.0s" {1..80}

  declare -i fwCnt=0 catgCnt=0
  EXIT_CODE=$EXIT_NORMAL

  fwCnt=$(iptables -L FORWARD 2> /dev/null | grep $BLOCK_APPLN_TAG | wc -l)
  catgCnt=$(wc -l "$CATEGORY_LIST" 2> /dev/null | awk '{print $1}')

  # if firewall count is less than category count, restore from saved state
  [[ $fwCnt -lt $catgCnt ]] && { synch_all_net_filters "$FIREWALL_TAG"; }

  return $EXIT_CODE
}

check_setup_config ()
{
  #log "START Check Config"
  [ ! -f "$IPBLOCKER_CONFIG" ]    && touch "$IPBLOCKER_CONFIG" 2> /dev/null
  [ ! -f "$IPBLOCKER_CONFIG" ]    && EXIT_CODE=$EXIT_ABORT
  [ $EXIT_CODE -ne $EXIT_NORMAL ] && \
  { printf "ABORT: Unable to Create $IPBLOCKER_CONFIG" | log; EXIT_CODE=$EXIT_ABORT; return $EXIT_CODE; }

  EXIT_CODE=$EXIT_NORMAL

  grep "IPBLOCKER_DIR" "$IPBLOCKER_CONFIG" > /dev/null 2>&1
  if [ $? -ne $EXIT_NORMAL ]
  then
    printf "%-80s" "Creating file: $IPBLOCKER_CONFIG"
    printf "\b%.0s" {1..80}

    echo                                                         >> $IPBLOCKER_CONFIG
    echo "export IPBLOCKER_DIR=$IPBLOCKER_DIR"                   >> $IPBLOCKER_CONFIG
    echo "export PATH=/opt/bin:/usr/sbin:$IPBLOCKER_DIR:$PATH"   >> $IPBLOCKER_CONFIG
    echo "export TEMP=/opt/tmp"                                  >> $IPBLOCKER_CONFIG
    echo "export TMP=/opt/tmp"                                   >> $IPBLOCKER_CONFIG
    echo "export TZ=$(cat /etc/TZ)"                              >> $IPBLOCKER_CONFIG
    echo "export SHELL=/opt/bin/bash"                            >> $IPBLOCKER_CONFIG
    echo "export BASH_ENV=$IPBLOCKER_CONFIG"                     >> $IPBLOCKER_CONFIG
    echo "export BASH=/opt/bin/bash"                             >> $IPBLOCKER_CONFIG
    echo "export LC_CTYPE=UTF-8"                                 >> $IPBLOCKER_CONFIG
    echo "export IFS=$' \t\n'"                                   >> $IPBLOCKER_CONFIG
    echo "export CHECK_MARK='\xE2\x9C\x93'"                      >> $IPBLOCKER_CONFIG
    echo "#export CHECK_MARK='+'"                                >> $IPBLOCKER_CONFIG
    echo                                                         >> $IPBLOCKER_CONFIG
    echo "cd $IPBLOCKER_DIR"                                     >> $IPBLOCKER_CONFIG
    chmod +x $IPBLOCKER_CONFIG
  fi

  #log "END Check Config"
  return $EXIT_CODE
}

check_setup_filters ()
{
  local outputFile="${1:-}"
  shift
  declare -a contentArray=("$@")

  #log "START Check Setup $outputFile"
  EXIT_CODE=$EXIT_NORMAL
  [ ! -f "$outputFile" ] && \
  {
    printf "%-80s" "Creating $outputFile";
    printf "\b%.0s" {1..80};
    printf "%s\n" ${contentArray[@]-} > "$outputFile";
    remove_blanks "$outputFile";
  }
  #log "END Check Setup $outputFile"
  return $EXIT_CODE
}

check_setup_custom ()
{
  local outputFile="${1:-}" outputFile2="${2:-}"
  shift 2
  declare -a contentArray=($@)

  #log "START Check Custom Setup $outputFile"
  EXIT_CODE=$EXIT_NORMAL

  if [ ! -f "$outputFile"  -a  ! -f "$outputFile2" ]
  then
    printf "%-80s" "Creating $outputFile"
    printf "\b%.0s" {1..80}
    printf "%s\n" ${contentArray[@]-} > "$outputFile"
    sort $SORT_IPS_OPT "$outputFile" -o "$outputFile"
  fi

  #log "END Check Custom Setup $outputFile"
  return $EXIT_CODE
}

check_setup_optional ()
{
  local outputFile="${1:-}"
  EXIT_CODE=$EXIT_NORMAL

  #log "START Check Setup Misc"
  # Need to remove the entries of AWS/CLOUDFARE/GIT _CIDR_REFRESH from outputFile with diff
  [ $AWS_CIDR_WHITE_LIST       -eq 0  -a  -f "$AWS_CIDR_REFRESH" ]       && rm -rf "$AWS_CIDR_REFRESH"
  [ $CLOUDFARE_CIDR_WHITE_LIST -eq 0  -a  -f "$CLOUDFARE_CIDR_REFRESH" ] && rm -rf "$CLOUDFARE_CIDR_REFRESH"
  [ $GIT_CIDR_WHITE_LIST       -eq 0  -a  -f "$GIT_CIDR_REFRESH" ]       && rm -rf "$GIT_CIDR_REFRESH"

  if [ $AWS_CIDR_WHITE_LIST -ne 0  -a  ! -f "$AWS_CIDR_REFRESH" ]
  then
    printf "Refreshing $AWS_CIDR_REFRESH"       | log
    # refresh latest amazon aws (jason) file. Grab CIDR's, Convert to IP Address, Remove Private IP Ranges
    curl $CURLOPT "$AWS_CIDR_URL"       | grep "$AWS_IP_EXPR"      | grep -oE "$CIDR_PATTERN" | grep -vE "$PVT_IP_PATTERN" | sort $SORT_IPS_OPT -o "$AWS_CIDR_REFRESH"
  fi

  if [ $CLOUDFARE_CIDR_WHITE_LIST -ne 0  -a  ! -f "$CLOUDFARE_CIDR_REFRESH" ]
  then
    printf "Refreshing $CLOUDFARE_CIDR_REFRESH" | log
    # refresh latest amazon aws (jason) file. Grab CIDR's, Convert to IP Address, Remove Private IP Ranges
    curl $CURLOPT "$CLOUDFARE_CIDR_URL" | grep -oE "$CIDR_PATTERN" | grep -vE "$PVT_IP_PATTERN" | sort $SORT_IPS_OPT -o "$CLOUDFARE_CIDR_REFRESH"
  fi

  if [ $GIT_CIDR_WHITE_LIST -ne 0  -a  ! -f "$GIT_CIDR_REFRESH" ]
  then
    printf "Refreshing $GIT_CIDR_REFRESH"       | log
    # refresh latest amazon aws (jason) file. Grab CIDR's, Convert to IP Address, Remove Private IP Ranges
    curl $CURLOPT "$GIT_CIDR_URL"       | grep -oE "$CIDR_PATTERN" | grep -vE "$PVT_IP_PATTERN" | sort $SORT_IPS_OPT -o "$GIT_CIDR_REFRESH"
  fi
  cat "$AWS_CIDR_REFRESH" "$CLOUDFARE_CIDR_REFRESH" "$GIT_CIDR_REFRESH" >> "$outputFile" 2> /dev/null

  #log "END Check Setup Misc"
  return $EXIT_CODE
}

# Core Dependency Check to see if all required are available
check_setup_refresh_schedule ()
{
  local category="" jobName="" jobSchedule="" jobValue=""

  #log "Scheduling Refreshes: ON"
  EXIT_CODE=$EXIT_NORMAL

  for category in $(cat "$CATEGORY_LIST" 2> /dev/null | sort -u) #$ALL
  do
    jobName=$BLOCK_APPLN_TAG"-"$REFRESH_TAG"-"$category
    jobSchedule=${REFRESH_SCHEDULE[$category]-}
    jobValue="$jobSchedule . $IPBLOCKER_CONFIG; $IPBLOCKER_DIR/$prgName $REFRESH_TAG $category #$jobName#"

    [ "$(crontab -l 2> /dev/null | grep -w $jobName)" ] || \
    {
      [ ! -z "$jobSchedule" ] && \
      { printf "%-80s"  "Scheduling $REFRESH_TAG for $category";
        printf "\b%.0s" {1..80};
        ( crontab  -l 2> /dev/null | grep -wv "$jobName"; echo "$jobValue"; ) | crontab - || EXIT_CODE=$EXIT_ERROR;
      }
    }
  done
  [ $EXIT_CODE -ne $EXIT_NORMAL ] && printf "ERROR: Unable to Create $REFRESH_TAG Schedules" | log

  #log "Scheduling Refreshes: FINISHED"
  return $EXIT_CODE
}

check_setup_fire_script ()
{
  #log "START Check Firewall Script"
  EXIT_CODE=$EXIT_NORMAL
  eval "${FIREWALL_CHECK_CMD}"

  if [ $? -ne $EXIT_NORMAL ]
  then
    eval "${FIREWALL_ENABLE_CMD}" > /dev/null 2>&1 || EXIT_CODE=$EXIT_ERROR
    eval "${CONFIRM_CONFIG_CMD}"  > /dev/null 2>&1 || EXIT_CODE=$EXIT_ERROR
  fi
  [ $EXIT_CODE -ne $EXIT_NORMAL ] && \
  printf "ERROR: Unable to TURN ON Firewall with Command: $FIREWALL_ENABLE_CMD Value: $FIREWALL_ENABLE_VALUE" | log

  EXIT_CODE=$EXIT_NORMAL
  [ ! -w $FIRE_SCRIPT ]           && touch $FIRE_SCRIPT 2> /dev/null
  [ ! -w $FIRE_SCRIPT ]           && EXIT_CODE=$EXIT_ERROR
  [ $EXIT_CODE -ne $EXIT_NORMAL ] && \
  { printf "ERROR: Unable to Create/Update $FIRE_SCRIPT" | log; EXIT_CODE=$EXIT_ERROR; return $EXIT_CODE; }

  grep $BLOCK_APPLN_TAG $FIRE_SCRIPT > /dev/null 2>&1
  if [ $? -ne $EXIT_NORMAL ]
  then
    printf "%-80s" "Adding iptables and ipset saved state restore to $FIRE_SCRIPT"
    printf "\b%.0s" {1..80}

    cp $FIRE_SCRIPT $FIRE_SCRIPT"-"$(time_now)

    echo -e                                                                                    >> $FIRE_SCRIPT
    echo -e "# ipBLOCKer: Restore from Saved State. CAUTION DO NOT CHANGE MANUALLY" >> $FIRE_SCRIPT
    echo -e "[ -f "$IPBLOCKER_DIR/$BLOCK_APPLN_TAG.sh" ] && { $IPBLOCKER_DIR/$BLOCK_APPLN_TAG.sh synch_all; }"                                    >> $FIRE_SCRIPT
    chmod +x $FIRE_SCRIPT
  fi

  #log "END Check Firewall Script"
  return $EXIT_CODE
}

check_setup_user_profile    ()
{
  #log "START Check User Profile $HOME"
  EXIT_CODE=$EXIT_NORMAL
  [ ! -f "$HOME/.profile" ]       && touch "$HOME/.profile"      2> /dev/null
  [ ! -f "$HOME/.profile" ]       && EXIT_CODE=$EXIT_ERROR
  [ $EXIT_CODE -ne $EXIT_NORMAL ] && \
  { printf "ERROR: Unable to Create/Update $HOME/.profile"      | log;
    EXIT_CODE=$EXIT_ERROR; return $EXIT_CODE; }

  grep $BLOCK_APPLN_TAG "$HOME/.profile" > /dev/null 2>&1
  if [ $? -ne $EXIT_NORMAL ]
  then
    printf "%-80s" "Adding alias to user profile"
    printf "\b%.0s" {1..80}
    echo -e                                            >> "$HOME/.profile"
    echo -e "export IPBLOCKER_DIR=$IPBLOCKER_DIR"      >> "$HOME/.profile"
    echo -e "export PATH=\$IPBLOCKER_DIR:\$PATH"       >> "$HOME/.profile"
    echo -e "alias block=\$IPBLOCKER_DIR/ipBLOCKer.sh" >> "$HOME/.profile"
  fi

  #log "END Check User Profile"
  return $EXIT_CODE
}

check_setup_bash_profile    ()
{
  #log "START Check Bash Profile $HOME"
  EXIT_CODE=$EXIT_NORMAL
  [ ! -f "$HOME/.bash_profile" ]  && touch "$HOME/.bash_profile" 2> /dev/null
  [ ! -f "$HOME/.bash_profile" ]  && EXIT_CODE=$EXIT_ERROR
  [ $EXIT_CODE -ne $EXIT_NORMAL ] && \
  { printf "ERROR: Unable to Create/Update $HOME/.bash_profile" | log;
    EXIT_CODE=$EXIT_ERROR; return $EXIT_CODE; }

  grep $BLOCK_APPLN_TAG "$HOME/.bash_profile" > /dev/null 2>&1
  if [ $? -ne $EXIT_NORMAL ]
  then
    printf "%-80s" "Adding alias to bash profile"
    printf "\b%.0s" {1..80}
    echo -e                                            >> "$HOME/.bash_profile"
    echo -e "export IPBLOCKER_DIR=$IPBLOCKER_DIR"      >> "$HOME/.bash_profile"
    echo -e "export PATH=\$IPBLOCKER_DIR:\$PATH"       >> "$HOME/.bash_profile"
    echo -e "alias block=\$IPBLOCKER_DIR/ipBLOCKer.sh" >> "$HOME/.bash_profile"
  fi

  #log "END Check Bash Profile"
  return $EXIT_CODE
}

check_setup_category_length ()
{
  local category=""
  EXIT_CODE=$EXIT_NORMAL

  for category in $(cat "$CATEGORY_LIST" 2> /dev/null) "$CUSTOM_TAG" "$WHITE_LIST_TAG"
  do
    printf "%-80s" "Checking $CATEGORIES_TAG : $category length"
    printf "\b%.0s" {1..80}
    [ ${#category} -gt $MAX_CATEGORY_LENGTH ] && \
    {
      printf "ABORT: $CATEGORIES_TAG : $category length ${#category} exceeds $MAX_CATEGORY_LENGTH" | log;
      EXIT_CODE=$EXIT_ABORT;
    }
  done

  return $EXIT_CODE
}

check_setup_syslog_packtype ()
{
  #log "START Checking syslog logging for Accept & Drop"
  EXIT_CODE=$EXIT_NORMAL

  eval "${PACKET_LOGGING_CHECK_CMD}"
  if [ $? -ne $EXIT_NORMAL ]
  then
    eval "${PACKET_LOGGING_ENABLE_CMD}" > /dev/null 2>&1 || EXIT_CODE=$EXIT_ERROR
    eval "${CONFIRM_CONFIG_CMD}"        > /dev/null 2>&1 || EXIT_CODE=$EXIT_ERROR
  fi
  [ $EXIT_CODE -ne $EXIT_NORMAL ] && \
  printf "ERROR: Unable to TURN ON Packet Logging: $PACKET_LOGGING_ENABLE_CMD Value: $PACKET_LOGGING_ENABLE_VALUE" | log

  #log "END Checking syslog logging for Accept & Drop"
  return $EXIT_CODE
}

####
# System setup - create required directories/filters/files if not present
####
system_setup ()
{
  local outputFile="" outputFile2="" outputFile3=""
  EXIT_CODE=$EXIT_NORMAL

  #log "START Setup"
  printf "%-80s" "Starting System Setup ...."
  printf "\b%.0s" {1..80}

  mkdir -p "$DIR_FILTERS"
  mkdir -p "$DIR_REFRESH"

  check_setup_filters $CATEGORY_LIST           ${CATEGORY_LIST_ARRAY[@]-}
  check_setup_filters $ADWARE_FILTERS          ${ADWARE_FILTERS_ARRAY[@]-}
  check_setup_filters $COUNTRY_FILTERS         ${COUNTRY_FILTERS_ARRAY[@]-}
  check_setup_filters $ETF_FILTERS             ${ETF_FILTERS_ARRAY[@]-}
  check_setup_filters $MALWARE_FILTERS         ${MALWARE_FILTERS_ARRAY[@]-}
  check_setup_filters $SHALLA_CATEGORY_LIST    ${SHALLA_CATEGORIES_LIST_ARRAY[@]-}
  check_setup_filters $SHALLA_FILTERS          ${SHALLA_FILTERS_ARRAY[@]-}
  check_setup_filters $SPAM_FILTERS            ${SPAM_FILTERS_ARRAY[@]-}
  check_setup_filters $TOR_EXITS_FILTERS       ${TOR_EXITS_FILTERS_ARRAY[@]-}

  check_setup_custom  $CUSTOM_REFRESH_TEMP     $CUSTOM_REFRESH     ${CUSTOM_REFRESH_TEMP_ARRAY[@]-}
  check_setup_custom  $WHITE_LIST_REFRESH_TEMP $WHITE_LIST_REFRESH ${WHITE_LIST_REFRESH_TEMP_ARRAY[@]-}

  outputFile="$WHITE_LIST_REFRESH_TEMP"
  outputFile2="$WHITE_LIST_REFRESH"
  outputFile3="$WHITE_LIST_REFRESH_CIDR"

  [ -f "$outputFile"  -a  -f "$outputFile2" ] && rm -rf "$outputFile"
  [ -f "$outputFile"  -a  -f "$outputFile3" ] && rm -rf "$outputFile"
  #[ -f $outputFile2 ]                        && outputFile=$outputFile2;
  [ -f "$outputFile3" ]                       && outputFile="$outputFile3"

  check_setup_optional $outputFile; sort $SORT_IPS_OPT "$outputFile" -o "$outputFile"
  #check_setup_config
  #check_setup_restore_buckets
  #check_setup_restore_firewall
  check_setup_refresh_schedule
  check_setup_fire_script
  check_setup_category_length
  check_setup_user_profile
  check_setup_bash_profile
  # Turn on Logging if disable...not needed with custom chains
  #check_setup_syslog_packtype

  printf "%-80s"
  printf "\b%.0s" {1..80}
  #log "END Setup"
  return $EXIT_CODE
}

show_status_header ()
{
  local memUsage=$(free  | grep "Mem"  | awk '{printf "Memory Status: %.2fM/%.2fM", $3/1024, $2/1024}')
  local swapUsage=$(free | grep "Swap" | awk '{printf "Swap Status: %.2fM/%.2fM",   $3/1024, $2/1024}')
  local spaceUsage="Space Usage: $(du -hs $IPBLOCKER_DIR | cut -f1)"

  echo -en ' '                                                           | log
  printf "$STATUS_LINE_SEPERATOR_1%.0s" {1..70}                          | log
  printf "%-30s \t %-30s" "Date: $(date)" "Device: $DEVICE_NAME"         | log

  echo -en ' '                                                           | log
  printf "%40s" "ipBLOCKer"                                              | log
  printf "%42s" "(Version: $VERSION)"                                    | log

  echo -en ' '                                                           | log
  printf "$memUsage \t $swapUsage"                                       | log

  echo -en ' '                                                           | log
  printf "%-10s" "Install: $IPBLOCKER_DIR"                               | log
  printf "%-10s" "Filters: $DIR_FILTERS"                                 | log
  printf "%-10s" "Refresh: $DIR_REFRESH"                                 | log
  printf "%-10s" "Backup : $DIR_BACKUP"                                  | log
  printf "%-10s" "Log    : $LOG_FILE"                                    | log

  echo -en ' '                                                           | log
  printf "$spaceUsage \t\t\t IPSet Version: $IPSET_VERSION"              | log
  printf "$STATUS_LINE_SEPERATOR_2%.0s" {1..70}                          | log
}

show_status_body ()
{
  printf "%30s %22s" "Total" "Total"                                                           | log
  printf "%-20s %-10s %-10s %-10s %-10s" "$CATEGORIES_TAG" "$IP_TAG" "Hits" "$CIDR_TAG" "Hits" | log
  printf "$STATUS_LINE_SEPERATOR_2%.0s" {1..70}                                                | log
}

show_status_body_content ()
{
  local dCatg="${1:-}" categoryName="" nfCatg=$BLOCK_APPLN_TAG"-""${1:-}"
  declare -a nfBuckets=()

  printf "%-60s" "Please wait working on $dCatg ...."
  printf "\b%.0s" {1..60}

  ipCount=0; cidrCount=0; hitIpCount=0; hitCidrCount=0;

  nfBuckets=($(ipset $LIST | grep $nfCatg | sort -u | awk {'print $2'}))

  clear_caches
  for categoryName in ${nfBuckets[@]-}
  do
    if [[ "$categoryName" == *"$CIDR_TAG"* ]]
    then
      cidrCount+=$(ipset $LIST $categoryName 2> /dev/null | grep -oEc $CIDR_PATTERN)
    else
      ipCount+=$(ipset   $LIST $categoryName 2> /dev/null | grep -oEc $IP_PATTERN)
    fi
  done
  clear_caches

  hitIpCount=$(iptables   -L -n -v -x | grep -w $nfCatg"[a-z]"          | grep -v 'Chain\|LOG' | awk {'print $1'} | awk '{ SUM += $1} END { print SUM }')
  hitCidrCount=$(iptables -L -n -v -x | grep -w $nfCatg$CIDR_TAG"[a-z]" | grep -v 'Chain\|LOG' | awk {'print $1'} | awk '{ SUM += $1} END { print SUM }')

  ipTotalCount+=$ipCount;          cidrTotalCount+=$cidrCount;
  hitIpTotalCount+=$hitIpCount; hitCidrTotalCount+=$hitCidrCount;

  printf "%-20s %-10d %-10d %-10d %-10d" "$dCatg" "$ipCount" "$hitIpCount" "$cidrCount" "$hitCidrCount" | log
}

show_status_footer ()
{
  printf "$STATUS_LINE_SEPERATOR_2%.0s" {1..70}                                                                                     | log
  printf "%-20s %-10d %-10d %-10d %-10d" "Grand Totals: " "$ipTotalCount" "$hitIpTotalCount" "$cidrTotalCount" "$hitCidrTotalCount" | log
  printf "$STATUS_LINE_SEPERATOR_1%.0s" {1..70}                                                                                     | log
  echo -en ' '                                                                                                                      | log
}

# Show ipBLOCKer Status
show_status ()
{
  declare -i    ipCount=0    cidrCount=0    ipTotalCount=0    cidrTotalCount=0
  declare -i hitIpCount=0 hitCidrCount=0 hitIpTotalCount=0 hitCidrTotalCount=0
  local category=""
  EXIT_CODE=$EXIT_NORMAL

  show_status_header
  show_status_body
  for category in $(cat "$CATEGORY_LIST" 2> /dev/null | sort -u) $CUSTOM_TAG $WHITE_LIST_TAG
  do
    show_status_body_content $category
  done
  show_status_footer

  #log "END Show Status"
  return $EXIT_CODE;
}

system_check ()
{
  declare -i failCtr=0
  #log "System check: ON"
  EXIT_CODE=$EXIT_NORMAL

  check_core_dependency;   [ $EXIT_CODE -ne $EXIT_NORMAL ] && \
  {
    failCtr+=1;
    printf "%-60b" "\n$APP_BANNER Core Dependency Check: "$RED"FAIL"$RESET"";
    printf "\nPlease install the below:\n";
    printf "%s\n" "${coreFails[@]-}";
  }
  check_package_dependency;   [ $EXIT_CODE -ne $EXIT_NORMAL ] && \
  {
    failCtr+=1;
    printf "%-40b" "\n$APP_BANNER $PACKAGE_NAME Dependency Check: "$RED"FAIL"$RESET"";
    printf "\nPlease install the below:\n";
    printf "Ex:$PACKAGE_INSTALL_CMD $PACKAGE_INSTALL_OPTION bash diffutils grep coreutils-sort coreutils-split findutils\n";
    printf "%s\n" "${packageFails[@]-}";
  }
  check_net_filters;   [ $EXIT_CODE -ne $EXIT_NORMAL ] && \
  {
    failCtr+=1;
    printf "%-40b" "\n$APP_BANNER Netfilters Check: "$RED"FAIL"$RESET"";
    printf "\nERROR: $IPSET_VERSION Unknown/Unavailable/Unsupported ipset module\n";
  }
  #\ || { echo -e "Netfilters Check: "$GREEN"PASS"$RESET""; }
  check_configuraton; [ $EXIT_CODE -ne $EXIT_NORMAL ] && \
  {
    failCtr+=1;
    printf "%-40b" "\n$APP_BANNER Configuration Check: "$RED"FAIL"$RESET"\n";
  }
  #\ || { echo -e "Configuration Check: "$GREEN"PASS"$RESET""; }
  [ $failCtr -gt 0 ]                                  && \
  {
    printf "%-40b" "\n$APP_BANNER System Check: "$RED"FAIL"$RESET"\n\n";
    EXIT_CODE=$EXIT_ABORT;
  }
  #\ || { echo -e "System Check: "$GREEN"PASS"$RESET""; }

  #log "System check: FINISHED"
  return $EXIT_CODE
}

# Core Dependency Check to see if all required are available
check_core_dependency ()
{
  local cmd=""
  coreFails=()
  declare -i ctr=0

  #log "Core Dependency Check: ON"
  EXIT_CODE=$EXIT_NORMAL

  for cmd in ${CORE_DEPENDS[@]-}
  do
    [ -z "$(type -p $cmd 2> /dev/null)" ] && \
    { coreFails[$ctr]="$cmd"; ctr+=1; }
  done

  [ "${#coreFails[@]}" -gt 0 ] && EXIT_CODE=$EXIT_ABORT

  #log "Core Dependency Check: FINISHED"
  return $EXIT_CODE
}

# Package Dependency Check to see if all required are available
check_package_dependency ()
{
  local cmd=""
  packageFails=()
  declare -i ctr=0

  #log "Package Dependency Check: ON"
  EXIT_CODE=$EXIT_NORMAL

  for cmd in ${PACKAGE_DEPENDS[@]-}
  do
    [ "$(type -p $PACKAGE_INSTALL_LOCATION"/"$cmd 2> /dev/null)" ] || \
    { packageFails[$ctr]="$cmd"; ctr+=1; }
  done

  [ "${#packageFails[@]}" -gt 0 ] && EXIT_CODE=$EXIT_ABORT

  #log "Package Dependency Check: FINISHED"
  return $EXIT_CODE
}

check_net_filters ()
{
  #log "START Check ipset modules"
  EXIT_CODE=$EXIT_NORMAL
  case $IPSET_VERSION in
    *v6)
       #log "Loading ipset 6 modules"
       modprobe -avs "${IPV6_MODULES[@]-}" || EXIT_CODE=$EXIT_ABORT
       ;;
    *v4)
       #log "Loading ipset 4 modules"
       modprobe -avs "${IPV4_MODULES[@]-}" || EXIT_CODE=$EXIT_ABORT
       ;;
    *)
       EXIT_CODE=$EXIT_ABORT
       ;;
  esac

  return $EXIT_CODE
}

check_configuraton ()
{
  EXIT_CODE=$EXIT_NORMAL
  #log "Configuration check: ON"

  #log "Configuration check: FINISHED"
  return $EXIT_CODE;
}

# Remove installed directories/filters/files
un_install  ()
{
  declare -i ctr=0 cleanUpFolders=0
  local categoryName="${1:-}" lst="" jobName=$BLOCK_APPLN_TAG"-"$REFRESH_TAG"-""${1:-}"

  #log "Uninstall: ON"
  EXIT_CODE=$EXIT_NORMAL
  [ -z "$categoryName" ] && { EXIT_CODE=$EXIT_ERROR; return $EXIT_CODE; }

  if [ "$categoryName" == "$ALL" ]
  then
      printf "%-60b" "$APP_BANNER Uninstall System"                         | log
      for lst in $(cat "$CATEGORY_LIST" 2> /dev/null) "$CUSTOM_TAG" "$WHITE_LIST_TAG"
      do
         remove_net_filters $lst
      done
      cleanUpFolders=1
  else
      printf "%-60b" "$APP_BANNER Uninstall $CATEGORIES_TAG: $categoryName" | log
      remove_net_filters $categoryName

      printf "Removing $categoryName $REFRESH_TAG from $DIR_REFRESH"        | log
      rm -rf $DIR_REFRESH/$categoryName*

      printf "Removing $categoryName $FILTERS_TAG from $DIR_FILTERS"        | log
      rm -rf $DIR_FILTERS/$categoryName*

      printf "Removing $categoryName Scheduled Jobs"                        | log
      ( crontab -l 2> /dev/null | grep -wv "$jobName" ) | crontab -        || EXIT_CODE=$EXIT_ERROR
  fi

  (( $cleanUpFolders )) && \
  {
    printf "\nRemoving firewall-start changes"                              | log;
    replace_config "$FIRE_SCRIPT" "$BLOCK_APPLN_TAG|ipset.save|iptables.save" "";

    printf "\nRemoving Scheduled Jobs"                                      | log;
    ( crontab -l 2> /dev/null | grep -wv "$BLOCK_APPLN_TAG" )  | crontab - || EXIT_CODE=$EXIT_ERROR;

    printf "\nRemoving profile changes"                                     | log;
    replace_config "$HOME/.profile"      "IPBLOCKER_DIR" "";
    replace_config "$HOME/.bash_profile" "IPBLOCKER_DIR" "";

    printf "\nRemoving $IPBLOCKER_CONFIG"                                   | log;
    rm -rf "$IPBLOCKER_CONFIG";

    printf "\nRemoving $DIR_REFRESH Folder"                                 | log;
    rm -rf "$DIR_REFRESH";

    printf "\nRemoving $DIR_FILTERS Folder"                                 | log;
    rm -rf "$DIR_FILTERS";

    printf "%-60b" "\nUninstalled $APP_BANNER. Check by running iptables -L FORWARD; ipset -L | grep $BLOCK_APPLN_TAG";
  }                     || \
  { save_net_filters; }

  #log "Uninstall: FINISHED"
  return $EXIT_CODE;
}

remove_net_filters ()
{
  local category="${1:-}"
  local ipDelSet="" cidrDelSet="" ipChainName="" cidrChainName=""
  declare -i ctr=0
  EXIT_CODE=$EXIT_NORMAL

  printf "Removing: $category" | log

  ctr=1
  for letter in $(echo {a..z})
  do
    ctr+=1
    ipDelSet=$BLOCK_APPLN_TAG"-"$category$letter
    cidrDelSet=$BLOCK_APPLN_TAG"-"$category$CIDR_TAG$letter

    ipChainName=$ipDelSet
    cidrChainName=$cidrDelSet

    iptables -D FORWARD -m set $MATCH_SET $ipDelSet   src,dst -j $ipChainName   > /dev/null 2>&1
    iptables -D FORWARD -m set $MATCH_SET $cidrDelSet src,dst -j $cidrChainName > /dev/null 2>&1

    iptables -D FORWARD $ACCEPT_PROTO_PORTS -m set $MATCH_SET $ipDelSet   src,dst -j $ipChainName   > /dev/null 2>&1
    iptables -D FORWARD $ACCEPT_PROTO_PORTS -m set $MATCH_SET $cidrDelSet src,dst -j $cidrChainName > /dev/null 2>&1

    ipset $DESTROY $ipDelSet   > /dev/null 2>&1
    ipset $DESTROY $cidrDelSet > /dev/null 2>&1

    iptables -F $ipChainName   > /dev/null 2>&1
    iptables -X $ipChainName   > /dev/null 2>&1

    iptables -F $cidrChainName > /dev/null 2>&1
    iptables -X $cidrChainName > /dev/null 2>&1

    [ $ctr -gt $MAX_BUCKETS ] && break
  done

  #log "END Remove ipBLOCKer $CATEGORIES_TAG : $category"
  return $EXIT_CODE;
}

clear_caches ()
{
  [ -w /proc/sys/vm/drop_caches ] && { sync; echo $CACHE_CLEAR_NORMAL > /proc/sys/vm/drop_caches; }
}

cli_select_category  ()
{
  local addFilters=""
  addFilters=$CUSTOM_TAG" "$WHITE_LIST_TAG; [ $SHOW_ALL -eq 1 ] && addFilters=$addFilters" "$ALL
  addFilters=$addFilters" "$NONE

  clear;echo;echo -e "$APP_BANNER ""$UNDERLINED""${1:-}"$RESET"";echo;

  PS3="Enter Your Number Choice:"
  selectedCategory=""
  echo
  select selectedCategory in $(cat "$CATEGORY_LIST" 2> /dev/null | sort -u) $addFilters
  do
     case $selectedCategory in
       "$NONE") break ;;
             *) [ -z $selectedCategory ] && { echo -e "$RED"invalid choice"$RESET"; continue; }
                echo; echo "Selected: $selectedCategory"
                prompt_confirm; [ $? -eq $EXIT_NORMAL ] && break ;;
     esac
  done
}

prompt_confirm ()
{
  local reply=""

  while read -t$WAIT_TIME -r -n 1 -p "${1:-Are you Sure?} [y/n]: " reply
  do
    case $reply in
      [yY]) echo ; return $EXIT_NORMAL            ;;
      [nN]) echo ; return $EXIT_ERROR             ;;
         *) echo -en "$RED"invalid choice"$RESET" ;;
    esac
  done
}

read_input ()
{
  local getVal="" line=""
  ipArray=() fndIpArray=() cidrArray=() webArray=()
  declare -i iCtr=0 cCtr=0 wCtr=0

  local tag="${1:-}"
  local prompt="Enter $tag Website, IP or CIDR values below. Press ENTER when Done.\nExample: www.somesite.com or 123.123.123.123 or 123.123.123.123/24\n"

  echo -e $prompt
  while read -t$WAIT_TIME -r line
  do
      [[ $line ]] || break

      getVal=$(echo $line | grep -oE $CIDR_PATTERN)
      [ $? -eq $EXIT_NORMAL ] && { cidrArray[$cCtr]="$getVal"; cCtr+=1; continue; }

      getVal=$(echo $line | grep -oE $IP_PATTERN)
      [ $? -eq $EXIT_NORMAL ] && {   ipArray[$iCtr]="$getVal"; iCtr+=1; continue; }

      webArray[$wCtr]="$line"; wCtr+=1;
  done

  if [ "${#ipArray[@]}" -gt 0 ]
  then
    printf "\nEntered IP's:\n"
    printf "%s\n" ${ipArray[@]-}
  fi
  if [ "${#cidrArray[@]}" -gt 0 ]
  then
    printf "\nEntered CIDR's:\n"
    printf "%s\n" ${cidrArray[@]-}
  fi
  if [ "${#webArray[@]}" -gt 0 ]
  then
    printf "\nEntered Websites's:\n"
    printf "%s\n" ${webArray[@]-}
  fi
}

find_ip ()
{
  local getIP=""
  declare -i ctr=0

  [ "${#webArray[@]}" -le 0 ] && return $EXIT_CODE
  echo "Please wait retrieving IP Address of Websites...."

  EXIT_CODE=$EXIT_NORMAL fndIpArray=()
  for getIP in ${webArray[@]-}
  do
    fndIpArray[$ctr]=$(nslookup $getIP 2> /dev/null | grep -oE $IP_PATTERN | grep -vE $PVT_IP_PATTERN | sort $SORT_IPS_OPT)
    ctr+=1
  done

  [ "${#fndIpArray[@]}" -le 0 ] && \
  {
    printf "ERROR: Unable to retrieve any IP's for Websites\n";
    EXIT_CODE=$EXIT_ERROR;
    return $EXIT_CODE;
  }
  printf "\nRetrieved IP's for Websites:\n"
  printf "%s\n" ${fndIpArray[@]-}
  printf "\n"

  return $EXIT_CODE
}

categories_subscribed ()
{
  EXIT_CODE=$EXIT_NORMAL

  [ ! -f "$CATEGORY_LIST" ] && EXIT_CODE=$EXIT_ABORT || \
  {
    remove_blanks "$CATEGORY_LIST";
    [[ $(wc -l "$CATEGORY_LIST" 2> /dev/null | awk '{print $1}') -le 0 ]] \
    && { EXIT_CODE=$EXIT_ABORT;  } \
    || { EXIT_CODE=$EXIT_NORMAL; }
  }

  return $EXIT_CODE
}

is_valid_category ()
{
  local checkCategory="${1:-}"
  EXIT_CODE=$EXIT_NORMAL

  case $checkCategory in
       "$ALL"|"$WHITE_LIST_TAG"|"$CUSTOM_TAG")
          return $EXIT_CODE ;;
       *)
          grep -qwx $checkCategory $CATEGORY_LIST > /dev/null 2>&1
          EXIT_CODE=$?; [ $EXIT_CODE -ne $EXIT_NORMAL ] && \
          { echo -e "Option: $option1  Invalid Category: "$RED"$checkCategory"$RESET"" | log; } ;;
  esac

  return $EXIT_CODE
}

is_refresh_ready ()
{
  local categoryName="${1:-}" outputFile="" tempFile="" cidrOutputFile=""
  outputFile="$DIR_REFRESH/$categoryName$REFRESH_FILE_EXT"
  tempFile="$outputFile$TEMP_FILE_EXT"
  cidrOutputFile="$DIR_REFRESH/$categoryName$CIDR_FILE_EXT"

  EXIT_CODE=$EXIT_NORMAL
  if [ ! -f "$outputFile"  -a  ! -f "$tempFile" -a  ! -f "$cidrOutputFile" ]
  then
      printf "ABORT: $categoryName $REFRESH_TAG file not found. Please run Setup ...." | log
      EXIT_CODE=$EXIT_ABORT
      return $EXIT_CODE
  fi

  return $EXIT_CODE
}

cli_process_add_del_input ()
{
  local filterName="${1:-}"
  EXIT_CODE=$EXIT_NORMAL
  txt="Option: $option1"; [ -z $option2 ] && txt=$txt" "$filterName || txt=$txt" "$option2

  while true
  do
     read_input $filterName
     find_ip
     echo;echo $txt; echo;
     prompt_confirm; [ $? -eq $EXIT_NORMAL ] && break
  done

  return $EXIT_CODE
}

cli_create_add_del_diff ()
{
  local file1="${1:-}" file2="${2:-}"

  # Create sort files from Global Arrays
  [ "${#ipArray[@]}" -eq 0 -a "${#fndIpArray[@]}" -eq 0 -a "${#cidrArray[@]}" -eq 0 ] && \
  { EXIT_CODE=$EXIT_ERROR; return $EXIT_CODE; }

  # Add ipArray fndIpArray cidrArray to sort files
  EXIT_CODE=$EXIT_NORMAL
  printf "%s\n" ${ipArray[@]-}  ${fndIpArray[@]-} > "$file1" || EXIT_CODE=$EXIT_ERROR
  printf "%s\n" ${cidrArray[@]-}                  > "$file2" || EXIT_CODE=$EXIT_ERROR
  remove_blanks "$file1" "$file2"

  return $EXIT_CODE
}

cli_add_del_ip_cidr ()
{
  local categoryName="${1:-}" addDel=$2
  local txt="" outputFile="" cidrOutputFile="" sortFile="" cidrSortFile=""

  outputFile="$DIR_REFRESH/$categoryName$REFRESH_FILE_EXT"
  cidrOutputFile="$DIR_REFRESH/$categoryName$CIDR_FILE_EXT"
  sortFile="$outputFile$SORT_FILE_EXT"
  cidrSortFile="$cidrOutputFile$SORT_FILE_EXT"

  ipArray=() fndIpArray=() cidrArray=() webArray=()

  # Do we allow user to run without categories being setup?
  cli_process_add_del_input $categoryName
  [ $EXIT_CODE -ne $EXIT_NORMAL ] && return $EXIT_CODE

  cli_create_add_del_diff $sortFile $cidrSortFile
  [ $EXIT_CODE -ne $EXIT_NORMAL ] && return $EXIT_CODE

  if [ $addDel -eq 1 ]
  then
    # Compare and Split the refreshed with the present
    compare_split $outputFile     $IP_TAG
    compare_split $cidrOutputFile $CIDR_TAG

    # Refresh Category Buckets with Refreshed filters
    EXIT_CODE=$EXIT_NORMAL
    clear_caches
    refresh_categories            $categoryName
  else
    delete_elements_from_category $categoryName $sortFile $cidrSortFile "WL"
  fi
  rm -rf "$sortFile" "$cidrSortFile"

  return $EXIT_CODE
}

check_ip_cidr_in_system ()
{
  local combinedArray=("${ipArray[@]-}" "${fndIpArray[@]-}" "${cidrArray[@]-}")
  local elem="" catg="" letter="" ipCheckSet="" cidrCheckSet=""
  declare -i ctr=0 iCtr=0 cCtr=0

  for elem in ${combinedArray[@]-}
  do
    declare -a ipFnd=() cidrFnd=()
    printf "\nChecking $CATEGORIES_TAG for: $elem \n"
    printf "$STATUS_LINE_SEPERATOR_2%.0s" {1..40}

    for catg in $(cat "$CATEGORY_LIST" 2> /dev/null | sort -u) $CUSTOM_TAG $WHITE_LIST_TAG
    do
      ctr=1
      for letter in $(echo {a..z})
      do
        ctr+=1
        ipCheckSet=$BLOCK_APPLN_TAG"-"$catg$letter
        cidrCheckSet=$BLOCK_APPLN_TAG"-"$catg$CIDR_TAG$letter

        EXIT_CODE=$EXIT_NORMAL
        ipset $TEST $ipCheckSet   $elem > /dev/null 2>&1 || EXIT_CODE=$EXIT_ERROR
        [ $EXIT_CODE -eq $EXIT_NORMAL ] && { ipFnd[$iCtr]="$catg"; iCtr+=1; }

        EXIT_CODE=$EXIT_NORMAL
        ipset $TEST $cidrCheckSet $elem > /dev/null 2>&1 || EXIT_CODE=$EXIT_ERROR
        [ $EXIT_CODE -eq $EXIT_NORMAL ] && { cidrFnd[$cCtr]="$catg"; cCtr+=1; }

        [ $ctr -gt $MAX_BUCKETS ]       && break
      done
    done

    printf "\nIP's  : "
    [ "${#ipFnd[@]}" -gt 0 ]   && { printf "%-10s" "${ipFnd[@]-}"; } \
                               || { printf "%-10s" "no block"; }
    printf "\nCIDR's: "
    [ "${#cidrFnd[@]}" -gt 0 ] && { printf "%-10s" ${cidrFnd[@]-}; } \
                               || { printf "%-10s" "no block"; }
    printf "\n"
    unset ipFnd cidrFnd
  done

  return $EXIT_CODE
}

cli_check ()
{
  local param1="${1:-}"

  read_input $param1
  find_ip

  # If nothing is entered or found return
  [ "${#ipArray[@]}" -le 0  -a  "${#fndIpArray[@]}" -le 0  -a  "${#cidrArray[@]}" -le 0 ] && return $EXIT_CODE

  check_ip_cidr_in_system

  return $EXIT_CODE
}

in_array()
{
  local checkValue="" searchValue="${1:-}"
  shift
  declare -a contentArray=("$@")

  EXIT_CODE=$EXIT_ERROR
  for checkValue in ${contentArray[@]-}
  do
    [ "$checkValue" == "$searchValue" ] && { EXIT_CODE=$EXIT_NORMAL; break; }
  done

  return $EXIT_CODE
}

log ()
{
  local logContent="${1:-}"
  logger -st $BLOCK_APPLN_TAG $logContent
}

is_white_list_refresh_ready ()
{
  EXIT_CODE=$EXIT_NORMAL
  [ ! -f "$WHITE_LIST_REFRESH" ] && \
  { log "ABORT: $WHITE_LIST_TAG $REFRESH_TAG file NOT FOUND cannot continue ....";
    EXIT_CODE=$EXIT_ABORT; }
  return $EXIT_CODE
}

####
 # Deletes elements from Categories.
####
delete_elements_from_category ()
{
   local categoryName="${1:-}" ipsFromFile="${2:-}" cidrsFromFile="${3:-}" tag="${4:-}"
   local lst="" addCatg=""

   #log "START Delete Elements from $categoryName"
   if [ "$categoryName" == "$ALL" ]
   then
     addCatg=$CUSTOM_TAG" "
     [ "$tag" != "NWL" ] && addFilters=$addCatg" "$WHITE_LIST_TAG

     for lst in $(cat "$CATEGORY_LIST" 2> /dev/null) $addCatg
     do
       remove_elements_from_category $lst          $ipsFromFile $cidrsFromFile
     done
   else
       remove_elements_from_category $categoryName $ipsFromFile $cidrsFromFile
   fi

   #log "END Delete Elements from $categoryName"
   return $EXIT_CODE
}

remove_elements_from_category  ()
{
   local categoryName="${1:-}"  ipsFromFile="${2:-}" cidrsFromFile="${3:-}" nfCatg=$BLOCK_APPLN_TAG"-""${1:-}"
   local ipRefreshFile="" cidrRefreshFile="" bucket=""
   declare -i cnt=0
   declare -a nfBuckets=()

   ipRefreshFile="$DIR_REFRESH/$categoryName$REFRESH_FILE_EXT"
   cidrRefreshFile="$DIR_REFRESH/$categoryName$CIDR_FILE_EXT"

   EXIT_CODE=$EXIT_NORMAL

   nfBuckets=($(ipset $LIST | grep $nfCatg | sort -u | awk {'print $2'}))
   for bucket in ${nfBuckets[@]-}
   do
     if [[ "$bucket" == *"$CIDR_TAG"* ]]
     then
       xargs -E END -P$NUM_PROCS -I "PARAM" -n1 -a"$cidrsFromFile" ipset $DELETE $bucket PARAM > /dev/null 2>&1 || EXIT_CODE=$EXIT_ERROR
     else
       xargs -E END -P$NUM_PROCS -I "PARAM" -n1 -a"$ipsFromFile"   ipset $DELETE $bucket PARAM > /dev/null 2>&1 || EXIT_CODE=$EXIT_ERROR
     fi
   done
   unset nfBuckets
   clear_caches

   # Remove elements from refreshed categories mostly useful for custom and white list
   cnt=$(remove_file1_from_file2 "$ipsFromFile"   "$ipRefreshFile")
   [ $cnt -gt 0 ] && printf "%-40s %-10s" "Removed from $categoryName $IP_TAG's:"   $cnt | log

   cnt=$(remove_file1_from_file2 "$cidrsFromFile" "$cidrRefreshFile")
   [ $cnt -gt 0 ] && printf "%-40s %-10s" "Removed from $categoryName $CIDR_TAG's:" $cnt | log

   clear_caches
   #log "END Removing Elements from $categoryName"
   return $EXIT_CODE
}

save_net_filters ()
{
  #log "START save_net_filters"
  eval "${IPTABLES_SAVE_CMD}"
  eval "${IPSET_SAVE_CMD}"
  #log "END save_net_filters"
}

synch_all_net_filters ()
{
  #log "START synch_all_net_filters"
  local netf="${1:-}" tag=""
  declare -i fwFlag=0 bkFlag=0
  EXIT_CODE=$EXIT_NORMAL

  case $netf in
    $FIREWALL_TAG) fwFlag=1;   ;;
     $BUCKETS_TAG) bkFlag=1;   ;;
                *) fwFlag=1; tag="$ALL"; bkFlag=1; ;;
  esac

  printf "%-80b" "Restore $APP_BANNER $tag saved state                 \n" #| log
  printf "\b%.0s" {1..80}

  (( $bkFlag )) && \
  {
    printf "%-80s" "Check $tag $BUCKETS_TAG have a saved state ...."      | log;
    [ -f "$IPSET_SAVE_FILE" ]    && \
    {
      printf "%-80s" "Restoring $tag $BUCKETS_TAG from saved state ...."  | log;
      eval "${IPSET_RESTORE_CMD}";
    }
  }

  (( $fwFlag )) && \
  {
    printf "%-80s" "Check $tag $FIREWALL_TAG has a saved state ...."      | log;
    [ -f "$IPTABLES_SAVE_FILE" ] && \
    {
      printf "%-80s" "Restoring $tag $FIREWALL_TAG from saved state ...." | log;
      eval "${IPTABLES_RESTORE_CMD}";
    }
  }

  #log "END synch_all_net_filters"
  return $EXIT_CODE
}

# Synchronize ipsets and iptables
synch_net_filters ()
{
  local categoryName="" tag=""
  declare -a nfBuckets=()

  EXIT_CODE=$EXIT_NORMAL
  printf "%-80b" "Synch & Restore $APP_BANNER FireWall State" #| log

  nfBuckets=($(ipset $LIST | grep $BLOCK_APPLN_TAG | sort -u | awk {'print $2'}))
  for categoryName in ${nfBuckets[@]-}
  do
    [[ "$categoryName" == *"$CIDR_TAG"* ]]       && { tag=$CIDR_TAG; }  || { tag=$IP_TAG; }
    [[ "$categoryName" == *"$WHITE_LIST_TAG"* ]] && WHITE_LIST_PROC=$ON || WHITE_LIST_PROC=$OFF
    create_net_filters $categoryName $tag > /dev/null 2>&1
  done
  unset nfBuckets
  WHITE_LIST_PROC=$OFF

  eval "${IPTABLES_SAVE_CMD}"
  return $EXIT_CODE
}


remove_file1_from_file2 ()
{
  local file1="${1:-}" file2="${2:-}" tempFile="$2$TEMP_FILE_EXT"
  declare -i beforeCount=0 afterCount=0

  #log "START remove file1 : $file1 from file2: $file2 tempFile: $tempFile"
  [ ! -f "$file1" -o ! -f "$file2" ] && { EXIT_CODE=$EXIT_ERROR; return $EXIT_CODE; }

  EXIT_CODE=$EXIT_NORMAL

  beforeCount=$(wc -l "$file2" 2> /dev/null | awk '{print $1}')

  grep -Fvxf "$file1" "$file2" > "$tempFile" 2> /dev/null      || EXIT_CODE=$EXIT_ERROR
  mv "$tempFile" "$file2"                     > /dev/null 2>&1 || EXIT_CODE=$EXIT_ERROR

  afterCount=$(wc -l "$file2" 2> /dev/null | awk '{print $1}')

  echo "$(($beforeCount-$afterCount))"

  #log "END remove_file1_from_file2"
  return $EXIT_CODE
}

remove_category_from_category ()
{
  local category="${1:-}" fromCategory="${2:-}"
  local outputFile="" cidrOutputFile="" sortFile="" cidrSortFile="" catg=""

  [ -z "$category" -o -z "$fromCategory" ] && \
  {
    printf "ALERT: Invalid parameters. Remove $CATEGORIES_TAG : $category From : $fromCategory" | log;
    EXIT_CODE=$EXIT_ERROR;
    return $EXIT_CODE;
  }

  [ "$category" == "$fromCategory" ] && fromCategory=$ALL

  printf "Removing $category from $fromCategory\n" | log

  # clear Array
  ipArray=() fndIpArray=() cidrArray=() webArray=()

  outputFile="$DIR_REFRESH/$category$REFRESH_FILE_EXT"
  cidrOutputFile="$DIR_REFRESH/$category$CIDR_FILE_EXT"
  sortFile="$outputFile$SORT_FILE_EXT"
  cidrSortFile="$cidrOutputFile$SORT_FILE_EXT"

  [ ! -f "$outputFile" -o ! -f "$cidrOutputFile" ] && \
  { EXIT_CODE=$EXIT_ERROR; return $EXIT_CODE; }

  EXIT_CODE=$EXIT_NORMAL

  # Populate the Global Arrays with the category data such as whitelist
  ipArray=($(cat   "$outputFile"     2> /dev/null)) || EXIT_CODE=$EXIT_ERROR
  cidrArray=($(cat "$cidrOutputFile" 2> /dev/null)) || EXIT_CODE=$EXIT_ERROR
  [ $EXIT_CODE -ne $EXIT_NORMAL ]      && return $EXIT_CODE

  cli_create_add_del_diff $sortFile $cidrSortFile
  [ $EXIT_CODE -ne $EXIT_NORMAL ]      && return $EXIT_CODE

  delete_elements_from_category $fromCategory $sortFile $cidrSortFile "NWL"
  rm -rf "$sortFile" "$cidrSortFile"

  #log "Finished Removing $removeCategoryName from $CATEGORIES_TAG $removeFromCategoryName"
  return $EXIT_CODE
}

menu_setup ()
{
  local prompt="${1:-}"'->'" Enter Your Number Choice: "

  COLUMNS=15
  PS3="$prompt"

  clear;echo;echo -e "$APP_BANNER ""$UNDERLINED""${1:-}"$RESET"";echo;

  local options=(
    "Select Categories to Block"
    "Change Directory of $FILTERS_TAG"
    "Change Directory of $REFRESH_TAG"
    "Change Directory of $BACKUP_TAG"
    "Change Maximum Buckets per Category"
    "Change Maximum Entries per Bucket"
  )

  _MAX_BUCKETS=$MAX_BUCKETS
  _MAX_ENTRIES=$MAX_ENTRIES
  _DIR_FILTERS=$DIR_FILTERS
  _DIR_REFRESH=$DIR_REFRESH
  _DIR_BACKUP=$DIR_BACKUP

  select opt in "${options[@]-}" $NONE
  do
    case $opt in
         $NONE)
              echo;echo "Selected: $opt"
              break
              ;;
         *Block*)
              echo;echo "Selected: $opt"
              menu_categories "Select Categories Menu"
              break
              ;;
         *Names*)
              echo;echo "Selected: $opt"
              ;;
         *$FILTERS_TAG*)
              echo;echo "Selected: $opt from $DIR_FILTERS"
              pr="Enter new Filters Directory: "
              var='_DIR_FILTERS'

              cli_read_directory "$pr" "$var"
              prompt_confirm; [ $? -ne $EXIT_NORMAL ] && { _DIR_FILTERS=$DIR_FILTERS; continue; }
              echo;echo "$opt to $_DIR_FILTERS ....";echo;
              ;;
         *$REFRESH_TAG*)
              echo;echo "Selected: $opt from $DIR_REFRESH"
              pr="Enter new Refresh Directory: "
              var='_DIR_REFRESH'
              cli_read_directory "$pr" "$var"
              prompt_confirm; [ $? -ne $EXIT_NORMAL ] && { _DIR_REFRESH=$DIR_REFRESH; continue; }
              echo;echo "$opt to $_DIR_REFRESH ....";echo;
              ;;
         *$BACKUP_TAG*)
              echo;echo "Selected: $opt from $DIR_BACKUP"
              pr="Enter new Backup Directory: "
              var='_DIR_BACKUP'
              cli_read_directory "$pr" "$var"
              prompt_confirm; [ $? -ne $EXIT_NORMAL ] && { _DIR_BACKUP=$DIR_BACKUP; continue; }
              echo;echo "$opt to $_DIR_BACKUP ....";echo;
              ;;
         *Buckets*)
              echo; echo "Selected: $opt from $MAX_BUCKETS"
              pr="Enter new value (between 1 to 26): "
              var='_MAX_BUCKETS'
              cli_read_number_between "$pr" "$var" 1 26
              prompt_confirm; [ $? -ne $EXIT_NORMAL ] && { _MAX_BUCKETS=$MAX_BUCKETS; continue; }
              echo;echo "$opt to $_MAX_BUCKETS ....";echo;
              ;;
         *Entries*)
              echo; echo "Selected: $opt from $MAX_ENTRIES"
              pr="Enter new value (between 1 to $MAX_ENTRIES_LIMIT): "
              var='_MAX_ENTRIES'
              cli_read_number_between "$pr" "$var" 1 $MAX_ENTRIES_LIMIT
              prompt_confirm; [ $? -ne $EXIT_NORMAL ] && { _MAX_ENTRIES=$MAX_ENTRIES; continue; }
              echo;echo "$opt to $_MAX_ENTRIES ....";echo;
              ;;
         *)
              echo;echo -en "$RED"invalid choice"$RESET"
              ;;
    esac
  done

  return $EXIT_NORMAL
}

cli_read_directory ()
{
  local lprompt="${1:-'Enter new location: '}" lvariable="${2:-}" line=""

  while read -t$WAIT_TIME -r -n100 -p "$lprompt" line
  do
    [[ $line ]] || break

    is_directory $line; [ $? -ne $EXIT_NORMAL ] && \
    { echo -en "$RED"not a directory"$RESET"; continue; }

    eval $lvariable=$line; break;
  done

  return $EXIT_NORMAL
}

cli_read_number_between ()
{
  local lprompt="${1:-'Enter numbers: '}" lvariable="${2:-}" line=""
  declare -i lowerValue="${3:-}" uppperValue="${4:-}"

  is_number $lowerValue; [ $? -ne $EXIT_NORMAL ] && \
  { echo "Invalid lower value: $lowerValue";  EXIT_CODE=$EXIT_ERROR; return $EXIT_CODE; }

  is_number $uppperValue; [ $? -ne $EXIT_NORMAL ] && \
  { echo "Invalid upper value: $uppperValue"; EXIT_CODE=$EXIT_ERROR; return $EXIT_CODE; }

  while read -t$WAIT_TIME -r -n 10 -p "$lprompt" line
  do
    [[ $line ]] || break

    is_number $line; [ $? -ne $EXIT_NORMAL ] && \
    { echo -en "$RED"enter a number"$RESET"; continue; }

    [ "$line" -ge "$lowerValue" -a "$line" -le "$uppperValue" ] && \
    { eval $lvariable=$line; break; } || \
    { echo -en "$RED"invalid value"$RESET"; }
  done

  return $EXIT_NORMAL
}

is_directory ()
{
  [ -d "${1:-}" ] && return $EXIT_NORMAL || return $EXIT_ERROR
}

is_number ()
{
  echo "${1:-}" | grep -oEq $NUMBER_PATTERN
  [ $? -eq $EXIT_NORMAL ]     && return $EXIT_NORMAL || return $EXIT_ERROR
}

replace_config ()
{
  local file="${1:-}" search="${2:-}" replace="${3:-}"

  [ ! -f "$file" ] && { echo "Error: Not a File: $file";                       return $EXIT_ERROR; }
  [ -z "$search" ] && { echo "Error: Empty Search: $search Replace: $replace"; return $EXIT_ERROR; }
  grep -Ev "$search" "$file" 2> /dev/null > "$file$TEMP_FILE_EXT"
  echo "$replace" >> "$file$TEMP_FILE_EXT"
  mv "$file$TEMP_FILE_EXT" "$file"

  return $EXIT_NORMAL
}

update_config ()
{
  EXIT_CODE=$EXIT_NORMAL

  # before the last if any / from directory
  _DIR_FILTERS="${_DIR_FILTERS%/}"
  _DIR_REFRESH="${_DIR_REFRESH%/}"
  _DIR_BACKUP="${_DIR_BACKUP%/}"

  [ "$MAX_BUCKETS" -ne "$_MAX_BUCKETS" ] && \
  { replace_config $IPBLOCKER_CONFIG "MAX_BUCKETS=$MAX_BUCKETS" "MAX_BUCKETS=$_MAX_BUCKETS";
    EXIT_CODE=$?; }

  [ "$MAX_ENTRIES" -ne "$_MAX_ENTRIES" ] && \
  { replace_config $IPBLOCKER_CONFIG "MAX_ENTRIES=$MAX_ENTRIES" "MAX_ENTRIES=$_MAX_ENTRIES";
    EXIT_CODE=$?; }

  [ "$DIR_FILTERS"  != "$_DIR_FILTERS" ] && \
  { cp -ap $DIR_FILTERS/* $_DIR_FILTERS 2> /dev/null;
    replace_config $IPBLOCKER_CONFIG "DIR_FILTERS=$DIR_FILTERS" "DIR_FILTERS=$_DIR_FILTERS";
    EXIT_CODE=$?; }

  [ "$DIR_REFRESH"  != "$_DIR_REFRESH" ] && \
  { cp -ap $DIR_REFRESH/* $_DIR_REFRESH 2> /dev/null;
    replace_config $IPBLOCKER_CONFIG "DIR_REFRESH=$DIR_REFRESH" "DIR_REFRESH=$_DIR_REFRESH";
    EXIT_CODE=$?; }

  [ "$DIR_BACKUP"   != "$_DIR_BACKUP" ]  && \
  { cp -ap $DIR_BACKUP/*  $_DIR_BACKUP 2> /dev/null;
    replace_config $IPBLOCKER_CONFIG "DIR_BACKUP=$DIR_BACKUP"   "DIR_BACKUP=$_DIR_BACKUP";
    EXIT_CODE=$?; }

  return $EXIT_CODE
}

backup_system ()
{
  EXIT_CODE=$EXIT_NORMAL

  mkdir -p "$DIR_BACKUP"
  mkdir -p "$DIR_BACKUP/$FILTERS_TAG"
  mkdir -p "$DIR_BACKUP/$REFRESH_TAG"

  cp -ap $DIR_SCRIPTS/*$BLOCK_APPLN_TAG*.sh $DIR_BACKUP              2> /dev/null || EXIT_CODE=$?
  cp -ap $IPBLOCKER_CONFIG                  $DIR_BACKUP              2> /dev/null || EXIT_CODE=$?

  cp -ap $DIR_FILTERS/*$FILTER_FILE_EXT     $DIR_BACKUP/$FILTERS_TAG 2> /dev/null || EXIT_CODE=$?
  cp -ap $DIR_FILTERS/*$REFRESH_FILE_EXT    $DIR_BACKUP/$FILTERS_TAG 2> /dev/null || EXIT_CODE=$?

  cp -ap $DIR_REFRESH/*$REFRESH_FILE_EXT    $DIR_BACKUP/$REFRESH_TAG 2> /dev/null || EXIT_CODE=$?
  cp -ap $DIR_REFRESH/*$CIDR_FILE_EXT       $DIR_BACKUP/$REFRESH_TAG 2> /dev/null || EXIT_CODE=$?
  cp -ap $DIR_REFRESH/*$ERROR_FILE_EXT      $DIR_BACKUP/$REFRESH_TAG 2> /dev/null || EXIT_CODE=$?

  cp -ap "$IPSET_SAVE_FILE"                 $DIR_BACKUP/$REFRESH_TAG 2> /dev/null || EXIT_CODE=$?
  cp -ap "$IPTABLES_SAVE_FILE"              $DIR_BACKUP/$REFRESH_TAG 2> /dev/null || EXIT_CODE=$?

  return $EXIT_CODE
}

restore_from_backup ()
{
  EXIT_CODE=$EXIT_NORMAL

  [ ! -d "$DIR_BACKUP" ]              && return $EXIT_ERROR
  [ ! -d "$DIR_BACKUP/$FILTERS_TAG" ] && return $EXIT_ERROR
  [ ! -d "$DIR_BACKUP/$REFRESH_TAG" ] && return $EXIT_ERROR

  cp -ap  $DIR_SCRIPTS/*$BLOCK_APPLN_TAG*.sh          $DIR_SCRIPTS 2> /dev/null || EXIT_CODE=$?
  cp -ap  $IPBLOCKER_CONFIG                           $DIR_SCRIPTS 2> /dev/null || EXIT_CODE=$?

  cp -ap  $DIR_BACKUP/$FILTERS_TAG/*$FILTER_FILE_EXT  $DIR_FILTERS 2> /dev/null || EXIT_CODE=$?
  cp -ap  $DIR_BACKUP/$FILTERS_TAG/*$REFRESH_FILE_EX  $DIR_FILTERS 2> /dev/null || EXIT_CODE=$?

  cp -ap  $DIR_BACKUP/$REFRESH_TAG/*$REFRESH_FILE_EX  $DIR_REFRESH 2> /dev/null || EXIT_CODE=$?
  cp -ap  $DIR_BACKUP/$REFRESH_TAG/*$CIDR_FILE_EXT    $DIR_REFRESH 2> /dev/null || EXIT_CODE=$?
  cp -ap  $DIR_BACKUP/$REFRESH_TAG/*$ERROR_FILE_EXT   $DIR_REFRESH 2> /dev/null || EXIT_CODE=$?

  return $EXIT_CODE
}

###
# Multi Selection Menu credit : MestreLion and Nathan Davieau
# https://serverfault.com/questions/144939/multi-select-menu-in-bash-script/298312#298312
###
menu_categories ()
{
  local prompt="[$1] Enter Number to Select or Unselect (ENTER when done): " ERROR=" "
  local options=() choices=()
  local on=$CHECK_MARK off=" " modified=0

  menu_categories_turn_on

  options=("${CATEGORY_LIST_ARRAY[@]-}")

  while menu_categories_show "${1:-}" && read -t$WAIT_TIME -r -p "$prompt" -n1 SELECTION && [[ -n "$SELECTION" ]]
  do
    if [[ "$SELECTION" == *[[:digit:]]* && $SELECTION -ge 1 && $SELECTION -le ${#options[@]} ]]
    then
      (( SELECTION-- ))
      [[ "${choices[SELECTION]-}" == "$on" ]] && choices[SELECTION]="$off" || choices[SELECTION]="$on"
      modified=1
      ERROR=" "
    else
      ERROR=""$RED"invalid choice: $SELECTION"$RESET""
    fi
  done

  menu_categories_selected
}

menu_categories_turn_on ()
{
  local category=""
  declare -i ctr=0

  # Get current category selection from categories file or seed values
  [ -f $CATEGORY_LIST ] && \
  { CATEGORY_LIST_SELECTED_ARRAY=($(cat "$CATEGORY_LIST" 2> /dev/null | sort -u)); } || \
  { CATEGORY_LIST_SELECTED_ARRAY=("${CATEGORY_LIST_ARRAY[@]-}"); }

  # Turn current category Selection to ON
  for category in ${CATEGORY_LIST_ARRAY[@]-}
  do
    in_array $category ${CATEGORY_LIST_SELECTED_ARRAY[@]-}
    [ $EXIT_CODE -eq $EXIT_NORMAL ] && { choices[$ctr]="$on"; }
    ctr+=1
  done
}

menu_categories_show ()
{
  clear;echo;echo -e "$APP_BANNER ""$UNDERLINED""${1:-}"$RESET"";echo;

  for NUM in ${!options[@]}
  do
    echo -e "[""${choices[NUM]:- }""]" $(( NUM+1 ))") ${options[NUM]}"
  done

  echo -e "$ERROR"
}

#Actions to take based on selection
menu_categories_selected ()
{
  # If its a fresh install turn on modified
  categories_subscribed; [ $EXIT_CODE -ne $EXIT_NORMAL ] && modified=1

  # Check to see if any selection was made
  (( ! $modified )) && { return $EXIT_NORMAL; }

  mkdir -p "$DIR_FILTERS"

  rm -rf $CATEGORY_LIST$TEMP_FILE_EXT; touch $CATEGORY_LIST$TEMP_FILE_EXT;
  printf "\nSelected Categories:"

  for slctd in ${!choices[@]}
  do
   [[ "${choices[slctd]}" =  "$on" ]] && \
   { echo -en " ${options[slctd]}"; echo ${options[slctd]} >> $CATEGORY_LIST$TEMP_FILE_EXT; }
  done

  echo;echo;
  prompt_confirm; [ $? -eq $EXIT_NORMAL ] && { menu_categories_add_delete; }

  rm -rf $CATEGORY_LIST$TEMP_FILE_EXT
}

menu_categories_add_delete ()
{
  local addedCategories=() deletedCategories=() addCatg="" delCatg=""

  [ ! -f "$CATEGORY_LIST" ] && touch "$CATEGORY_LIST"

  addedCategories=($($DIFF_CMD_EXP   $CATEGORY_LIST $CATEGORY_LIST$TEMP_FILE_EXT | grep $DIFF_ADD_PATTERN | tr -d "$DIFF_ADD_PATTERN "))
  deletedCategories=($($DIFF_CMD_EXP $CATEGORY_LIST $CATEGORY_LIST$TEMP_FILE_EXT | grep $DIFF_DEL_PATTERN | tr -d "$DIFF_DEL_PATTERN "))

  echo;echo -en "  Added $CATEGORIES_TAG:"
  for addCatg in ${addedCategories[@]-}
  do
    echo -en " $addCatg"
  done

  echo;echo -en "Deleted $CATEGORIES_TAG:"
  for delCatg in ${deletedCategories[@]-}
  do
    echo -en " $delCatg"
  done
  echo;echo;

  for delCatg in ${deletedCategories[@]-}
  do
    un_install $delCatg
  done

  [ ! -z "$addCatg" ] && \
  { system_setup;
    printf "%-60s\n" "NOTE: Auto $REFRESH_TAG Added $CATEGORIES_TAG is not done NOW to prevent conflict with $REFRESH_TAG Schedules";
    printf "%-60s\n" "Please $REFRESH_TAG $CATEGORIES_TAG Added manually if they are needed immediately ...."; }

  mv -f $CATEGORY_LIST$TEMP_FILE_EXT $CATEGORY_LIST
}

time_now      () { echo $(date +"%Y%m%d-%H%M%S"); }

remove_blanks ()
{
  [ -z "$*" ] && return $EXIT_ERROR
  eval "${REMOVE_EMPTY_LINES}" "$*"
}
