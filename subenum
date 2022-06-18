#!/usr/bin/env bash

D="$1"
OUT="$2"

assetfinder --subs-only $D >> $OUT
subfinder --silent -d $D >> $OUT
amass enum --passive -d $D >> $OUT
findomain -q --target $D >> $OUT
chaos -d $D -silent >> $OUT
sublist3r -d $D -n -o /tmp/domains > /tmp/sublist3rtmp; cat /tmp/domains >> $OUT
query="SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.$D'));"
(echo $D; echo $query | \
    psql -t -h crt.sh -p 5432 -U guest certwatch | \
    sed -e 's:^ *::g' -e 's:^*\.::g' -e '/^$/d' | \
    sed -e 's:*.::g';) | sort -u >> $OUT
curl -s "https://jldc.me/anubis/subdomains/$D" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep "$D" | grep -v "^\." | anew >> $OUT
curl -s "https://rapiddns.io/subdomain/$D?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u >> $OUT
curl -s "https://riddler.io/search/exportcsv?q=pld:$D" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u >> $OUT
curl -s "https://securitytrails.com/list/apex_domain/$D" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".$D" | sort -u >> $OUT
curl -s "https://crt.sh/?q=%.$D&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | anew >> $OUT
cat $OUT | haktrails subdomains >> $OUT
sort -u $OUT -o $OUT
