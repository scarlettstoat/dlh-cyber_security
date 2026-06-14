#!/bin/bash
whois $1 | awk '/^[[:space:]]*(Registrant|Admin|Tech) /{line=$0; gsub(/^[[:space:]]+/,"",line); if(line~/Ext:/){sub(/Ext:.*$/,"Ext:,",line); print line; next} n=index(line,": "); field=substr(line,1,n-1); val=substr(line,n+2); if(field~/Street/) val=val" "; print field","val}' > $1.csv
