#!/bin/bash -i

banner (){
echo -e "
@nullenc0de"
}

kill (){
        banner
    echo -e "ASSET RECONNAISSANCE TOOL"
    echo "USAGE: recon.sh domain.com"
    exit 1
}

recon (){
banner

echo -e "\e[31m[STARTING]\e[0m"

##SUB DOMAIN DISCOVERY
mkdir ./output

## LAUNCH ACTIVE AMASS
echo -e "\nRUNNING \e[31m[AMASS ACTIVE]\e[0m"
amass enum -passive -d $1 -o ./output/$1.amassactive.txt  
echo "FOUND SUBDOMAINS [$(cat ./output/$1.amassactive.txt  | wc -l)]"
echo "RUNNING AMASS \e[32mFINISH\e[0m"

## LAUNCH ASSETFINDER
echo -e "\nRUNNING \e[31m[ASSETFINDER]\e[0m"
assetfinder -subs-only $1 > ./output/$1.assetfinder.txt
echo "FOUND SUBDOMAINS [$(cat ./output/$1.assetfinder.txt | wc -l)]"
echo "RUNNING ASSETFINDER \e[32mFINISH\e[0m"

## LAUNCH FINDOMAIN
echo -e "\nRUNNING \e[31m[FINDOMAIN]\e[0m"
findomain -t $1 -o ./output/$1
echo "FOUND SUBDOMAINS [$(cat ./output/$1.txt | wc -l)]"
echo "RUNNING FINDOMAIN \e[32mFINISH\e[0m"

## LAUNCH DNSBUFFER
echo -e "\nRUNNING \e[31m[DNSBUFFEROVER]\e[0m"
curl -s https://dns.bufferover.run/dns?q=.$1 | jq -r .FDNS_A[]|cut -d',' -f2 > ./output/$1.dnsbuffer.txt
echo "FOUND SUBDOMAINS [$(cat ./output/$1.dnsbuffer.txt | wc -l)]"
echo "RUNNING DNSBUFFER \e[32mFINISH\e[0m"

## LAUNCH SUBFINDER
echo -e "\nRUNNING \e[31m[SUBFINDER]\e[0m"
subfinder -d $1 -o ./output/$1.subfinder.txt 
echo "FOUND SUBDOMAINS [$(cat ./output/$1.subfinder.txt | wc -l)]"
echo "RUNNING SUBFINDER \e[32mFINISH\e[0m"

## REMOVING DUPLICATES
echo -e "\nRUNNING \e[31m[REMOVING DUPLICATES]\e[0m"
sort  ./output/*.txt | uniq > ./output/$1.alldomains.txt
echo "REMOVING DUPLICATES \e[32mFINISH\e[0m"

## LAUNCH LIVEHOSTS
echo -e "\nRUNNING \e[31m[FILTERING THE BAD ONES]\e[0m"
rm ./output/$1.live_subdomains.txt ||true
cat ./output/$1.alldomains.txt | filter-resolved -c 100 > ./output/$1.live_subdomains.log
rm ./output/$1.alldomains.txt ||true
rm ./output/$1.subfinder.txt ||true
rm ./output/$1.dnsbuffer.txt ||true
rm ./output/$1.txt ||true
rm ./output/$1.assetfinder.txt ||true
rm ./output/$1.amassactive.txt ||true

echo "TOTAL GOOD SUBDOMAINS [$(cat ./output/$1.live_subdomains.txt | wc -l)]"
echo "FILTERING THE BAD ONES \e[32mFINISH\e[0m"

## LAUNCH LIVEHOSTS
echo -e "\nRUNNING \e[31m[RESOLVING SUBS TO IP ADDRESSES]\e[0m"
cat ./output/$1.live_subdomains.txt | while read resolved; do host -t A "$resolved" | awk '{print $NF}' | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'; done |sort -u > ./output/$1.domain_ips.txt
echo "RESOLVING SUBS TO IP ADDRESSES \e[32mFINISH\e[0m"

echo -e "\nRUNNING \e[31m[FINDING REGISTERED SUBNETS]\e[0m"
cat ./output/$1.domain_ips.txt |while read url; do curl -s http://networktools.nl/whois/$url |grep -i -B 6 "$(echo $1 |cut -d '.' -f1 | rev |cut -c1-4 |rev)" |grep CIDR |cut -d : -f2 |tr , "\n"| awk '{$1=$1};1'; done |sort -u > ./output/$1.subnets.txt
echo "FINDING REGISTERED SUBNETS \e[32mFINISH\e[0m"
rm ./output/$1.domain_ips.txt ||true

echo -e "\nRUNNING \e[31m[FINDING OWNED ASN SUBNETS]\e[0m"
cat ./output/$1.subnets.txt |while read ip ;do whois -h whois.cymru.com " -v $ip" |grep -i "$(echo $1 |cut -d '.' -f1 | rev |cut -c1-4 |rev)" |cut -d '|' -f2 |awk '{$1=$1};1'; done > ./output/$1.asn.txt
cat ./output/$1.asn.txt |while read ip ;do whois -h whois.radb.net -i origin -T route $(whois -h whois.radb.net $ip | grep origin: | cut -d ' ' -f 6 | head -1) | grep -w "route:" | awk '{print $NF}' ;done|sort -n >> ./output/$1.subnets.txt
sort -u ./output/$1.subnets.txt > ./output/$1.live_subnets.log
rm ./output/$1.subnets.txt ||true
rm ./output/$1.asn.txt ||true
echo "FINDING OWNED ASN SUBNETS \e[32mFINISH\e[0m"
echo " "
echo "output live_subnets.txt and live_subdomains.txt in ./output/$(echo pwd)."
echo " "
echo -e "\e[31m[FINISHED. OUTPUT SAVED IN WORKING DIR]\e[0m"

}

if [ -z "$1" ]
  then
    kill
else
        recon $1
fi