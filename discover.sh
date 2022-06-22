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
mkdir ./output 2> /dev/null

##LAUNCH REVERSEWHOIS
echo -e "\nRUNNING \e[31m[KNOCKKNOCK]\e[0m"
knockknock -n $1 -p |grep -v "\[" |tee ./output/$1.reversewhois.log
echo "FOUND HORIZONTAL DOMAINS [$(cat ./output/$1.reversewhois.log  | wc -l)]"
echo "RUNNING REVERSEWHOIS \e[32mFINISH\e[0m"

## LAUNCH ACTIVE AMASS
echo -e "\nRUNNING \e[31m[AMASS ACTIVE]\e[0m"
amass enum -config /root/config.ini -passive -d $1 -o ./output/$1.amassactive.txt
echo "FOUND SUBDOMAINS [$(cat ./output/$1.amassactive.txt  | wc -l)]"
echo "RUNNING AMASS \e[32mFINISH\e[0m"

## LAUNCH ASSETFINDER
echo -e "\nRUNNING \e[31m[ASSETFINDER]\e[0m"
assetfinder -subs-only $1 > ./output/$1.assetfinder.txt
echo "FOUND SUBDOMAINS [$(cat ./output/$1.assetfinder.txt | wc -l)]"
echo "RUNNING ASSETFINDER \e[32mFINISH\e[0m"

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
sort  ./output/$1.*.txt | uniq > ./output/$1.alldomains.txt
echo "REMOVING DUPLICATES \e[32mFINISH\e[0m"

## LAUNCH LIVEHOSTS
echo -e "\nRUNNING \e[31m[FILTERING THE BAD ONES]\e[0m"
rm ./output/$1.live_subdomains.log 2> /dev/null
cat ./output/$1.alldomains.txt | dnsx > ./output/$1.live_subdomains_wild.log
cat ./output/$1.live_subdomains_wild.log |httpx |goverview probe -N -c 500 |sort -u -t';' -k2,14 |cut -d ';' -f1 > ./output/$1.httpx.log
cat ./output/$1.httpx.log | httpx -silent -tech-detect -title > ./output/$1.httpx_tech.log
cat ./output/$1.live_subdomains_wild.log | dnsx -wd $1 > ./output/$1.live_subdomains.log
rm ./output/$1.live_subdomains_wild.log
rm ./output/$1.alldomains.txt 2> /dev/null
rm ./output/$1.subfinder.txt 2> /dev/null
rm ./output/$1.dnsbuffer.txt 2> /dev/null
rm ./output/$1.assetfinder.txt 2> /dev/null
rm ./output/$1.amassactive.txt 2> /dev/null

echo "TOTAL GOOD SUBDOMAINS [$(cat ./output/$1.live_subdomains.log | wc -l)]"
echo "FILTERING THE BAD ONES \e[32mFINISH\e[0m"

## LAUNCH LIVEHOSTS
echo -e "\nRUNNING \e[31m[RESOLVING SUBS TO IP ADDRESSES]\e[0m"
cat ./output/$1.live_subdomains.log | dnsx -silent -a -resp-only |sort -u > ./output/$1.domain_ips.txt
echo "RESOLVING SUBS TO IP ADDRESSES \e[32mFINISH\e[0m"

echo " "
echo "NEED TO LOOK UP [$(cat ./output/$1.domain_ips.txt | wc -l)] ADDRESSES FOR ASSIGNED SUBNETS"

echo -e "\nRUNNING \e[31m[FINDING REGISTERED SUBNETS]\e[0m"
cat ./output/$1.domain_ips.txt |xargs -n1 -P 1500 -I% curl -s http://networktools.nl/whois/$url% |grep -i -B 6 "$(echo $1 |cut -d '.' -f1 | rev |cut -c1-4 |rev)" |grep CIDR |cut -d : -f2 |tr , "\n"| awk '{$1=$1};1' |sort -u > ./output/$1.subnets.txt
echo "FINDING REGISTERED SUBNETS \e[32mFINISH\e[0m"
rm ./output/$1.domain_ips.txt 2> /dev/null

echo -e "\nRUNNING \e[31m[FINDING OWNED ASN SUBNETS]\e[0m"
cat ./output/$1.live_subdomains.log | dnsx -silent -cname -resp |sort -u > ./output/$1.cloudhost.log
cat ./output/$1.subnets.txt |while read ip ;do whois -h whois.cymru.com " -v $ip" |grep -i "$(echo $1 |cut -d '.' -f1 | rev |cut -c1-4 |rev)" |cut -d '|' -f2 |awk '{$1=$1};1'; done > ./output/$1.asn.txt
cat ./output/$1.asn.txt |while read ip ;do whois -h whois.radb.net -i origin -T route $(whois -h whois.radb.net $ip | grep origin: | cut -d ' ' -f 6 | head -1) | grep -w "route:" | awk '{print $NF}' ;done|sort -n >> ./output/$1.subnets.txt
sort -u ./output/$1.subnets.txt > ./output/$1.live_subnets.log
rm ./output/$1.subnets.txt 2> /dev/null
rm ./output/$1.asn.txt 2> /dev/null
echo "FINDING OWNED ASN SUBNETS \e[32mFINISH\e[0m"
echo " "
echo -e "\x1B[01;91m \nFOUND [$(cat ./output/$1.reversewhois.log | wc -l)] HORIZONTAL DOMAINS in ./output/$1.reversewhois.log. \nFOUND [$(cat ./output/$1.live_subnets.log | wc -l)] SUBNETS IN ./output/$1.live_subnets.log. \nFOUND [$(cat ./output/$1.cloudhost.log | wc -l)] CLOUD HOSTED DOMAINS in ./output/$1.cloudhost.log. \nFOUND [$(cat ./output/$1.live_subdomains.log | wc -l)] SUBDOMAINS in ./output/$1.live_subdomains.log. \nFOUND [$(cat ./output/$1.httpx.log | wc -l)] WEB APPS in ./output/$1.httpx.log. \nFOUND MSFT AD, [$(grep "outlook.com" ./output/$1.cloudhost.log > /dev/null && echo TRUE || echo FALSE)]. \nFOUND Amazon Cloud, [$(grep "amazonaws.com" ./output/$1.cloudhost.log > /dev/null && echo TRUE || echo FALSE)]. \nFOUND MSFT Azure Cloud, [$(grep "azure" ./output/$1.cloudhost.log > dev/null && echo TRUE || echo FALSE)]. \nFOUND Phishing addresses, [$(echo 'https://hunter.io/try/search/$1' |httpx -silent -match-string 'All the email addresses found for the domain name' > /dev/null && echo TRUE || echo FALSE)]. \x1B[0m"
find ./output -size 0 -delete 2> /dev/null
echo " "
echo -e "\e[31m[FINISHED. HACK SAFELY]\e[0m"

}

if [ -z "$1" ]
  then
    kill
else
        recon $1
fi