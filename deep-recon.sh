#!/bin/bash

# ================================
# Deep Subdomain Enumeration Script
# Author: ChatGPT
# ================================
# REQUIREMENTS:
# - Go tools: subfinder, amass, findomain, puredns, dnsx, httpx, gotator, cero
# - Python tools: favfreak, AnalyticsRelationships
# - Other: gospider, dnsvalidator, ffuf
# ================================

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain=$1
output_dir="recon-$domain"
mkdir -p "$output_dir"/{passive,active,horizontal,permutations,recursive,scraping,vhosts}

echo "[+] Starting deep subdomain enumeration for: $domain"
sleep 2

# -------------------------------
# STEP 1: Passive Enumeration
# -------------------------------
echo "[+] Running passive subdomain enumeration..."
subfinder -d $domain -all -silent -o $output_dir/passive/subfinder.txt
findomain --quiet -t $domain > $output_dir/passive/findomain.txt
amass enum -passive -d $domain -o $output_dir/passive/amass.txt

cat $output_dir/passive/*.txt | sort -u > $output_dir/passive/all_passive.txt

# -------------------------------
# STEP 2: Active Enumeration (PureDNS brute force)
# -------------------------------
echo "[+] Running PureDNS brute force..."
wget -q https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O $output_dir/best-dns-wordlist.txt
wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt -O $output_dir/resolvers.txt
puredns bruteforce $output_dir/best-dns-wordlist.txt $domain -r $output_dir/resolvers.txt -w $output_dir/active/dns_brute.txt

# -------------------------------
# STEP 3: Permutations
# -------------------------------
echo "[+] Generating permutations with gotator..."
gotator -sub $output_dir/passive/all_passive.txt -perm dns_permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md | sort -u > $output_dir/permutations/perms.txt
puredns resolve $output_dir/permutations/perms.txt -r $output_dir/resolvers.txt -w $output_dir/permutations/resolved_perms.txt

# -------------------------------
# STEP 4: Favicon Hashing (FavFreak)
# -------------------------------
echo "[+] Running Favicon Hashing (FavFreak)..."
cat $output_dir/passive/all_passive.txt | httpx -silent | python3 /home/nigga/Documents/Tools/FavFreak/favfreak.py -o $output_dir/favicons.txt

# -------------------------------
# STEP 5: Google Analytics Enumeration
# -------------------------------
echo "[+] Finding Google Analytics relationships..."
python3 ~/Documents/Tools/AnalyticsRelationships/Python/analyticsrelationships.py -u https://$domain > $output_dir/analytics.txt

# -------------------------------
# STEP 6: VHost Enumeration
# -------------------------------
echo "[+] Enumerating virtual hosts with FFUF..."
cat $output_dir/passive/all_passive.txt | httpx -ip -silent -o $output_dir/vhosts/httpx_ip_map.txt
cut -d ' ' -f2 $output_dir/vhosts/httpx_ip_map.txt | sort -u > $output_dir/vhosts/ips.txt

for ip in $(cat $output_dir/vhosts/ips.txt); do
    ffuf -u http://$ip -H "Host: FUZZ.$domain" -w $output_dir/best-dns-wordlist.txt -mc 200 -t 50 -o $output_dir/vhosts/ffuf_$ip.json -of json
done

# -------------------------------
# STEP 7: JS Scraping & Crawling
# -------------------------------
echo "[+] Scraping JavaScript files for more subdomains..."
cat $output_dir/passive/all_passive.txt | httpx -silent > $output_dir/probed_urls.txt
gospider -S $output_dir/probed_urls.txt --js -t 50 -d 3 --sitemap --robots -w -r > $output_dir/gospider.txt
cat $output_dir/gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep ".${domain}$" | sort -u > $output_dir/scraping/scraped_subs.txt
puredns resolve $output_dir/scraping/scraped_subs.txt -r $output_dir/resolvers.txt -w $output_dir/scraping/resolved_scraped.txt

# -------------------------------
# STEP 8: Recursive Enumeration
# -------------------------------
echo "[+] Running recursive enumeration..."
for sub in $(cat $output_dir/passive/all_passive.txt); do
    subfinder -d $sub -silent | anew -q $output_dir/recursive/recursive.txt
    assetfinder --subs-only $sub | anew -q $output_dir/recursive/recursive.txt
    amass enum -timeout 2 -passive -d $sub | anew -q $output_dir/recursive/recursive.txt
done

# -------------------------------
# STEP 9: Final Consolidation & Live Filtering
# -------------------------------
echo "[+] Consolidating all results and filtering live subdomains..."
cat $output_dir/**/**/*.txt | sort -u > $output_dir/all_subdomains.txt
cat $output_dir/all_subdomains.txt | httpx -random-agent -retries 2 -silent -o $output_dir/live_subdomains.txt

echo "[+] Recon completed. Results saved in $output_dir/"
