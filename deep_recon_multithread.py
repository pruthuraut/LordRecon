import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

TOOLS_DIR = os.path.expanduser("~/Documents/Tools")
FAVFREAK = os.path.join(TOOLS_DIR, "FavFreak/favfreak.py")
ANALYTICS = os.path.join(TOOLS_DIR, "AnalyticsRelationships/Python/analyticsrelationships.py")
THREADS = 10
HTTPX_PORTS = "80,443,8080,8000,8081,8008,8888,8443,9000,9001,9090"


def run_command(command, shell=True):
    try:
        result = subprocess.run(command, shell=shell, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        print(f"Error running command: {command}\n{e}")
        return ""


def create_dirs(domain):
    root = f"recon-{domain}"
    for sub in ["passive", "active", "horizontal", "permutations", "recursive", "scraping", "vhosts"]:
        os.makedirs(os.path.join(root, sub), exist_ok=True)
    return root


def passive_recon(domain, root):
    output_dir = os.path.join(root, "passive")
    output_file = os.path.join(output_dir, "all_passive.txt")
    
    tools = [
        f"subfinder -d {domain} -all -silent",
        f"amass enum -passive -norecursive -noalts -d {domain}",
        f"assetfinder --subs-only {domain}",
        f"findomain -t {domain} --quiet"
    ]

    with open(output_file, "w") as f:
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = [executor.submit(run_command, cmd) for cmd in tools]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    f.write(result + "\n")

    run_command(f"sort -u {output_file} -o {output_file}")
    return output_file


def run_favfreak(subs_file, output_dir):
    out_file = os.path.join(output_dir, "favfreak.txt")
    command = f"cat {subs_file} | httpx -silent | python3 {FAVFREAK} -o {out_file}"
    run_command(command)
    return out_file


def run_analytics(domain, output_dir):
    out_file = os.path.join(output_dir, "analytics.txt")
    command = f"python3 {ANALYTICS} -u https://{domain} > {out_file}"
    run_command(command)
    return out_file


def run_dns_bruteforce(domain, root):
    wordlist = os.path.join(root, "best-dns-wordlist.txt")
    resolvers = os.path.join(root, "resolvers.txt")
    output = os.path.join(root, "active", "dns_brute.txt")

    run_command(f"wget -q https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O {wordlist}")
    run_command(f"wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt -O {resolvers}")
    run_command(f"puredns bruteforce {wordlist} {domain} -r {resolvers} -w {output}")


def run_permutations(domain, root):
    passive_file = os.path.join(root, "passive", "all_passive.txt")
    perms_file = os.path.join(root, "permutations", "perms.txt")
    resolved_file = os.path.join(root, "permutations", "resolved_perms.txt")
    resolvers = os.path.join(root, "resolvers.txt")

    run_command(f"gotator -sub {passive_file} -perm dns_permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md | sort -u > {perms_file}")
    run_command(f"puredns resolve {perms_file} -r {resolvers} -w {resolved_file}")


def run_vhost_enum(domain, root):
    vhost_dir = os.path.join(root, "vhosts")
    passive_file = os.path.join(root, "passive", "all_passive.txt")
    ip_map_file = os.path.join(vhost_dir, "httpx_ip_map.txt")
    ips_file = os.path.join(vhost_dir, "ips.txt")
    wordlist = os.path.join(root, "best-dns-wordlist.txt")

    run_command(f"cat {passive_file} | httpx -ip -silent -o {ip_map_file}")
    run_command(f"cut -d ' ' -f2 {ip_map_file} | sort -u > {ips_file}")

    with open(ips_file) as f:
        for ip in f.read().splitlines():
            out = os.path.join(vhost_dir, f"ffuf_{ip}.json")
            run_command(f"ffuf -u http://{ip} -H \"Host: FUZZ.{domain}\" -w {wordlist} -mc 200 -t 50 -o {out} -of json")


def run_js_scraping(domain, root):
    passive_file = os.path.join(root, "passive", "all_passive.txt")
    urls_file = os.path.join(root, "probed_urls.txt")
    gospider_out = os.path.join(root, "gospider.txt")
    scraped = os.path.join(root, "scraping", "scraped_subs.txt")
    resolved = os.path.join(root, "scraping", "resolved_scraped.txt")
    resolvers = os.path.join(root, "resolvers.txt")

    run_command(f"cat {passive_file} | httpx -silent > {urls_file}")
    run_command(f"gospider -S {urls_file} --js -t 50 -d 3 --sitemap --robots -w -r > {gospider_out}")
    run_command(f"cat {gospider_out} | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep \".{domain}$\" | sort -u > {scraped}")
    run_command(f"puredns resolve {scraped} -r {resolvers} -w {resolved}")


def recursive_enum(domain, root):
    passive_file = os.path.join(root, "passive", "all_passive.txt")
    recursive_out = os.path.join(root, "recursive", "recursive.txt")

    with open(passive_file) as f:
        subs = f.read().splitlines()

    for sub in subs:
        run_command(f"subfinder -d {sub} -silent | anew -q {recursive_out}")
        run_command(f"assetfinder --subs-only {sub} | anew -q {recursive_out}")
        run_command(f"amass enum -timeout 2 -passive -d {sub} | anew -q {recursive_out}")


def consolidate_and_probe(domain, root):
    all_file = os.path.join(root, "all_subdomains.txt")
    live_file = os.path.join(root, "live_subdomains.txt")

    run_command(f"cat {root}/**/**/*.txt | sort -u > {all_file}")
    run_command(f"cat {all_file} | httpx -random-agent -retries 2 -silent -ports {HTTPX_PORTS} > {live_file}")


def main(domain):
    print(f"[*] Starting recon for {domain}...")
    root = create_dirs(domain)

    print("[*] Running passive subdomain enumeration...")
    passive_recon(domain, root)

    print("[*] Running DNS bruteforce...")
    run_dns_bruteforce(domain, root)

    print("[*] Running permutations...")
    run_permutations(domain, root)

    print("[*] Running FavFreak fingerprinting...")
    run_favfreak(os.path.join(root, "passive", "all_passive.txt"), os.path.join(root, "passive"))

    print("[*] Running analytics relationships...")
    run_analytics(domain, os.path.join(root, "passive"))

    print("[*] Running VHost enumeration...")
    run_vhost_enum(domain, root)

    print("[*] Running JS scraping and crawling...")
    run_js_scraping(domain, root)

    print("[*] Running recursive enumeration...")
    recursive_enum(domain, root)

    print("[*] Consolidating results and probing live subdomains...")
    consolidate_and_probe(domain, root)

    print(f"[+] Recon complete. Results stored in: {root}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <domain>")
        sys.exit(1)

    main(sys.argv[1])
