import argparse
import curses
import requests
import sys
from curses import wrapper
from urllib.parse import urlparse


class WebScanner:
    def __init__(self, target: str, wordlist_path: str, mode: str):
        self.target = target
        self.wordlist_path = wordlist_path
        self.mode = mode

        if not self.target.startswith(("http://", "https://")):
            self.target = f"http://{self.target}"

        parsed = urlparse(self.target)
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port

    def print_message(self, message, stdscr, y, msg_type="note"):
        colors = {
            "find": curses.color_pair(1),
            "error": curses.color_pair(2),
            "note": curses.color_pair(3),
        }

        max_y, max_x = stdscr.getmaxyx()

        if 0 <= y < max_y:
            message = message[:max_x - 1]
            stdscr.addstr(y, 0, message, colors.get(msg_type, curses.A_NORMAL))
            stdscr.refresh()

    def read_wordlist(self, stdscr, y):
        try:
            with open(self.wordlist_path, "r", encoding="utf-8") as f:
                words = [line.strip() for line in f if line.strip()]

            return words, y

        except FileNotFoundError:
            self.print_message(f"[-] Wordlist not found: {self.wordlist_path}", stdscr, y, "error")
            return [], y + 1

        except OSError as e:
            self.print_message(f"[-] Could not read wordlist: {e}", stdscr, y, "error")
            return [], y + 1

    def build_base_url(self):
        url = f"{self.scheme}://{self.host}"

        if self.port:
            url += f":{self.port}"

        return url

    def scan_subdomains(self, words, stdscr, y):
        for word in words:
            subdomain = f"{word}.{self.host}"
            url = f"{self.scheme}://{subdomain}"
            if self.port:
                url += f":{self.port}"
            try:
                response = requests.get(url, timeout=0.5, allow_redirects=False)

                if response.status_code in (200, 302, 301, 401, 403):
                    self.print_message(f"[+] Subdomain: {subdomain} [{response.status_code}]", stdscr, y, "find")
                    y += 1

            except requests.RequestException:
                pass

        return y

    def scan_vhosts(self, words, stdscr, y):
        base_url = self.build_base_url()

        for word in words:
            vhost = f"{word}.{self.host}"

            headers = {"Host": vhost}

            try:
                response = requests.get(base_url, headers=headers, timeout=0.5, allow_redirects=False)

                if response.status_code in (200, 302, 301, 401, 403):
                    self.print_message(f"[+] VHost: {vhost} [{response.status_code}]", stdscr, y, "find")
                    y += 1

            except requests.RequestException:
                pass

        return y

    def scan_directories(self, words, stdscr, y):
        base_url = self.build_base_url()

        for word in words:
            url = f"{base_url}/{word}"

            try:
                response = requests.get(url, timeout=0.5, allow_redirects=False)

                if response.status_code in (200, 302, 301, 401, 403):
                    self.print_message(f"[+] Directory: /{word} [{response.status_code}]", stdscr, y, "find")
                    y += 1

            except requests.RequestException:
                pass

        return y

    def run(self, stdscr):
        curses.use_default_colors()

        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)

        y = 0

        words, y = self.read_wordlist(stdscr, y)

        if not words:
            self.print_message("Press any key to exit...", stdscr, y, "note")
            stdscr.getch()
            return

        self.print_message(f"[*] Target: {self.target}", stdscr, y, "note")
        y += 1

        self.print_message(f"[*] Mode: {self.mode}", stdscr, y, "note")
        y += 1

        self.print_message(f"[*] Words: {len(words)}", stdscr, y, "note")
        y += 2

        if self.mode == "subdomain":
            y = self.scan_subdomains(words, stdscr, y)

        elif self.mode == "vhost":
            y = self.scan_vhosts(words, stdscr, y)

        elif self.mode == "directory":
            y = self.scan_directories(words, stdscr, y)

        self.print_message("[*] Scan finished. Press any key to exit...", stdscr, y, "note")

        stdscr.getch()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Subdomain, VHost, and Directory Scanner",
        usage="python Subfinder.py -w <wordlist> -u <url> [-s | -d | -v]"
    )
    parser.add_argument("-w", dest="wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-u", dest="url", required=True, help="Target URL")

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-s", "--subdomain", dest="subdomain", action="store_true", help="Subdomain enumeration mode")
    mode_group.add_argument("-d", "--directory", dest="directory", action="store_true", help="Directory enumeration mode")
    mode_group.add_argument("-v", "--vhost", dest="vhost", action="store_true", help="VHost enumeration mode")

    return parser.parse_args()


def main(stdscr, args):
    if args.subdomain:
        mode = "subdomain"
    elif args.directory:
        mode = "directory"
    elif args.vhost:
        mode = "vhost"

    scanner = WebScanner(target=args.url, wordlist_path=args.wordlist, mode=mode)
    scanner.run(stdscr)


if __name__ == "__main__":
    args = parse_args()
    wrapper(main, args)
