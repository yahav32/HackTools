# Subdomain finder tool
import requests
import sys
import curses
from curses import wrapper


class Subfinder:
    def __init__(self, domain: str, wordlist_path: str=None):
        self.domain = domain
        self.wordlist_path = wordlist_path

    def print_message(self, message: str, stdscr, y: int, x: int, msg_type: str):
        if msg_type == "finding":
            color = curses.color_pair(1)
        elif msg_type == "error":
            color = curses.color_pair(2)
        elif msg_type == "note":
            color = curses.color_pair(3)
        else:
            color = curses.A_NORMAL

        max_y, max_x = stdscr.getmaxyx()
        if 0 <= y < max_y and 0 <= x < max_x:
            truncated_message = message[:max_x - x - 1]
            stdscr.addstr(y, x, truncated_message, color)
            stdscr.refresh()
        
    def read_wordlist(self, stdscr, y: int):
        if self.wordlist_path:
            try:
                with open(self.wordlist_path, 'r') as f:
                    wordlist = f.readlines()
                return [word.strip() for word in wordlist], y
            except FileNotFoundError:
                self.print_message(f"[-] Wordlist file not found: {self.wordlist_path}", stdscr, y, 0, "error")
                return [], y + 1
        else:
            self.print_message("[-] No wordlist provided", stdscr, y, 0, "note")
            return [], y + 1
            
    def run(self, stdscr):
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        
        y = 0
        wordlist, y = self.read_wordlist(stdscr, y)
        if not wordlist:
            self.print_message("Press any key to exit...", stdscr, y, 0, "note")
            stdscr.getch()
            return
            
        self.print_message(f"[*] Starting scan for {self.domain}...", stdscr, y, 0, "note")
        y += 1
        
        for word in wordlist:
            subdomain = f"{word}.{self.domain}"
            try:
                response = requests.get(f"http://{subdomain}")
                if response.status_code == 200:
                    self.print_message(f"[+] Found subdomain: {subdomain}", stdscr, y, 0, "finding")
                    y += 1
            except requests.exceptions.RequestException:
                pass
                
        self.print_message("Scan finished. Press any key to exit...", stdscr, y, 0, "note")
        stdscr.getch()


def main(stdscr):
    if len(sys.argv) < 3:
        curses.use_default_colors()
        curses.init_pair(2, curses.COLOR_RED, -1)
        stdscr.addstr(0, 0, "Usage: python Subfinder.py <domain> <wordlist_path>", curses.color_pair(2))
        stdscr.addstr(1, 0, "Press any key to exit...", curses.A_NORMAL)
        stdscr.refresh()
        stdscr.getch()
        return

    subfinder = Subfinder(sys.argv[1], sys.argv[2])
    subfinder.run(stdscr)

if __name__ == "__main__":
    wrapper(main)
    
            
    
