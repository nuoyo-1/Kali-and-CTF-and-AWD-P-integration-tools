#!/usr/bin/env python3
"""Double-click entrypoint. No third-party Python packages required."""
import json
import os
from pathlib import Path
import sys
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

def main():
    url = 'http://127.0.0.1:8765'
    try:
        with urllib.request.urlopen(url + '/api/health', timeout=1) as r:
            if json.loads(r.read()).get('app') == 'ctf-deck':
                webbrowser.open(url)
                return
    except Exception:
        pass
    data = ROOT / 'data'
    data.mkdir(exist_ok=True)
    log = (data / 'platform.log').open('a', encoding='utf-8', buffering=1)
    sys.stdout = sys.stderr = log
    try:
        from ctfhub.server import serve
        serve()
    except Exception as error:
        print(f'启动失败：{error}', flush=True)
        try:
            from tkinter import Tk, messagebox
            window = Tk()
            window.withdraw()
            messagebox.showerror('CTF Deck 启动失败',f'{error}\n\n日志：{data / "platform.log"}')
            window.destroy()
        except Exception:
            raise

if __name__ == '__main__':
    main()
