#!/usr/bin/env python3
"""
MC Plugin Scanner - Phiên bản GUI 'Vuông' (Tiếng Việt)
File này được thiết kế để chạy trực tiếp trên GitHub Codespaces hoặc máy local:
- Python 3.8+
- Khuyến nghị cài requests (pip install requests)
- Tùy chọn: yara-python, jadx trên PATH để quét nâng cao

Tính năng chính:
- GUI vuông, icon nhỏ, màu sắc nổi bật
- Tính hash (md5/sha1/sha256)
- Trích xuất plugin.yml
- Quét chuỗi tĩnh nâng cao (RCE, tải mã, API keys, IP cố định, base64 lớn...)
- YARA rules (nếu yara-python có sẵn)
- So sánh với bản chính thức: GitHub Releases / SpigotMC (nếu nhập link)
- VirusTotal (tùy chọn API key)
- Xuất báo cáo JSON + HTML

Hạn chế: Đây là công cụ heuristic. KHÔNG có công cụ static nào đảm bảo 100% phát hiện backdoor. Dùng để hỗ trợ, không thay thế phân tích chuyên sâu.

Hướng dẫn nhanh (Codespaces):
1. Push file này vào repo.
2. Mở Codespaces.
3. (Tùy chọn) pip install requests yara-python
4. python mc_plugin_scanner_vuong.py

"""

import os, sys, zipfile, hashlib, re, json, tempfile, shutil, subprocess, time
from pathlib import Path
try:
    import requests
except Exception:
    requests = None

# GUI
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except Exception:
    tk = None

# Optional YARA
try:
    import yara
except Exception:
    yara = None

# -------------------- Config & Patterns --------------------
SUSPICIOUS_PATTERNS = [
    r"Runtime\.getRuntime\(\)\.exec",
    r"ProcessBuilder\(",
    r"java\.net\.Socket",
    r"HttpURLConnection",
    r"openConnection\(",
    r"getOutputStream\(",
    r"new\s+Socket\(",
    r"Base64\.decode",
    r"Cipher\.getInstance",
    r"SecretKeySpec",
    r"MessageDigest\.getInstance",
    r"System\.exit\(",
    r"exec\(",
    r"\b(crack|cracked|leak|leaked|keygen|serial|patch|pirate)\b",
    r"password",
    r"api[_-]?key",
    r"license",
    r"update\(",
    r"check[_-]?license",
    r"authenticate",
    r"authServer",
    r"ClassLoader\.getSystemClassLoader\(\)",
    r"URLClassLoader",
    r"setAccessible\(",
]
IP_PATTERN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{100,}")

# YARA default rules (simple heuristics)
YARA_RULES = """
rule suspicious_plugin_keywords {
  strings:
    $a = "Runtime.getRuntime"
    $b = "new Socket"
    $c = "HttpURLConnection"
    $d = "api_key"
    $e = "check_license"
  condition:
    any of them
}
"""

# -------------------- Utilities --------------------

def hash_file(path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return {'md5': md5.hexdigest(), 'sha1': sha1.hexdigest(), 'sha256': sha256.hexdigest()}


def extract_plugin_yml(jar_path):
    try:
        with zipfile.ZipFile(jar_path, 'r') as z:
            for name in z.namelist():
                if name.endswith('plugin.yml'):
                    return z.read(name).decode(errors='ignore')
    except Exception:
        return None
    return None


def scan_strings_in_jar(jar_path):
    findings = []
    try:
        with zipfile.ZipFile(jar_path, 'r') as z:
            for name in z.namelist():
                if name.endswith('.class') or name.endswith('.yml') or name.endswith('.txt') or name.endswith('.properties') or name.endswith('.conf'):
                    try:
                        raw = z.read(name)
                    except Exception:
                        continue
                    try:
                        txt = raw.decode('utf-8', errors='ignore')
                    except Exception:
                        txt = str(raw)
                    for pat in SUSPICIOUS_PATTERNS:
                        if re.search(pat, txt, re.IGNORECASE):
                            findings.append({'file': name, 'pattern': pat})
                    for ip in IP_PATTERN.findall(txt):
                        findings.append({'file': name, 'pattern': 'IP:'+ip})
                    if len(BASE64_RE.findall(txt))>0:
                        findings.append({'file': name, 'pattern': 'LONG_BASE64_BLOB'})
    except Exception as e:
        findings.append({'error': str(e)})
    return findings


def is_obfuscated(jar_path):
    names = []
    try:
        with zipfile.ZipFile(jar_path, 'r') as z:
            for name in z.namelist():
                if name.endswith('.class'):
                    names.append(Path(name).stem)
    except Exception:
        return False, 0.0
    short_names = sum(1 for n in names if len(n)<=2)
    ratio = short_names / max(1, len(names))
    return ratio>0.10, ratio


def yara_scan_file(path):
    if not yara:
        return {'available': False}
    try:
        rules = yara.compile(source=YARA_RULES)
        matches = rules.match(path)
        return {'available': True, 'matches': [str(m) for m in matches]}
    except Exception as e:
        return {'available': True, 'error': str(e)}


def run_jadx_scan(jar_path, work_dir):
    jadx = shutil.which('jadx') or shutil.which('jadx-gui')
    if not jadx:
        return {'jadx_available': False}
    out_dir = os.path.join(work_dir, 'jadx_src')
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    try:
        subprocess.run([jadx, '-d', out_dir, jar_path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
    except Exception as e:
        return {'jadx_available': True, 'error': str(e)}
    findings = []
    for root,_,files in os.walk(out_dir):
        for f in files:
            if f.endswith('.java'):
                p = os.path.join(root, f)
                try:
                    with open(p, 'r', errors='ignore') as fh:
                        txt = fh.read()
                except Exception:
                    continue
                for pat in SUSPICIOUS_PATTERNS:
                    if re.search(pat, txt, re.IGNORECASE):
                        findings.append({'file': p.replace(out_dir+os.sep, ''), 'pattern': pat})
    return {'jadx_available': True, 'findings': findings}

# -------------------- Official download helpers --------------------

def download_github_asset(url, out_path):
    # Expect url to be a release asset or repo zip; try to fetch raw asset if given
    if not requests:
        return False, 'requests cần cài (pip install requests)'
    try:
        r = requests.get(url, stream=True, timeout=30)
        if r.status_code==200:
            with open(out_path, 'wb') as fh:
                for chunk in r.iter_content(8192):
                    fh.write(chunk)
            return True, None
        else:
            return False, f'HTTP {r.status_code}'
    except Exception as e:
        return False, str(e)


def try_download_official(link, out_path):
    # Support GitHub releases URLs and direct jar/raw URLs.
    if 'github.com' in link:
        # try to convert release page to download link if /releases/ contains asset
        # if link ends with .jar or .zip try direct
        if link.endswith('.jar') or link.endswith('.zip'):
            return download_github_asset(link, out_path)
        # try append /releases/latest/download/<name>.jar (best-effort)
        parts = link.rstrip('/').split('/')
        if 'releases' in parts:
            # try raw asset endpoint from page - lots of variants; we'll try a few heuristics
            # fallback: download repo archive of latest
            repo = '/'.join(parts[0:5])
            zipurl = repo + '/archive/refs/heads/main.zip'
            return download_github_asset(zipurl, out_path)
        else:
            # try repo archive
            repo = '/'.join(parts[0:5])
            zipurl = repo + '/archive/refs/heads/main.zip'
            return download_github_asset(zipurl, out_path)
    elif 'spigotmc.org' in link or 'spigot' in link:
        # Spigot pages often require session/csrf; cannot reliably download without API; inform user
        return False, 'Spigot downloads thường yêu cầu đăng nhập/tokens — chức năng tự động bị hạn chế.'
    else:
        # try direct download
        return download_github_asset(link, out_path)

# -------------------- VirusTotal --------------------

def check_virustotal_by_hash(sha256, api_key):
    if not requests:
        return {'error': 'requests chưa cài'}
    if not api_key:
        return {'error': 'Không có API key'}
    base = 'https://www.virustotal.com/api/v3/'
    headers = {'x-apikey': api_key}
    try:
        r = requests.get(base+f'files/{sha256}', headers=headers, timeout=30)
        if r.status_code==200:
            return {'ok': True, 'data': r.json()}
        else:
            return {'ok': False, 'error': f'VT HTTP {r.status_code}', 'text': r.text}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

# -------------------- Reports --------------------

def export_html_report(report, out_path):
    html = ['<html><head><meta charset="utf-8"><title>MC Plugin Scanner Report</title>',
            '<style>body{font-family:Arial;background:#0b0d10;color:#eaeaea;padding:16px} .card{background:#121416;padding:12px;margin:10px;border-radius:8px} .bad{color:#ff6b6b;font-weight:bold} .ok{color:#7efc6b}</style></head><body>']
    html.append(f"<h2>Report: {report.get('file')}</h2>")
    html.append('<div class=card>')
    html.append(f"<div>SHA256: <code>{report.get('hashes',{}).get('sha256')}</code></div>")
    html.append(f"<div>Thời gian: {report.get('time')}</div>")
    html.append('</div>')
    html.append('<div class=card>')
    html.append('<h3>Phát hiện tĩnh</h3>')
    if report.get('static_findings'):
        html.append('<ul>')
        for f in report['static_findings']:
            html.append('<li class=bad>' + f"{f.get('file')} — {f.get('pattern')}</li>")
        html.append('</ul>')
    else:
        html.append('<div class=ok>Không tìm thấy dấu hiệu tĩnh nghiêm trọng</div>')
    html.append('</div>')
    # plugin.yml
    if report.get('plugin_yml'):
        html.append('<div class=card'>< ')
    html.append('</body></html>')
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(html))

# -------------------- GUI App --------------------
class App:
    def __init__(self, root):
        self.root = root
        root.title('MC Plugin Scanner — Vuông')
        root.geometry('980x640')
        root.configure(bg='#0b0d10')
        # top bar
        top = tk.Frame(root, bg='#0b0d10')
        top.pack(side='top', fill='x', padx=8, pady=8)
        tk.Label(top, text='MC Plugin Scanner', bg='#0b0d10', fg='white', font=('Segoe UI',16,'bold')).pack(side='left')
        tk.Label(top, text='(Phiên bản Vuông)', bg='#0b0d10', fg='#9aa4b2').pack(side='left', padx=8)

        ctrl = tk.Frame(root, bg='#111217')
        ctrl.pack(side='top', fill='x', padx=8, pady=6)
        self.path_var = tk.StringVar(value='Chưa chọn file .jar')
        tk.Entry(ctrl, textvariable=self.path_var, bg='#0f1113', fg='white', width=80, relief='flat').pack(side='left', padx=6, pady=6)
        tk.Button(ctrl, text='Chọn .jar', command=self.choose_file, bg='#ff9900', fg='white').pack(side='left', padx=6)
        tk.Button(ctrl, text='Quét', command=self.quick_scan, bg='#2b9af3', fg='white').pack(side='left', padx=6)
        tk.Button(ctrl, text='Quét nâng cao', command=self.advanced_scan, bg='#ff3b3b', fg='white').pack(side='left', padx=6)

        # main panels: left list (vuông) and right detail
        main = tk.Frame(root, bg='#0b0d10')
        main.pack(fill='both', expand=True, padx=8, pady=8)

        left = tk.Frame(main, bg='#121416', width=360)
        left.pack(side='left', fill='y', padx=(0,8))
        left.pack_propagate(False)

        right = tk.Frame(main, bg='#0b0d10')
        right.pack(side='right', fill='both', expand=True)

        # left header
        hdr = tk.Frame(left, bg='#121416')
        hdr.pack(fill='x')
        tk.Label(hdr, text='Phát hiện', bg='#121416', fg='white', font=('Segoe UI',12,'bold')).pack(side='left', padx=8, pady=8)

        # listbox
        self.listbox = tk.Listbox(left, bg='#0b0f12', fg='white', activestyle='none', bd=0, selectbackground='#ff9900')
        self.listbox.pack(fill='both', expand=True, padx=8, pady=(0,8))
        self.listbox.bind('<<ListboxSelect>>', self.on_select)

        # right: detail and actions
        self.txt = tk.Text(right, bg='#0f1113', fg='white', wrap='word')
        self.txt.pack(fill='both', expand=True)

        bottom = tk.Frame(root, bg='#0b0d10')
        bottom.pack(side='bottom', fill='x', padx=8, pady=8)
        tk.Label(bottom, text='VT API Key (tùy):', bg='#0b0d10', fg='white').pack(side='left')
        self.vt_entry = tk.Entry(bottom, width=40)
        self.vt_entry.pack(side='left', padx=6)
        tk.Button(bottom, text='Xuất JSON', command=self.export_json, bg='#7ec9ff').pack(side='right', padx=6)
        tk.Button(bottom, text='Xuất HTML', command=self.export_html, bg='#7efc6b').pack(side='right', padx=6)

        # state
        self.current_file = None
        self.report = None

    def choose_file(self):
        p = filedialog.askopenfilename(title='Chọn file .jar', filetypes=[('Jar files','*.jar'),('All files','*.*')])
        if p:
            self.current_file = p
            self.path_var.set(p)

    def quick_scan(self):
        if not self.current_file:
            messagebox.showwarning('Chưa chọn file', 'Vui lòng chọn file .jar trước khi quét')
            return
        self._log('Bắt đầu quét nhanh...')
        rep = {'file': os.path.basename(self.current_file), 'path': self.current_file, 'time': time.ctime(), 'checks': []}
        rep['hashes'] = hash_file(self.current_file)
        yml = extract_plugin_yml(self.current_file)
        if yml:
            rep['plugin_yml'] = yml
            self._log('Tìm thấy plugin.yml')
        else:
            self._log('Không tìm thấy plugin.yml')
        findings = scan_strings_in_jar(self.current_file)
        rep['static_findings'] = findings
        obf, ratio = is_obfuscated(self.current_file)
        rep['obfuscated'] = {'likely': obf, 'ratio': ratio}
        self.report = rep
        self._show_summary()

    def advanced_scan(self):
        if not self.current_file:
            messagebox.showwarning('Chưa chọn file', 'Vui lòng chọn file .jar trước khi quét')
            return
        if not self.report:
            self.quick_scan()
        self._log('Bắt đầu quét nâng cao...')
        wd = tempfile.mkdtemp(prefix='mcscan_')
        try:
            jres = run_jadx_scan(self.current_file, wd)
            self.report['jadx'] = jres
            if not jres.get('jadx_available'):
                self._log('jadx không có trên PATH')
            else:
                self._log('jadx quét xong, mục khả nghi: %d' % len(jres.get('findings',[])))
        finally:
            try: shutil.rmtree(wd)
            except Exception: pass
        # yara
        yres = yara_scan_file(self.current_file)
        self.report['yara'] = yres
        if yres.get('available'):
            self._log('YARA: ' + (', '.join(yres.get('matches',[])) if yres.get('matches') else ('Lỗi: '+yres.get('error',''))))
        else:
            self._log('YARA không khả dụng (pip install yara-python)')
        # virustotal
        vtkey = self.vt_entry.get().strip()
        if vtkey:
            vt = check_virustotal_by_hash(self.report['hashes']['sha256'], vtkey)
            self.report['virustotal'] = vt
            if vt.get('ok'):
                stats = vt['data'].get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                positives = stats.get('malicious',0)+stats.get('suspicious',0)
                total = sum(stats.values()) if stats else 0
                self._log('VirusTotal: %d/%d flagged' % (positives, total))
            else:
                self._log('VirusTotal: ' + str(vt.get('error')))
        else:
            self._log('Bỏ qua VirusTotal (chưa có API key)')
        self._show_summary()

    def _show_summary(self):
        self.listbox.delete(0, 'end')
        if not self.report: return
        if self.report.get('static_findings'):
            self.listbox.insert('end', f"⚠️ Dấu hiệu chuỗi: {len(self.report['static_findings'])}")
        if self.report.get('obfuscated',{}).get('likely'):
            self.listbox.insert('end', '⚠️ Nhiều tên class ngắn → khả nghi obf')
        if self.report.get('jadx',{}).get('jadx_available') and len(self.report.get('jadx',{}).get('findings',[]))>0:
            self.listbox.insert('end', f"⚠️ JADX phát hiện: {len(self.report['jadx']['findings'])}")
        if self.report.get('virustotal') and self.report['virustotal'].get('ok'):
            stats = self.report['virustotal']['data'].get('data', {}).get('attributes', {}).get('last_analysis_stats',{})
            positives = stats.get('malicious',0)+stats.get('suspicious',0)
            total = sum(stats.values()) if stats else 0
            self.listbox.insert('end', f"[VT] {positives}/{total} engine flagged")
        self.listbox.insert('end', f"File: {self.report.get('file')}")
        self.listbox.insert('end', f"SHA256: {self.report.get('hashes',{}).get('sha256')}")
        self.listbox.insert('end', 'Click để xem chi tiết JSON')

    def on_select(self, evt):
        if not self.report: return
        self.txt.delete('1.0', 'end')
        self.txt.insert('1.0', json.dumps(self.report, ensure_ascii=False, indent=2)[:15000])

    def _log(self, msg):
        self.txt.insert('end', str(msg)+'\n')
        self.txt.see('end')

    def export_json(self):
        if not self.report:
            messagebox.showwarning('Chưa có báo cáo', 'Hãy quét trước khi xuất báo cáo')
            return
        p = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON','*.json')])
        if not p: return
        with open(p, 'w', encoding='utf-8') as fh:
            json.dump(self.report, fh, ensure_ascii=False, indent=2)
        messagebox.showinfo('Đã lưu', f'Báo cáo JSON đã lưu: {p}')

    def export_html(self):
        if not self.report:
            messagebox.showwarning('Chưa có báo cáo', 'Hãy quét trước khi xuất báo cáo')
            return
        p = filedialog.asksaveasfilename(defaultextension='.html', filetypes=[('HTML','*.html')])
        if not p: return
        # build a small HTML
        try:
            html = '<html><meta charset="utf-8"><body style="background:#0b0d10;color:#eaeaea;font-family:Arial">'
            html += f"<h2>Report: {self.report.get('file')}</h2>"
            html += f"<div><b>SHA256:</b> <code>{self.report.get('hashes',{}).get('sha256')}</code></div>"
            html += '<h3>Phát hiện tĩnh</h3>'
            if self.report.get('static_findings'):
                html += '<ul>'
                for f in self.report['static_findings']:
                    html += f"<li style='color:#ff6b6b'>{f.get('file')} — {f.get('pattern')}</li>"
                html += '</ul>'
            else:
                html += '<div style="color:#7efc6b">Không tìm thấy dấu hiệu tĩnh</div>'
            html += '<h3>plugin.yml</h3>'
            if self.report.get('plugin_yml'):
                html += '<pre style="background:#0f1113;padding:8px;border-radius:6px">' + (self.report['plugin_yml'][:2000]) + '</pre>'
            else:
                html += '<div>Không tìm thấy plugin.yml</div>'
            html += '</body></html>'
            with open(p, 'w', encoding='utf-8') as fh:
                fh.write(html)
            messagebox.showinfo('Đã lưu', f'Báo cáo HTML đã lưu: {p}')
        except Exception as e:
            messagebox.showerror('Lỗi', str(e))


# -------------------- Entrypoint --------------------

def main():
    if tk is None:
        print('Tkinter không khả dụng trên môi trường này. Cài đặt hoặc chạy nơi có GUI.')
        sys.exit(1)
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__=='__main__':
    main()
