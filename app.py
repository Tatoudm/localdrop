import os
import socket
import threading
import zipfile
import json
import bcrypt
import tempfile
import shutil
from tkinter import filedialog, messagebox

import customtkinter as ctk
import qrcode
from PIL import Image
from flask import Flask, request, send_file, render_template_string, abort
from flask_httpauth import HTTPBasicAuth
from werkzeug.serving import make_server
from werkzeug.utils import secure_filename

app = Flask(__name__)
auth = HTTPBasicAuth()
app.config['MAX_CONTENT_LENGTH'] = 3 * 1024 * 1024 * 1024 
ctk.set_appearance_mode("dark")

SETTINGS_FILE = "settings.json"

class LocalDropApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("LocalDrop - Natha Tools")
        self.geometry("600x900")

        self.settings = self.load_settings()
        self.shared_files = []
        self.received_logs = [] 
        self.server = None
        self.mode = ctk.StringVar(value="download")
        
        self.upload_dir = self.settings.get("upload_dir", os.path.join(os.path.expanduser("~"), "Downloads"))
        self.auto_zip = ctk.BooleanVar(value=self.settings.get("auto_zip", False))
        self.use_auth = ctk.BooleanVar(value=self.settings.get("use_auth", False))
        self.hashed_password = self.settings.get("password", "")

        self.setup_ui()
        self.update_ui_state()

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r") as f: return json.load(f)
            except: return {}
        return {}

    def save_settings_action(self):
        new_pwd = self.entry_pwd.get()
        if new_pwd:
            salt = bcrypt.gensalt()
            self.hashed_password = bcrypt.hashpw(new_pwd.encode(), salt).decode()
            self.lbl_pwd_status.configure(text="Mot de passe défini ✔", text_color="green")
            self.entry_pwd.delete(0, "end")

        settings = {
            "upload_dir": self.upload_dir,
            "auto_zip": self.auto_zip.get(),
            "use_auth": self.use_auth.get(),
            "password": self.hashed_password
        }
        with open(SETTINGS_FILE, "w") as f: json.dump(settings, f)
        messagebox.showinfo("Sauvegarde", "Paramètres enregistrés !")
        if self.server: self.update_flask_config()

    def setup_ui(self):
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(padx=20, pady=20, fill="both", expand=True)
        self.tab_main = self.tabview.add("Transfert")
        self.tab_settings = self.tabview.add("Réglages ⚙️")

        ctk.CTkLabel(self.tab_main, text="LocalDrop", font=("Roboto", 26, "bold")).pack(pady=10)
        
        self.mode_switch = ctk.CTkSegmentedButton(
            self.tab_main, 
            values=["Envoyer", "Recevoir"], 
            command=self.update_mode
        )
        self.mode_switch.set("Envoyer")
        self.mode_switch.pack(pady=10)

        self.btn_select = ctk.CTkButton(self.tab_main, text="Ajouter des fichiers...", command=self.select_files)
        self.btn_select.pack(pady=5)
        
        self.lbl_status = ctk.CTkLabel(self.tab_main, text="En attente...", font=("Arial", 14))
        self.lbl_status.pack(pady=5)

        self.files_box = ctk.CTkTextbox(self.tab_main, height=150, state="disabled", font=("Consolas", 12))
        self.files_box.pack(pady=5, padx=20, fill="x")

        self.btn_server = ctk.CTkButton(
            self.tab_main, text="DÉMARRER LE SERVEUR", 
            fg_color="green", height=45, font=("Roboto", 14, "bold"), 
            command=self.toggle_server
        )
        self.btn_server.pack(pady=20, fill="x", padx=40)

        self.qr_label = ctk.CTkLabel(self.tab_main, text="")
        self.qr_label.pack(pady=5)
        self.lbl_url = ctk.CTkLabel(self.tab_main, text="", font=("Courier", 12), text_color="#4aa3df")
        self.lbl_url.pack()

        ctk.CTkLabel(self.tab_settings, text="Dossier de réception :").pack(pady=(15,5))
        frame_dir = ctk.CTkFrame(self.tab_settings, fg_color="transparent")
        frame_dir.pack(fill="x", padx=20)
        self.entry_dir = ctk.CTkEntry(frame_dir)
        self.entry_dir.insert(0, self.upload_dir)
        self.entry_dir.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(frame_dir, text="📂", width=40, command=self.change_dest_dir).pack(side="right")

        ctk.CTkCheckBox(self.tab_settings, text="Zipper automatiquement si plusieurs fichiers", variable=self.auto_zip).pack(pady=15, anchor="w", padx=20)
        
        ctk.CTkLabel(self.tab_settings, text="Sécurité", font=("Roboto", 14, "bold")).pack(pady=(10,5))
        ctk.CTkCheckBox(self.tab_settings, text="Activer mot de passe", variable=self.use_auth, command=self.toggle_pwd_view).pack(pady=5, anchor="w", padx=20)
        
        pwd_text = "Mot de passe défini ✔" if self.hashed_password else "Aucun mot de passe défini"
        self.lbl_pwd_status = ctk.CTkLabel(self.tab_settings, text=pwd_text, text_color="green" if self.hashed_password else "gray")
        self.lbl_pwd_status.pack(pady=2)

        self.entry_pwd = ctk.CTkEntry(self.tab_settings, placeholder_text="Nouveau mot de passe...", show="*")
        if self.use_auth.get(): self.entry_pwd.pack(pady=5)

        ctk.CTkButton(self.tab_settings, text="SAUVEGARDER TOUT", fg_color="#34495e", command=self.save_settings_action).pack(side="bottom", pady=30)

    def toggle_pwd_view(self):
        if self.use_auth.get(): self.entry_pwd.pack(pady=5)
        else: self.entry_pwd.pack_forget()

    def update_mode(self, v):
        is_send = "Envoyer" in v
        self.mode.set("download" if is_send else "upload")
        self.update_ui_state()

    def update_ui_state(self):
        self.files_box.configure(state="normal")
        self.files_box.delete("0.0", "end") 
        
        if self.mode.get() == "download":
            self.btn_select.configure(state="normal")
            count = len(self.shared_files)
            self.lbl_status.configure(text=f"{count} fichier(s) prêt(s) à l'envoi", text_color="white")
            
            if not self.shared_files:
                self.files_box.insert("end", "(Aucun fichier sélectionné)")
            else:
                for file in self.shared_files:
                    self.files_box.insert("end", f"📄 {os.path.basename(file)}\n")
        
        else:
            self.btn_select.configure(state="disabled")
            self.lbl_status.configure(text=f"Stockage : {os.path.basename(self.upload_dir)}", text_color="#f39c12")
            
            self.files_box.insert("end", "--- Réceptions ---\n")
            if not self.received_logs:
                self.files_box.insert("end", "En attente de fichiers...\n")
            else:
                for log in self.received_logs:
                    self.files_box.insert("end", log + "\n")
                    
        self.files_box.configure(state="disabled")

    def log_reception(self, filename):
        self.after(0, lambda: self._add_log_entry(filename))

    def _add_log_entry(self, filename):
        msg = f"📥 Reçu : {filename}"
        self.received_logs.append(msg)
        
        if self.mode.get() == "upload":
            self.files_box.configure(state="normal")
            if "En attente" in self.files_box.get("0.0", "end"):
                self.files_box.delete("2.0", "end") 
                
            self.files_box.insert("end", msg + "\n")
            self.files_box.see("end") 
            self.files_box.configure(state="disabled")

    def select_files(self):
        f = filedialog.askopenfilenames()
        if f: 
            self.shared_files = list(f)
            self.update_ui_state()

    def change_dest_dir(self):
        d = filedialog.askdirectory()
        if d:
            self.upload_dir = d
            self.entry_dir.delete(0, "end")
            self.entry_dir.insert(0, d)
            self.update_ui_state()

    def toggle_server(self):
        if self.server is None: self.start_server()
        else: self.stop_server()

    def update_flask_config(self):
        app.config.update(
            DIR=self.upload_dir, 
            FILES=self.shared_files,
            MODE=self.mode.get(), 
            PWD_HASH=self.hashed_password if self.use_auth.get() else None,
            ZIP=self.auto_zip.get(),
            LOGGER=self.log_reception
        )

    def start_server(self):
        ip = self.get_ip()
        url = f"https://{ip}:5000"
        self.update_flask_config()

        qr = qrcode.QRCode(box_size=4)
        qr.add_data(url)
        img = qr.make_image(fill_color="black", back_color="white").get_image()
        self.qr_label.configure(image=ctk.CTkImage(img, img, size=(180,180)))
        self.lbl_url.configure(text=url)

        cert_file = "cert.pem"
        key_file = "key.pem"

        if os.path.exists(cert_file) and os.path.exists(key_file):
            context = (cert_file, key_file)
        else:
            context = 'adhoc'

        try:
            self.server = make_server('0.0.0.0', 5000, app, ssl_context=context)
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            self.btn_server.configure(text="ARRÊTER LE SERVEUR", fg_color="orange")
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec du lancement : {e}")

    def stop_server(self):
        if self.server:
            self.server.shutdown()
            self.server = None
            self.qr_label.configure(image=None)
            self.lbl_url.configure(text="")
            self.btn_server.configure(text="DÉMARRER LE SERVEUR", fg_color="green")

    def get_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            return s.getsockname()[0]
        except: return '127.0.0.1'
        finally: s.close()


@auth.verify_password
def verify(u, p):
    h = app.config.get('PWD_HASH')
    if not h: return True
    try: return bcrypt.checkpw(p.encode(), h.encode())
    except: return False

@app.route('/')
@auth.login_required
def index():
    return render_template_string(HTML, mode=app.config['MODE'], files=app.config['FILES'], zip=app.config['ZIP'])

@app.route('/get/<int:fid>')
@auth.login_required
def get_file(fid):
    files = app.config.get('FILES', [])
    if fid < 0 or fid >= len(files): abort(404)
    return send_file(files[fid], as_attachment=True)

@app.route('/zip')
@auth.login_required
def get_zip():
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    try:
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for f in app.config['FILES']:
                zf.write(f, os.path.basename(f))
    except Exception as e:
        os.remove(path)
        return str(e), 500

    @flask_after_this_request
    def remove_file(response):
        try: os.remove(path)
        except: pass
        return response
    return send_file(path, as_attachment=True, download_name="archive.zip")

@app.route('/up', methods=['POST'])
@auth.login_required
def upload():
    target_dir = app.config['DIR']
    logger = app.config.get('LOGGER')
    
    if not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)
        
    files = request.files.getlist("file")
    if not files: return "Aucun fichier", 400

    for f in files:
        if f.filename:
            fname = secure_filename(f.filename)
            f.save(os.path.join(target_dir, fname))
            if logger: logger(fname)
            
    return "<h3>Fichiers bien reçus ! ✅</h3><br><a href='/'>Retour</a>"

def flask_after_this_request(f):
    from flask import after_this_request
    return after_this_request(f)

HTML = """
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:'Segoe UI', sans-serif;background:#121212;color:#eee;text-align:center;padding:20px;}
.c{background:#1e1e1e;padding:20px;border-radius:12px;max-width:400px;margin:auto;box-shadow:0 4px 10px rgba(0,0,0,0.5);}
a{display:block;padding:12px;color:#3498db;text-decoration:none;border:1px solid #333;margin:8px 0;border-radius:8px;transition:0.2s;}
a:hover{background:#2c3e50;}
button{background:#2ecc71;border:none;padding:12px 25px;color:white;border-radius:8px;width:100%;cursor:pointer;font-weight:bold;font-size:16px;}
h2{margin-top:0;color:#2ecc71;}
</style></head>
<body><div class="c"><h2>LocalDrop ⚡</h2>
{% if mode == 'download' %}
  <p>Fichiers partagés :</p>
  {% if zip and files|length > 1 %}<a href="/zip" style="background:#e67e22;color:white;border:none;">📦 Télécharger tout (.zip)</a>{% endif %}
  {% for f in files %}<a href="/get/{{loop.index0}}">📄 {{f.split('/')[-1] if '/' in f else f.split('\\\\')[-1]}}</a>{% endfor %}
{% else %}
  <p>Envoyer vers PC :</p>
  <form action="/up" method="post" enctype="multipart/form-data">
  <input type="file" name="file" multiple style="margin-bottom:20px;width:100%"><br><button type="submit">Envoyer 🚀</button></form>
{% endif %}</div></body></html>
"""

if __name__ == "__main__":
    LocalDropApp().mainloop()