"""Portable Tk launcher for local roster captures. Never edits live accounts."""
import subprocess
import os
import sys
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
import roster_menu as roster
from prepare_duration_trials import build as build_duration_capture

HERE=Path(__file__).resolve().parent


def card_info(cid):
    return (f'{roster.NAMES.get(cid, roster.SUPER.get(cid,"Bilinmeyen kart"))}\n'
            f'{roster.position_label(cid)}  ·  {roster.RARITIES.get(cid,"Doğrulanmadı")}\n'
            f'Kart kodu: {cid}\n\n'
            'İstatistikler henüz çıkarılmadı.\n'
            'Mevki uyumu ve maliyeti oyunda kontrol et.')


class Launcher:
    def __init__(self,root):
        self.root=root
        self.source=None
        self.recording_origin=None
        self.output=None
        self.rows=[]
        self.process=None
        self.recorder=None
        self.game_root=None
        root.title('Revival Offline | Squad Studio')
        screen_w,screen_h=root.winfo_screenwidth(),root.winfo_screenheight()
        width=min(1180,screen_w-40)
        height=min(780,screen_h-90)
        root.geometry(f'{width}x{height}+{max(0,(screen_w-width)//2)}+{max(0,(screen_h-height)//2)}')
        root.minsize(min(900,width),min(640,height))
        root.configure(bg='#0b1018')
        style=ttk.Style()
        style.theme_use('clam')
        style.configure('.',background='#0b1018',foreground='#e7edf6',font=('Segoe UI',10))
        style.configure('Panel.TFrame',background='#141d2b')
        style.configure('Panel.TLabel',background='#141d2b')
        style.configure('Muted.TLabel',foreground='#94a4ba')
        style.configure('PanelMuted.TLabel',background='#141d2b',foreground='#94a4ba')
        style.configure('Title.TLabel',font=('Segoe UI',26,'bold'))
        style.configure('Section.TLabel',font=('Segoe UI',11,'bold'))
        style.configure('TButton',padding=(12,10),background='#233147',borderwidth=0,
                        foreground='#e7edf6',focusthickness=2,focuscolor='#62d6b4')
        style.map('TButton',background=[('active','#344b68'),('pressed','#1c2a3e')])
        style.configure('Accent.TButton',background='#58d5ae',foreground='#08251e',font=('Segoe UI',10,'bold'))
        style.map('Accent.TButton',background=[('active','#8de6c9'),('pressed','#32b78e')])
        style.configure('TEntry',fieldbackground='#1b293c',foreground='#e7edf6',padding=9,
                        insertcolor='#e7edf6',bordercolor='#30435e')
        style.configure('TCombobox',padding=7,arrowsize=15)
        style.map('TCombobox',fieldbackground=[('readonly','#1b293c')],
                  foreground=[('readonly','#e7edf6')],selectbackground=[('readonly','#1b293c')],
                  selectforeground=[('readonly','#e7edf6')])
        root.option_add('*TCombobox*Listbox.background','#1b293c')
        root.option_add('*TCombobox*Listbox.foreground','#e7edf6')
        style.configure('Treeview',background='#141d2b',fieldbackground='#141d2b',
                        foreground='#e7edf6',rowheight=33,borderwidth=0)
        style.configure('Treeview.Heading',background='#1b293c',foreground='#94a4ba',
                        font=('Segoe UI',9,'bold'),padding=10,relief='flat')
        style.map('Treeview',background=[('selected','#245e56')],foreground=[('selected','#ffffff')])
        style.map('Treeview.Heading',background=[('active','#233147')])
        header=ttk.Frame(root,padding=(24,18))
        header.pack(fill='x')
        ttk.Label(header,text='REVIVAL',style='Title.TLabel').pack(side='left')
        ttk.Label(header,text='  /  SQUAD STUDIO',style='Muted.TLabel').pack(side='left',padx=10)
        ttk.Label(header,text='OFFLINE  •  Yerel kadro atölyesi',foreground='#58d5ae').pack(side='right')
        footer=ttk.Frame(root,padding=(24,12))
        footer.pack(side='bottom',fill='x')
        self.hotkey_hint=ttk.Label(footer,text='',style='Muted.TLabel')
        self.hotkey_hint.pack(side='left')
        ttk.Button(header,text='Tuş ayarları',command=self.configure_hotkeys).pack(side='right',padx=8)
        self.refresh_hotkeys()
        ttk.Button(footer,text='OYUNU BAŞLAT  →',style='Accent.TButton',command=self.play).pack(side='right')
        ttk.Button(footer,text='KARTI DEĞİŞTİR',style='Accent.TButton',command=self.save).pack(side='right',padx=12)
        self.status=ttk.Label(root,text='Hazır. Kurulu oyunu ve kadro kaydını seçerek başla.',
                              style='Muted.TLabel',wraplength=1100,padding=(24,5))
        self.status.pack(side='bottom',fill='x')
        body=ttk.Frame(root,padding=(24,0,24,0))
        body.pack(fill='both',expand=True)
        sidebar=ttk.Frame(body,style='Panel.TFrame',padding=18,width=280)
        sidebar.pack(side='left',fill='y',padx=(0,18))
        sidebar.pack_propagate(False)
        ttk.Label(sidebar,text='01  BAĞLANTI VE KAYIT',style='Panel.TLabel',
                  font=('Segoe UI',10,'bold')).pack(anchor='w',pady=(0,12))
        ttk.Button(sidebar,text='Kurulu oyunu seç',command=self.select_game).pack(fill='x',pady=4)
        ttk.Button(sidebar,text='Kadro kaydı aç',command=self.open_capture).pack(fill='x',pady=4)
        ttk.Button(sidebar,text='Normal oyundan kadro kaydet',command=self.record_roster).pack(fill='x',pady=4)
        ttk.Button(sidebar,text='Bu PC için offline veri hazırla',command=self.setup_local).pack(fill='x',pady=4)
        self.path=ttk.Label(sidebar,text='Henüz kadro seçilmedi',style='PanelMuted.TLabel',wraplength=238)
        self.path.pack(anchor='w',pady=(10,18))
        ttk.Separator(sidebar).pack(fill='x',pady=10)
        ttk.Label(sidebar,text='02  MAÇ AYARLARI',style='Panel.TLabel',
                  font=('Segoe UI',10,'bold')).pack(anchor='w',pady=(12,14))
        ttk.Label(sidebar,text='Süre · dakika',style='PanelMuted.TLabel').pack(anchor='w')
        self.minutes=tk.StringVar(value='3')
        ttk.Combobox(sidebar,textvariable=self.minutes,values=('3','6','9'),
                     state='readonly').pack(fill='x',pady=(5,14))
        ttk.Label(sidebar,text='Bot zorluğu · 1–10',style='PanelMuted.TLabel').pack(anchor='w')
        self.difficulty=tk.StringVar(value='1')
        ttk.Combobox(sidebar,textvariable=self.difficulty,values=tuple(str(n) for n in range(1,11)),
                      state='readonly').pack(fill='x',pady=(5,10))
        self.spirit=tk.BooleanVar(value=True)
        ttk.Checkbutton(sidebar,text='Takım ruhu 5 / Mevcut 22',variable=self.spirit).pack(anchor='w',pady=4)
        ttk.Label(sidebar,text='Süre ve seviye oda açılırken uygulanır.\nUzatma ve LAN desteklenmiyor.',
                  style='PanelMuted.TLabel',wraplength=238).pack(anchor='w',pady=8)
        ttk.Button(sidebar,text='Bütçe kurtar · Alves KL',command=self.restore_keeper).pack(side='bottom',fill='x',pady=6)
        ttk.Label(sidebar,text='Orijinal kayıt korunur.\nDeğişiklikler yeni kopyaya yazılır.',
                  style='PanelMuted.TLabel',wraplength=238).pack(side='bottom',anchor='w',pady=12)
        content=ttk.Frame(body)
        content.pack(side='left',fill='both',expand=True)
        ttk.Label(content,text='Kadronu kur.',font=('Segoe UI',20,'bold')).pack(anchor='w')
        ttk.Label(content,text='Mevcut oyuncuyu seç, kartları karşılaştır ve değiştir.',
                  style='Muted.TLabel').pack(anchor='w',pady=(4,14))
        ttk.Label(content,text='MEVCUT İLK 11',style='Section.TLabel').pack(anchor='w',pady=(0,6))
        self.current=ttk.Combobox(content,state='readonly')
        self.current.pack(fill='x')
        self.current.bind('<<ComboboxSelected>>',self.update_info)
        catalogbar=ttk.Frame(content)
        catalogbar.pack(fill='x',pady=(16,8))
        ttk.Label(catalogbar,text='KART KATALOĞU',style='Section.TLabel').pack(side='left')
        self.catalog_count=ttk.Label(catalogbar,text='',style='Muted.TLabel')
        self.catalog_count.pack(side='right')
        self.query=tk.StringVar()
        entry=ttk.Entry(content,textvariable=self.query)
        entry.pack(fill='x')
        ttk.Label(content,text='İsim, yıl, mevki veya kart koduyla ara',style='Muted.TLabel').pack(anchor='w',pady=(4,0))
        self.query.trace_add('write',self.filter)
        self.card_level=tk.StringVar()
        filters=ttk.Frame(content)
        filters.pack(fill='x',pady=(6,0))
        self.rarity=tk.StringVar(value='Tüm nadirlikler')
        self.position=tk.StringVar(value='Tüm mevkiler')
        for variable,values in ((self.rarity,('Tüm nadirlikler','Süper','Ender','Uzman','Mythic')),
                                (self.position,('Tüm mevkiler',)+tuple(sorted({roster.position_label(cid) for cid in roster.CARDS})))):
            ttk.Combobox(filters,textvariable=variable,values=values,state='readonly',width=22).pack(side='left',padx=(0,8))
            variable.trace_add('write',self.filter)
        ttk.Label(filters,text='Seviye:').pack(side='left')
        ttk.Entry(filters,textvariable=self.card_level,width=7).pack(side='left',padx=4)
        table=ttk.Frame(content)
        table.pack(fill='both',expand=True,pady=(8,4))
        self.tree=ttk.Treeview(table,columns=('position','name','id'),show='headings',height=5,selectmode='browse')
        for key,title,width in [('position','MEVKİ',85),('name','OYUNCU / SÜRÜM',320),('id','KART KODU',130)]:
            self.tree.heading(key,text=title)
            self.tree.column(key,width=width)
        scroll=ttk.Scrollbar(table,orient='vertical',command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side='left',fill='both',expand=True)
        scroll.pack(side='right',fill='y')
        self.tree.bind('<<TreeviewSelect>>',self.update_info)
        comparison=ttk.Frame(content)
        comparison.pack(fill='x',pady=(10,4))
        comparison.columnconfigure((0,1),weight=1,uniform='cards')
        self.details=[]
        for column,title in enumerate(['MEVCUT KART','YENİ KART']):
            panel=ttk.Frame(comparison,style='Panel.TFrame',padding=14)
            panel.grid(row=0,column=column,sticky='nsew',padx=(0,8) if column==0 else (0,0))
            ttk.Label(panel,text=title,style='PanelMuted.TLabel',font=('Segoe UI',9,'bold')).pack(anchor='w',pady=(0,8))
            label=ttk.Label(panel,text='Karşılaştırmak için kart seç.',style='Panel.TLabel',justify='left',wraplength=305)
            label.pack(anchor='w')
            self.details.append(label)
        self.filter()

    def refresh_hotkeys(self):
        import hotkey_settings
        try:
            room,start=hotkey_settings.load()
        except (ValueError,OSError,KeyError,TypeError):
            room,start='N','M'
        self.hotkey_hint.configure(text=f'{room} → Hazırlık    {start} → Maç')

    def configure_hotkeys(self):
        import hotkey_settings
        dialog=tk.Toplevel(self.root)
        dialog.title('Tuş ayarları')
        dialog.resizable(False,False)
        dialog.transient(self.root)
        body=ttk.Frame(dialog,padding=16)
        body.pack()
        try:
            current=hotkey_settings.load()
        except (ValueError,OSError,KeyError,TypeError):
            current=('N','M')
        variables=[]
        for title,value in zip(('Maç hazırlık ekranını aç','Maçı başlat'),current):
            ttk.Label(body,text=title).pack(anchor='w',pady=(8,4))
            variable=tk.StringVar(value=value)
            variables.append(variable)
            ttk.Combobox(body,textvariable=variable,values=tuple(hotkey_settings.KEYS),
                         state='readonly',width=28).pack(fill='x')
        ttk.Label(body,text='Yalnızca oyun öndeyken çalışır.\nN ve M varsayılandır.',style='Muted.TLabel').pack(pady=12)
        def save():
            try:
                hotkey_settings.save(*(variable.get() for variable in variables))
            except (ValueError,OSError) as exc:
                messagebox.showerror('Tuş ayarları',str(exc),parent=dialog);return
            self.refresh_hotkeys()
            dialog.destroy()
        ttk.Button(body,text='Kaydet',command=save).pack(fill='x')

    def open_capture(self):
        name=filedialog.askopenfilename(initialdir=HERE,title='Offline kadro kaydi',filetypes=[('Capture','*.log')])
        if not name:return
        try:
            self.load_capture(Path(name))
        except (ValueError,OSError) as exc:
            messagebox.showerror('Kayit okunamadi',str(exc));return

    def select_game(self):
        name=filedialog.askopenfilename(title='Kurulu oyun: Game/BinaryTr/BinaryTrU.exe',
                                       filetypes=[('Oyun','BinaryTrU.exe')])
        if not name:return
        game=Path(name)
        if game.name.lower()!='binarytru.exe' or game.parent.name.lower()!='binarytr' or game.parent.parent.name.lower()!='game':
            messagebox.showerror('Gecersiz konum','Game/BinaryTr/BinaryTrU.exe dosyasini secin.');return
        self.game_root=game.parent.parent.parent
        self.status.configure(text=f'Kurulu oyun: {game}')

    def setup_local(self):
        self.select_game()
        if self.game_root is not None:
            self.record_roster(setup=True)

    def record_roster(self, setup=False):
        if self.process and self.process.poll() is None:
            messagebox.showinfo('Offline oturum acik','Once offline oyunu ve oturumunu kapatin.');return
        if self.recorder and self.recorder.poll() is None:
            messagebox.showinfo('Kayit acik','Kadro kaydi zaten calisiyor.');return
        if not messagebox.askokcancel('Normal oyundan kadro kaydi',
                'Once tum oyunlari kapatin. Kaydi baslatin, sonra NORMAL oyunu acip giris yapin.\n'
                'Paket/hesap degistirilmez. Frida gozlemi oyun guvenligine takilabilir; '
                'kurallar izin vermiyorsa kullanmayin. Loglar ozel hesap bilgileri icerebilir.\n'
                + ('Bu hazırlık giriş/kanal/maç trafiği ve oturum anahtarı gözlemler. '
                 'Önce NORMAL launcher açık olsun ama OYNA düğmesine basmayın. '
                 'Kayıt için oyun bağlantıları yerel TCP aktarıcısından, baytları değiştirilmeden geçer. '
                 'Kaydı bitirmek bu bağlantıları kapatır; normal oturum sunucudan ayrılabilir. '
                 'Hazırlık konsolu gözlemci hazır deyince OYNA düğmesine basın. '
                 'Kendi antrenman maçını ve devre arasını kaydet; gerçek offline oynatım henüz doğrulanmadı. Devam?'
                 if setup else 'Bu islem lobi/kadro kaydi alir; mac kaydi olusturmaz. Devam?')):return
        try:
            extra=['--setup-game-root',str(self.game_root)] if setup else []
            self.recorder=subprocess.Popen([sys.executable,str(HERE/'limited_run.py'),
                sys.executable,'-u',str(HERE/'record_roster.py')]+extra,cwd=HERE,
                creationflags=subprocess.CREATE_NEW_CONSOLE)
        except OSError as exc:messagebox.showerror('Kayit acilamadi',str(exc))

    def load_capture(self,path):
        from prepare_recording import prepare_recording
        original=path
        path=prepare_recording(path)
        raw=original
        if raw.name.endswith('.offline.log'):
            raw=raw.with_name(raw.name.replace('.offline.log','.log'))
        if raw.with_suffix('.auth.log').is_file():
            self.recording_origin=raw
        else:
            self.recording_origin=None
        _,cards,ids=roster.inspect(path)
        self.source=path
        self.output=None
        self.rows=[(i,cards[i][2]) for i in ids]
        self.current['values']=[f'{n+1}. {roster.position_label(cid)} | {roster.NAMES.get(cid,"Bilinmeyen oyuncu")} | {cid}' for n,(_,cid) in enumerate(self.rows)]
        self.current.current(0)
        self.path.configure(text=self.source.name)
        self.update_info()
        if path!=original:
            self.status.configure(text=f'Offline kopya otomatik hazırlandı: {path.name} | Orijinal korundu.')

    def filter(self,*_):
        self.tree.delete(*self.tree.get_children())
        for cid,name in sorted(roster.CARDS.items(),key=lambda item:item[1]):
            if self.rarity.get()!='Tüm nadirlikler' and roster.RARITIES[cid]!=self.rarity.get():
                continue
            if self.position.get()!='Tüm mevkiler' and roster.position_label(cid)!=self.position.get():
                continue
            values=(roster.position_label(cid),f'{roster.RARITIES[cid]} · {name}',str(cid))
            if self.query.get().casefold() in ' '.join(values).casefold():
                self.tree.insert('', 'end',iid=str(cid),values=values)
        self.catalog_count.configure(text=f'{len(self.tree.get_children())} / {len(roster.CARDS)} kart')

    def update_info(self,*_):
        n=self.current.current()
        if n>=0 and self.rows:self.details[0].configure(text=card_info(self.rows[n][1]))
        selection=self.tree.selection()
        self.details[1].configure(text=card_info(int(selection[0])) if selection else 'Kart secin')

    def save(self):
        selection=self.tree.selection()
        if not self.source or self.current.current()<0 or not selection:
            messagebox.showinfo('Secim gerekli','Mevcut karti ve yeni karti secin.');return
        target=HERE/f'capture-launcher-{time.time_ns()}.log'
        try:
            text=self.card_level.get().strip()
            level=int(text) if text else None
            roster.replace(self.source,target,self.rows[self.current.current()][0],int(selection[0]),level=level)
        except (ValueError,OSError,AssertionError) as exc:
            messagebox.showerror('Kaydedilemedi',str(exc));return
        index=self.current.current()
        origin=self.recording_origin
        self.load_capture(target)
        self.recording_origin=origin
        self.current.current(index)
        self.update_info()
        self.output=target
        rarity=roster.RARITIES.get(int(selection[0]))
        level=level if level is not None else {'Süper':25,'Uzman':20}.get(rarity)
        suffix=f' | Seviye {level}' if level is not None else ''
        self.status.configure(text=f'Kart değiştirildi{suffix}. Güncel kadro: {target.name} | Orijinal korundu.')

    def play(self):
        active=self.output or self.source
        if not active:
            messagebox.showinfo('Kadro secin','Once bir kadro kaydi acin. Kart degistirmek zorunlu degil.');return
        if self.process and self.process.poll() is None:
            messagebox.showinfo('Oturum acik','Once mevcut test oturumunu kapatin.');return
        from offline_replay import forced_session_key
        if '"kind": "gap"' in active.read_text(encoding='utf-8',errors='replace'):
            messagebox.showerror('Kayıt eksik paket içeriyor',
                'Kaydedici paket kaybı bildirmiş. Bu kayıtla offline oyun başlatılmadı.\n'
                'Daha uzun oynamak veya sahte anahtar eklemek eksikleri gidermez.\n'
                'Kadro düzenlemeleriniz korunuyor.');return
        try:
            capture_key=forced_session_key(active)
        except ValueError as exc:
            messagebox.showerror('Oturum anahtarı uyumsuz',str(exc));return
        if capture_key is None:
            messagebox.showerror('Kadro kaydı offline oynatmaya uygun değil',
                'Kadro okunabiliyor, ancak bu kayıtta doğrulanmış offline oturum anahtarı yok.\n'
                'Bu PC için offline veri hazırla ile YENİ kayıt alın; antrenman maçını da kaydedin.\n'
                'game.log oluşturmak veya kayda sabit anahtar yazmak bunu çözmez.\n'
                'Oyun başlatılmadı; kadronuz ve değişiklikleriniz korundu.');return
        missing=[name for name in ('game.log','offline_launch_candidate.json') if not (HERE/name).is_file()]
        if missing:
            if messagebox.askyesno('Kendi giriş kaydından tamamla',
                    'Eksik yerel dosyaları kendi .auth.log kaydınızdan hazırlamak ister misiniz?\n'
                    'Yalnızca bu bilgisayardaki kendi kaydınızı seçin. Resmi manifest için internet gerekir.'):
                origin=getattr(self,'recording_origin',None)
                auth=origin.with_suffix('.auth.log') if origin else None
                name=str(auth) if auth and auth.is_file() else filedialog.askopenfilename(initialdir=HERE,title='Kendi giriş kaydınız',filetypes=[('Giriş kaydı','*.auth.log')])
                if name:
                    if self.game_root is None:
                        self.select_game()
                    if self.game_root is not None:
                        try:
                            from local_setup import save_setup, installed_release
                            from offline_replay import records
                            save_setup(HERE,self.game_root,records(Path(name)),installed_release(self.game_root))
                        except (ValueError,OSError,KeyError,StopIteration) as exc:
                            messagebox.showerror('Hazırlık tamamlanamadı',str(exc));return
                        self.play()
                        return
            messagebox.showerror('Yerel offline verisi gerekli',
                'Bu temiz dagitim paketi kisisel oyun/oturum verisi icermez.\n'
                'Eksik: '+', '.join(missing)+'\n'
                'Bu PC için offline veri hazırla düğmesini kullanın. '
                'Kadro kaydi tek basina mac acmaya yetmez.');return
        if not (HERE/'Game'/'BinaryTr'/'BinaryTrU.exe').is_file() and self.game_root is None:
            self.select_game()
            if self.game_root is None:return
        diagnostic=HERE/'run_halftime_diagnostic.py'
        runner=diagnostic if diagnostic.exists() else HERE/'run_offline_test.py'
        if self.spirit.get():
            runner=HERE/'team_spirit_trial.py'
        args=[sys.executable,str(HERE/'limited_run.py'),sys.executable,str(runner),
              '--local-candidate','--redirect-all','--capture',str(active),
              '--session-key',capture_key,'--seconds','0']
        try:roster.match_port(active)
        except ValueError:
            args.append('--lobby-card')
            note='Bu kayit LOBI ICIN: Training/BASLAT kullanmayin.'
        else:
            from offline_replay import room_phases,match_replay
            try:
                room_phases(active)
                match_replay(active,roster.match_port(active))
            except ValueError:
                if not messagebox.askyesno('Kayıt okunuyor; maç akışı desteklenmiyor',
                        'Bu kaydın paketleri okunuyor ama oda akışı mevcut maç replay düzenine uymuyor.\n'
                        'Bu, oyun güncellemesi olduğu anlamına gelmez.\n'
                        'Yalnızca lobiyi açmak ister misiniz? Maç için önceki çalışan kaydı seçebilirsiniz.'):
                    return
                args.append('--lobby-card')
                note='Yalnızca lobi açılacak; bu kayıtla maçı başlatmayın.'
            else:
                note=f'Offline antrenman. Mac suresi: {self.minutes.get()} dakika. Zorluk: {self.difficulty.get()}.'
        if '--lobby-card' not in args:
            args.append('--manual-room')
            import hotkey_settings
            room_key,start_key=hotkey_settings.load()
            note+=f'\nOyun öndeyken {room_key} = hazırlık, {start_key} = başlat.\nSüre ve zorluk önceden uygulanır; rakip takım seçimi deneyseldir. Uzatma desteklenmiyor.'
        if not messagebox.askokcancel('Offline oturum',note+'\nSure siniri yok; bitirmek icin oyunu kapat. Devam?'):return
        try:
            if '--lobby-card' not in args:
                text,_=build_duration_capture(active.read_text(encoding='utf-8'),int(self.minutes.get()),
                                              int(self.difficulty.get()))
                target=HERE/f'capture-launcher-duration-{time.time_ns()}.log'
                with target.open('x',encoding='utf-8') as out:out.write(text)
                args[args.index('--capture')+1]=str(target)
            environment=os.environ.copy()
            if self.game_root is not None:environment['REVIVAL_GAME_ROOT']=str(self.game_root)
            self.process=subprocess.Popen(args,cwd=HERE,env=environment,creationflags=subprocess.CREATE_NEW_CONSOLE)
        except (OSError,ValueError,AssertionError) as exc:messagebox.showerror('Acilamadi',str(exc))

    def restore_keeper(self):
        if not self.source:
            messagebox.showinfo('Kadro secin','Once sorunlu guncel kadro kaydini acin.');return
        matches=[(i,cid) for i,cid in self.rows if cid in (116103134,116103139)]
        if len(matches)!=1:
            messagebox.showinfo('Uygulanamadi','Bu kurtarma yalniz tek bir 2016 Super Courtois bulunan kadro icindir.');return
        if not messagebox.askyesno('Butce kurtarma','Super Courtois (10) yerine eski kaleci Alves (7) geri gelsin mi?\n91 maliyetli kadro 88 olur. Orijinal korunur.'):
            return
        target=HERE/f'capture-budget-rescue-{time.time_ns()}.log'
        try:
            roster.replace(self.source,target,matches[0][0],114203012,restore_keeper=True)
            self.load_capture(target)
            self.output=target
            self.status.configure(text='Kaleci Alves geri getirildi (-3 maliyet). Yeni kadroyla oyunu yeniden acin.')
        except (ValueError,OSError,AssertionError) as exc:
            messagebox.showerror('Kurtarma basarisiz',str(exc))


if __name__=='__main__':
    root=tk.Tk()
    Launcher(root)
    root.mainloop()
