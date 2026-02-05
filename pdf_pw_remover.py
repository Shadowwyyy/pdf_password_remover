#!/usr/bin/env python3
"""
PDF Password Remover
A simple GUI application to remove passwords from PDF files
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
import threading
from pypdf import PdfReader, PdfWriter


class CustomButton(tk.Canvas):
    """Custom button that works well on macOS"""

    def __init__(self, parent, text, cmd, bg, fg='white',
                 hover=None, font=('Helvetica', 11, 'bold'), **kwargs):
        super().__init__(parent, highlightthickness=0, **kwargs)
        self.cmd = cmd
        self.bg = bg
        self.fg = fg
        self.hover_col = hover or bg
        self.txt = text
        self.font = font

        # size
        self.h = kwargs.get('height', 45)
        self.w = kwargs.get('width', 200)

        self.configure(width=self.w, height=self.h)
        self.draw()

        self.bind('<Button-1>', self.click)
        self.bind('<Enter>', self.enter)
        self.bind('<Leave>', self.leave)

    def draw(self, hovering=False):
        self.delete('all')
        col = self.hover_col if hovering else self.bg

        # rectangle
        self.create_rectangle(2, 2, self.w-2, self.h-2,
                              fill=col, outline=col, width=0)

        # text
        self.create_text(self.w//2, self.h//2,
                         text=self.txt, fill=self.fg,
                         font=self.font)

    def enter(self, e):
        self.draw(hovering=True)
        self.configure(cursor='hand2')

    def leave(self, e):
        self.draw(hovering=False)

    def click(self, e):
        self.cmd()


class PDFPasswordRemoverApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Password Remover")
        self.root.geometry("750x500")
        self.root.resizable(False, False)

        # background
        self.root.configure(bg='#f5f5f5')

        # style setup
        self.style = ttk.Style()
        self.style.theme_use('default')

        self.style.configure('Custom.TEntry',
                             fieldbackground='white',
                             foreground='#2c3e50',
                             borderwidth=1,
                             relief='solid')

        # vars
        self.inp_file = tk.StringVar()
        self.out_file = tk.StringVar()
        self.pwd = tk.StringVar()
        self.status_txt = tk.StringVar(value="Ready to unlock your PDF")

        self.setup_ui()

        self.setup_ui()

    def setup_ui(self):
        # main frame
        main = tk.Frame(self.root, bg='#f5f5f5')
        main.pack(fill=tk.BOTH, expand=True, padx=30, pady=25)

        # header
        hdr = tk.Frame(main, bg='#f5f5f5')
        hdr.pack(fill=tk.X, pady=(0, 25))

        # title
        tk.Label(
            hdr,
            text="🔓 PDF Password Remover",
            font=('Helvetica', 22, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50'
        ).pack()

        tk.Label(
            hdr,
            text="Remove password protection from your PDF files",
            font=('Helvetica', 11),
            bg='#f5f5f5',
            fg='#7f8c8d'
        ).pack(pady=(5, 0))

        # content area
        content = tk.Frame(main, bg='white', relief=tk.SOLID, bd=1)
        content.pack(fill=tk.BOTH, expand=True, pady=10)

        padded = tk.Frame(content, bg='white', padx=25, pady=25)
        padded.pack(fill=tk.BOTH, expand=True)

        # file inputs
        self._make_file_row(padded, 0, "📄 Input PDF:",
                            self.inp_file, self.browse_input)

        self._make_file_row(padded, 1, "💾 Output PDF:",
                            self.out_file, self.browse_output)

        # password input
        pwd_frame = tk.Frame(padded, bg='white')
        pwd_frame.pack(fill=tk.X, pady=20)

        lbl_frame = tk.Frame(pwd_frame, bg='white')
        lbl_frame.pack(side=tk.LEFT)

        tk.Label(
            lbl_frame,
            text="🔑 Password:",
            font=('Helvetica', 12),
            bg='white',
            fg='#34495e',
            width=15,
            anchor='w'
        ).pack()

        inp_frame = tk.Frame(pwd_frame, bg='white')
        inp_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.pwd_entry = tk.Entry(
            inp_frame,
            textvariable=self.pwd,
            font=('Helvetica', 12),
            show="•",
            relief=tk.SOLID,
            bd=1,
            bg='white',
            fg='#2c3e50',
            insertbackground='#2c3e50'
        )
        self.pwd_entry.pack(fill=tk.X, ipady=6)

        # show password checkbox
        self.show_pwd = tk.BooleanVar()
        tk.Checkbutton(
            pwd_frame,
            text="Show",
            variable=self.show_pwd,
            command=self.toggle_pwd,
            bg='white',
            fg='#2c3e50',
            font=('Helvetica', 10),
            activebackground='white',
            activeforeground='#2c3e50',
            selectcolor='white',
            cursor='hand2'
        ).pack(side=tk.LEFT)

        # button
        btn_frame = tk.Frame(main, bg='#f5f5f5')
        btn_frame.pack(pady=20)

        self.remove_btn = CustomButton(
            btn_frame,
            text="🔓 Remove Password",
            cmd=self.remove_password,
            bg='#27ae60',
            hover='#2ecc71',
            font=('Helvetica', 13, 'bold'),
            width=250,
            height=50
        )
        self.remove_btn.pack()

        # progress bar
        prog_frame = tk.Frame(main, bg='#f5f5f5')
        prog_frame.pack(fill=tk.X, pady=(10, 0))

        self.prog = ttk.Progressbar(
            prog_frame,
            mode='indeterminate',
            length=650
        )
        self.prog.pack(pady=5)

        # status
        tk.Label(
            prog_frame,
            textvariable=self.status_txt,
            font=('Helvetica', 10),
            bg='#f5f5f5',
            fg='#7f8c8d'
        ).pack()

    def _make_file_row(self, parent, row, lbl_txt, var, cmd):
        """file input row"""
        row = tk.Frame(parent, bg='white')
        row.pack(fill=tk.X, pady=12)

        lbl = tk.Frame(row, bg='white')
        lbl.pack(side=tk.LEFT)

        tk.Label(
            lbl,
            text=lbl_txt,
            font=('Helvetica', 12),
            bg='white',
            fg='#34495e',
            width=15,
            anchor='w'
        ).pack()

        entry_box = tk.Frame(row, bg='white')
        entry_box.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        tk.Entry(
            entry_box,
            textvariable=var,
            font=('Helvetica', 11),
            relief=tk.SOLID,
            bd=1,
            bg='#f8f9fa',
            fg='#2c3e50',
            state='readonly'
        ).pack(fill=tk.X, ipady=6)

        # browse button
        CustomButton(
            row,
            text="Browse",
            cmd=cmd,
            bg='#3498db',
            hover='#2980b9',
            font=('Helvetica', 11, 'bold'),
            width=100,
            height=38
        ).pack(side=tk.LEFT)

    def toggle_pwd(self):
        """show/hide password"""
        if self.show_pwd.get():
            self.pwd_entry.configure(show="")
        else:
            self.pwd_entry.configure(show="•")

    def browse_input(self):
        """pick input file"""
        f = filedialog.askopenfilename(
            title="Select PDF file",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if f:
            self.inp_file.set(f)
            # auto set output
            p = Path(f)
            out = p.parent / f"{p.stem}_unlocked.pdf"
            self.out_file.set(str(out))
            self.status_txt.set(f"Selected: {p.name}")

    def browse_output(self):
        """pick output location"""
        f = filedialog.asksaveasfilename(
            title="Save unlocked PDF as",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if f:
            self.out_file.set(f)

    def remove_password(self):
        """remove pwd from pdf"""
        # validate
        if not self.inp_file.get():
            messagebox.showerror("Error", "Please select an input PDF file")
            return

        if not self.out_file.get():
            messagebox.showerror("Error", "Please specify an output location")
            return

        if not self.pwd.get():
            ok = messagebox.askyesno(
                "No Password",
                "No password entered. Try to open PDF without password?"
            )
            if not ok:
                return

        # disable button
        self.remove_btn.configure(state='disabled')
        self.prog.start(10)
        self.status_txt.set("Processing...")

        # process in thread
        t = threading.Thread(target=self._do_remove)
        t.daemon = True
        t.start()

    def _do_remove(self):
        """actual removal logic"""
        try:
            inp = self.inp_file.get()
            out = self.out_file.get()
            pw = self.pwd.get()

            # read pdf
            reader = PdfReader(inp)

            # check encryption
            if reader.is_encrypted:
                if not pw:
                    self._err("PDF is encrypted. Please provide the password.")
                    return

                # try decrypt
                result = reader.decrypt(pw)

                # 0=fail, 1=user pw, 2=owner pw
                if result == 0:
                    self._err("Incorrect password. Please check and try again.")
                    return
                elif result == 1:
                    self.root.after(0, lambda: self.status_txt.set(
                        "Decrypted with user password"))
                elif result == 2:
                    self.root.after(0, lambda: self.status_txt.set(
                        "Decrypted with owner password"))

            # copy pages
            writer = PdfWriter()

            try:
                num_pages = len(reader.pages)
                for pg in reader.pages:
                    writer.add_page(pg)
            except Exception as e:
                self._err(
                    f"Could not read PDF pages. The password may be incorrect.\n{str(e)}")
                return

            # copy metadata
            try:
                if reader.metadata:
                    writer.add_metadata(reader.metadata)
            except:
                pass

            # save
            with open(out, "wb") as f:
                writer.write(f)

            self._success(f"Success! Unlocked PDF saved to:\n{Path(out).name}")

        except Exception as e:
            self._err(f"An error occurred:\n{str(e)}")

    def _success(self, msg):
        """show success"""
        self.root.after(0, lambda: self._done(True, msg))

    def _err(self, msg):
        """show error"""
        self.root.after(0, lambda: self._done(False, msg))

    def _done(self, success, msg):
        """cleanup"""
        self.prog.stop()
        self.remove_btn.configure(state='normal')

        if success:
            self.status_txt.set("Completed successfully")
            messagebox.showinfo("Success", msg)
            # clear
            self.inp_file.set("")
            self.out_file.set("")
            self.pwd.set("")
            self.status_txt.set("Ready to unlock your PDF")
        else:
            self.status_txt.set("Error occurred")
            messagebox.showerror("Error", msg)


def main():
    root = tk.Tk()
    app = PDFPasswordRemoverApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
