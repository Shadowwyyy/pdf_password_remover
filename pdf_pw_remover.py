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

    def __init__(self, parent, text, command, bg_color, fg_color='white',
                 hover_color=None, font=('Helvetica', 11, 'bold'), **kwargs):
        super().__init__(parent, highlightthickness=0, **kwargs)
        self.command = command
        self.bg_color = bg_color
        self.fg_color = fg_color
        self.hover_color = hover_color or bg_color
        self.text = text
        self.font = font

        # Calculate size based on text
        self.height = kwargs.get('height', 45)
        self.width = kwargs.get('width', 200)

        self.configure(width=self.width, height=self.height)
        self.draw_button()

        self.bind('<Button-1>', self.on_click)
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)

    def draw_button(self, hover=False):
        self.delete('all')
        color = self.hover_color if hover else self.bg_color

        # Draw rounded rectangle
        self.create_rectangle(2, 2, self.width-2, self.height-2,
                              fill=color, outline=color, width=0)

        # Draw text
        self.create_text(self.width//2, self.height//2,
                         text=self.text, fill=self.fg_color,
                         font=self.font)

    def on_enter(self, event):
        self.draw_button(hover=True)
        self.configure(cursor='hand2')

    def on_leave(self, event):
        self.draw_button(hover=False)

    def on_click(self, event):
        self.command()


class PDFPasswordRemoverApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Password Remover")
        self.root.geometry("750x500")
        self.root.resizable(False, False)

        # Set background color
        self.root.configure(bg='#f5f5f5')

        # Configure ttk style
        self.style = ttk.Style()
        self.style.theme_use('default')

        # Custom styles for ttk
        self.style.configure('Custom.TEntry',
                             fieldbackground='white',
                             foreground='#2c3e50',
                             borderwidth=1,
                             relief='solid')

        # Variables
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.password = tk.StringVar()
        self.status = tk.StringVar(value="Ready to unlock your PDF")

        self.setup_ui()

    def setup_ui(self):
        # Main frame with background
        main_frame = tk.Frame(self.root, bg='#f5f5f5')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=25)

        # Header section
        header_frame = tk.Frame(main_frame, bg='#f5f5f5')
        header_frame.pack(fill=tk.X, pady=(0, 25))

        # Title with emoji
        title_label = tk.Label(
            header_frame,
            text="🔓 PDF Password Remover",
            font=('Helvetica', 22, 'bold'),
            bg='#f5f5f5',
            fg='#2c3e50'
        )
        title_label.pack()

        subtitle_label = tk.Label(
            header_frame,
            text="Remove password protection from your PDF files",
            font=('Helvetica', 11),
            bg='#f5f5f5',
            fg='#7f8c8d'
        )
        subtitle_label.pack(pady=(5, 0))

        # Content frame with white background
        content_frame = tk.Frame(main_frame, bg='white', relief=tk.SOLID, bd=1)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Add padding inside content frame
        padded_content = tk.Frame(content_frame, bg='white', padx=25, pady=25)
        padded_content.pack(fill=tk.BOTH, expand=True)

        # Input file section
        self._create_file_row(padded_content, 0, "📄 Input PDF:",
                              self.input_file, self.browse_input)

        # Output file section
        self._create_file_row(padded_content, 1, "💾 Output PDF:",
                              self.output_file, self.browse_output)

        # Password section
        password_frame = tk.Frame(padded_content, bg='white')
        password_frame.pack(fill=tk.X, pady=20)

        password_label_frame = tk.Frame(password_frame, bg='white')
        password_label_frame.pack(side=tk.LEFT)

        tk.Label(
            password_label_frame,
            text="🔑 Password:",
            font=('Helvetica', 12),
            bg='white',
            fg='#34495e',
            width=15,
            anchor='w'
        ).pack()

        password_input_frame = tk.Frame(password_frame, bg='white')
        password_input_frame.pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.password_entry = tk.Entry(
            password_input_frame,
            textvariable=self.password,
            font=('Helvetica', 12),
            show="•",
            relief=tk.SOLID,
            bd=1,
            bg='white',
            fg='#2c3e50',
            insertbackground='#2c3e50'
        )
        self.password_entry.pack(fill=tk.X, ipady=6)

        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        show_check = tk.Checkbutton(
            password_frame,
            text="Show",
            variable=self.show_password_var,
            command=self.toggle_password,
            bg='white',
            fg='#2c3e50',
            font=('Helvetica', 10),
            activebackground='white',
            activeforeground='#2c3e50',
            selectcolor='white',
            cursor='hand2'
        )
        show_check.pack(side=tk.LEFT)

        # Button section
        button_frame = tk.Frame(main_frame, bg='#f5f5f5')
        button_frame.pack(pady=20)

        self.remove_button = CustomButton(
            button_frame,
            text="🔓 Remove Password",
            command=self.remove_password,
            bg_color='#27ae60',
            hover_color='#2ecc71',
            font=('Helvetica', 13, 'bold'),
            width=250,
            height=50
        )
        self.remove_button.pack()

        # Progress section
        progress_frame = tk.Frame(main_frame, bg='#f5f5f5')
        progress_frame.pack(fill=tk.X, pady=(10, 0))

        self.progress = ttk.Progressbar(
            progress_frame,
            mode='indeterminate',
            length=650
        )
        self.progress.pack(pady=5)

        # Status label
        status_label = tk.Label(
            progress_frame,
            textvariable=self.status,
            font=('Helvetica', 10),
            bg='#f5f5f5',
            fg='#7f8c8d'
        )
        status_label.pack()

    def _create_file_row(self, parent, row, label_text, variable, command):
        """Helper to create file input rows"""
        row_frame = tk.Frame(parent, bg='white')
        row_frame.pack(fill=tk.X, pady=12)

        label_frame = tk.Frame(row_frame, bg='white')
        label_frame.pack(side=tk.LEFT)

        tk.Label(
            label_frame,
            text=label_text,
            font=('Helvetica', 12),
            bg='white',
            fg='#34495e',
            width=15,
            anchor='w'
        ).pack()

        entry_frame = tk.Frame(row_frame, bg='white')
        entry_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        entry = tk.Entry(
            entry_frame,
            textvariable=variable,
            font=('Helvetica', 11),
            relief=tk.SOLID,
            bd=1,
            bg='#f8f9fa',
            fg='#2c3e50',
            state='readonly'
        )
        entry.pack(fill=tk.X, ipady=6)

        # Custom browse button
        browse_btn = CustomButton(
            row_frame,
            text="Browse",
            command=command,
            bg_color='#3498db',
            hover_color='#2980b9',
            font=('Helvetica', 11, 'bold'),
            width=100,
            height=38
        )
        browse_btn.pack(side=tk.LEFT)

    def toggle_password(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="•")

    def browse_input(self):
        """Browse for input PDF file"""
        filename = filedialog.askopenfilename(
            title="Select PDF file",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if filename:
            self.input_file.set(filename)
            # Auto-generate output filename
            input_path = Path(filename)
            output_path = input_path.parent / f"{input_path.stem}_unlocked.pdf"
            self.output_file.set(str(output_path))
            self.status.set(f"Selected: {input_path.name}")

    def browse_output(self):
        """Browse for output PDF location"""
        filename = filedialog.asksaveasfilename(
            title="Save unlocked PDF as",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if filename:
            self.output_file.set(filename)

    def remove_password(self):
        """Remove password from PDF in a separate thread"""
        # Validate inputs
        if not self.input_file.get():
            messagebox.showerror("Error", "Please select an input PDF file")
            return

        if not self.output_file.get():
            messagebox.showerror("Error", "Please specify an output location")
            return

        if not self.password.get():
            result = messagebox.askyesno(
                "No Password",
                "No password entered. Try to open PDF without password?"
            )
            if not result:
                return

        # Disable button and start progress
        self.remove_button.configure(state='disabled')
        self.progress.start(10)
        self.status.set("Processing...")

        # Run in separate thread to prevent UI freezing
        thread = threading.Thread(target=self._remove_password_thread)
        thread.daemon = True
        thread.start()

    def _remove_password_thread(self):
        """Actual password removal logic"""
        try:
            input_path = self.input_file.get()
            output_path = self.output_file.get()
            pwd = self.password.get()

            # Read the encrypted PDF
            reader = PdfReader(input_path)

            # Check if PDF is encrypted
            if reader.is_encrypted:
                if not pwd:
                    self._show_error(
                        "PDF is encrypted. Please provide the password.")
                    return

                # Try to decrypt with the password
                decrypt_result = reader.decrypt(pwd)

                # pypdf returns 0 for failure, 1 for user password, 2 for owner password
                if decrypt_result == 0:
                    self._show_error(
                        "Incorrect password. Please check and try again.")
                    return
                elif decrypt_result == 1:
                    self.root.after(0, lambda: self.status.set(
                        "Decrypted with user password"))
                elif decrypt_result == 2:
                    self.root.after(0, lambda: self.status.set(
                        "Decrypted with owner password"))

            # Create writer and copy all pages
            writer = PdfWriter()

            # Try to access pages (this will fail if password is wrong)
            try:
                page_count = len(reader.pages)
                for page in reader.pages:
                    writer.add_page(page)
            except Exception as page_error:
                self._show_error(
                    f"Could not read PDF pages. The password may be incorrect.\n{str(page_error)}")
                return

            # Copy metadata if available
            try:
                if reader.metadata:
                    writer.add_metadata(reader.metadata)
            except:
                pass  # Skip metadata if it causes issues

            # Write to output file
            with open(output_path, "wb") as output_file:
                writer.write(output_file)

            self._show_success(
                f"Success! Unlocked PDF saved to:\n{Path(output_path).name}")

        except Exception as e:
            self._show_error(f"An error occurred:\n{str(e)}")

    def _show_success(self, message):
        """Show success message on main thread"""
        self.root.after(0, lambda: self._finish_processing(True, message))

    def _show_error(self, message):
        """Show error message on main thread"""
        self.root.after(0, lambda: self._finish_processing(False, message))

    def _finish_processing(self, success, message):
        """Clean up after processing"""
        self.progress.stop()
        self.remove_button.configure(state='normal')

        if success:
            self.status.set("Completed successfully")
            messagebox.showinfo("Success", message)
            # Clear fields
            self.input_file.set("")
            self.output_file.set("")
            self.password.set("")
            self.status.set("Ready to unlock your PDF")
        else:
            self.status.set("Error occurred")
            messagebox.showerror("Error", message)


def main():
    root = tk.Tk()
    app = PDFPasswordRemoverApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
