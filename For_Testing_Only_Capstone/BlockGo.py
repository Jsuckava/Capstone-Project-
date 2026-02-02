import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from datetime import datetime
import openpyxl
from openpyxl.styles import Font, Alignment, Border, Side
from openpyxl.utils import get_column_letter


class App:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Student System")
        self.master.geometry("1350x720")
        self.role = None
        self.user = None
        self.editable_row = None
        
        # Sample data for demonstration
        self.sample_data = []
        
        self.create_login_ui()

    def clear_ui(self):
        """Clear all widgets from the window."""
        for w in self.master.winfo_children():
            w.destroy()

    def create_login_ui(self):
        """Create the login interface."""
        self.clear_ui()
        f = ttk.Frame(self.master, padding=30)
        f.pack(expand=True)
        
        ttk.Label(f, text="Username").grid(row=0, column=0, sticky='w', pady=6)
        self.e_user = ttk.Entry(f, width=30)
        self.e_user.grid(row=0, column=1, pady=6)
        
        ttk.Label(f, text="Password").grid(row=1, column=0, sticky='w', pady=6)
        self.e_pass = ttk.Entry(f, width=30, show='*')
        self.e_pass.grid(row=1, column=1, pady=6)
        
        ttk.Button(f, text="Login", command=self.login).grid(row=2, column=0, columnspan=2, pady=15)

    def login(self):
        """Handle login authentication."""
        u, p = self.e_user.get().strip(), self.e_pass.get()
        
        # Placeholder for authentication logic
        # TODO: Add your authentication logic here
        if u and p:
            self.user = u
            self.role = 'admin' if u.lower() == 'admin' else 'user'
            self.create_dashboard()
        else:
            messagebox.showerror("Login", "Invalid credentials")

    def create_dashboard(self):
        """Create the main dashboard interface."""
        self.clear_ui()
        
        # Top toolbar
        top = ttk.Frame(self.master)
        top.pack(fill='x', padx=12, pady=6)
        
        ttk.Label(top, text="Search student name:").pack(side='left')
        self.search_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.search_var, width=30).pack(side='left', padx=4)
        ttk.Button(top, text="Search", command=self.do_search).pack(side='left', padx=2)
        ttk.Button(top, text="Clear", command=self.clear_search).pack(side='left', padx=2)
        ttk.Button(top, text="Add Transaction", command=self.add_dialog).pack(side='right', padx=5)
        ttk.Button(top, text="Change Password", command=self.change_password_dialog).pack(side='right', padx=5)
        
        if self.role == 'admin':
            ttk.Button(top, text="Add User", command=self.add_user_dialog).pack(side='right', padx=5)
            ttk.Button(top, text="Export Daily Report", command=self.export_daily_report).pack(side='right', padx=5)
        
        ttk.Button(top, text="Logout", command=self.logout).pack(side='right', padx=5)

        # Configure treeview style
        style = ttk.Style(self.master)
        style.theme_use("default")
        style.configure("Treeview", background="white", foreground="black", rowheight=25, fieldbackground="white")
        style.map('Treeview', background=[('selected', 'lightblue')])

        # Create treeview
        cols = ("ID", "Name", "Section", "Course", "Year", "Address", "Amount", "Transaction Type", "Created By")
        self.tree = ttk.Treeview(self.master, columns=cols, show='headings')
        
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=110, anchor='center')
        
        self.tree.column("Name", width=160)
        self.tree.column("Address", width=180)
        self.tree.column("Transaction Type", width=150)
        self.tree.pack(fill='both', expand=True, padx=12, pady=6)

        self.tree.bind("<Double-1>", self.on_double_click)

        # Admin controls
        if self.role == 'admin':
            admin_bar = ttk.Frame(self.master)
            admin_bar.pack(fill='x', pady=2)
            ttk.Button(admin_bar, text="Delete Selected", command=self.delete_selected).pack(side='right', padx=5)

        self.load_all()

    def load_all(self):
        """Load all transactions into the treeview."""
        # TODO: Replace with actual database query
        # For now, display sample data
        self._populate_tree(self.sample_data)

    def do_search(self):
        """Search for transactions by student name."""
        term = self.search_var.get().strip()
        if not term:
            messagebox.showinfo("Search", "Enter a name first.")
            return
        
        # TODO: Replace with actual database search query
        messagebox.showinfo("Search", f"Searching for: {term}")
        self._populate_tree(self.sample_data)

    def clear_search(self):
        """Clear search and reload all data."""
        self.search_var.set("")
        self.load_all()

    def _populate_tree(self, data):
        """Populate treeview with data."""
        self.tree.delete(*self.tree.get_children())
        for r in data:
            self.tree.insert('', 'end', values=(
                r.get('transactionid', ''),
                r.get('name', ''),
                r.get('section', ''),
                r.get('course', ''),
                r.get('year', ''),
                r.get('address', ''),
                r.get('amount', ''),
                r.get('TransactionCreated', ''),
                r.get('created_by', '')
            ))

    def add_dialog(self):
        """Open dialog to add new transaction."""
        dlg = AddTransactionDialog(self.master, self.user)
        self.master.wait_window(dlg)
        if dlg.result:
            # TODO: Add database insert logic here
            messagebox.showinfo("Success", "Transaction added successfully!")
            self.load_all()

    def on_double_click(self, event):
        """Handle double-click on treeview cell for editing."""
        sel = self.tree.selection()
        if not sel:
            return
        
        item = self.tree.item(sel[0])
        col = self.tree.identify_column(event.x)
        col_idx = int(col[1:]) - 1
        col_name = self.tree['columns'][col_idx]
        tid = item['values'][0]

        if self.role == 'user':
            if self.editable_row and self.editable_row != tid:
                messagebox.showwarning("Edit", "Finish the current edit first.")
                return
            self.editable_row = tid

        if self.role == 'admin':
            self.start_cell_edit(sel[0], col_idx, col_name, tid)
            return

        new_val = simpledialog.askstring("Edit", f"New value for {col_name} (ID {tid}):")
        if new_val is None:
            return

        if col_name == 'Amount' and self.role == 'user':
            messagebox.showwarning("Permission", "Users cannot edit Amount.")
            return

        # TODO: Add database update logic here
        messagebox.showinfo("Success", f"Updated {col_name} to {new_val}")
        self.load_all()

    def start_cell_edit(self, item_id, col_idx, col_name, tid):
        """Start inline editing for admin users."""
        x, y, w, h = self.tree.bbox(item_id, column=f"#{col_idx + 1}")
        if not x:
            return
        
        entry = ttk.Entry(self.tree)
        entry.insert(0, self.tree.item(item_id)['values'][col_idx])
        entry.select_range(0, 'end')
        entry.focus()
        entry.place(x=x, y=y, width=w, height=h)

        def save():
            new_val = entry.get()
            # TODO: Add database update logic here
            messagebox.showinfo("Success", f"Updated {col_name}")
            self.load_all()
            entry.destroy()

        def cancel():
            entry.destroy()

        entry.bind("<Return>", lambda e: save())
        entry.bind("<Escape>", lambda e: cancel())
        entry.bind("<FocusOut>", lambda e: save())

    def delete_selected(self):
        """Delete selected transaction (admin only)."""
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Choose a row")
            return
        
        tid = self.tree.item(sel[0])['values'][0]
        if messagebox.askyesno("Delete", f"Delete ID {tid}?"):
            # TODO: Add database delete logic here
            messagebox.showinfo("Success", f"Deleted transaction {tid}")
            self.load_all()

    def logout(self):
        """Handle logout."""
        self.user = self.role = None
        self.create_login_ui()

    def add_user_dialog(self):
        """Admin function to add new user."""
        dlg = simpledialog.askstring("Add User", "Enter new username:")
        if not dlg:
            return
        pw = simpledialog.askstring("Add User", f"Enter password for {dlg}:", show='*')
        if not pw:
            return
        
        # TODO: Add database insert logic here
        messagebox.showinfo("Success", f"User {dlg} added.")

    def change_password_dialog(self):
        """Handle password change for users and admins."""
        if self.role == 'admin':
            user_to_change = simpledialog.askstring("Change Password", "Enter username to change password:")
            if not user_to_change:
                return
            new_pass = simpledialog.askstring("Change Password", f"Enter new password for {user_to_change}:", show='*')
            if not new_pass:
                return
            
            # TODO: Add database update logic here
            messagebox.showinfo("Success", f"Password for {user_to_change} updated.")
        else:
            admin_pass = simpledialog.askstring("Admin Verification", "Enter Admin password to change your password:", show='*')
            if not admin_pass:
                return
            
            # TODO: Add admin verification logic here
            new_pass = simpledialog.askstring("Change Password", "Enter your new password:", show='*')
            if not new_pass:
                return
            
            # TODO: Add database update logic here
            messagebox.showinfo("Success", "Your password has been updated.")

    def export_daily_report(self):
        """Export daily report to Excel (admin only)."""
        date_str = simpledialog.askstring("Report Date", "Enter date (YYYY-MM-DD) or leave blank for today:")
        
        # TODO: Replace with actual database query
        report_data = {}  # Empty report for demonstration
        report_date = datetime.now().date() if not date_str else date_str

        if not report_data:
            messagebox.showinfo("No Data", f"No non-admin entries on {report_date}")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx")],
            initialfile=f"daily_report_{report_date}.xlsx"
        )
        if not filename:
            return

        try:
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = f"Report {report_date}"
            title = f"Daily Transaction Report - {report_date}"
            ws.merge_cells('A1:I1')
            ws['A1'] = title
            ws['A1'].font = Font(size=14, bold=True)
            ws['A1'].alignment = Alignment(horizontal='center')

            row = 3
            for user, entries in report_data.items():
                ws.cell(row, 1, f"User: {user}").font = Font(bold=True)
                ws.cell(row, 2, f"Total Entries: {len(entries)}").font = Font(bold=True)
                row += 1

                headers = ["ID", "Name", "Section", "Course", "Year", "Address", "Amount", "Type"]
                for col, h in enumerate(headers, 1):
                    cell = ws.cell(row, col, h)
                    cell.font = Font(bold=True)
                    cell.border = Border(top=Side(style='thin'), bottom=Side(style='thin'),
                                         left=Side(style='thin'), right=Side(style='thin'))
                    cell.alignment = Alignment(horizontal='center')
                row += 1
                
                for entry in entries:
                    for col, key in enumerate(["ID", "Name", "Section", "Course", "Year", "Address", "Amount", "Type"], 1):
                        val = entry[key]
                        if key == "Amount":
                            val = f"₱{val:,.2f}"
                        ws.cell(row, col, val)
                    row += 1
                row += 1

            for col in range(1, 9):
                max_len = 0
                column = get_column_letter(col)
                for cell in ws[column]:
                    try:
                        if len(str(cell.value)) > max_len:
                            max_len = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_len + 2, 50)
                ws.column_dimensions[column].width = adjusted_width

            wb.save(filename)
            messagebox.showinfo("Success", f"Report saved to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save Excel: {e}")


class AddTransactionDialog(tk.Toplevel):
    """Dialog for adding new transactions."""
    
    def __init__(self, parent, username):
        super().__init__(parent)
        self.title("Add Transaction")
        self.geometry("480x500")
        self.username = username
        self.result = False
        
        fields = ["Name", "Section", "Course", "Year", "Address", "Amount", "Transaction Type"]
        self.entries = {}
        
        for i, f in enumerate(fields):
            ttk.Label(self, text=f"{f}:").grid(row=i, column=0, sticky='e', padx=10, pady=5)
            
            if f == "Transaction Type":
                var = tk.StringVar(value="School Fee")
                combo = ttk.Combobox(self, textvariable=var, state="readonly", width=35)
                combo['values'] = [
                    "School Fee", "Miscellaneous Fee", "ID Fee", "Enrollment Fee",
                    "Uniform Fee", "COR Replacement Fee", "ID Replacement Fee",
                    "Library Fee", "Other Fees"
                ]
                combo.grid(row=i, column=1, padx=10, pady=5)
                self.entries[f] = var
            else:
                e = ttk.Entry(self, width=38)
                e.grid(row=i, column=1, padx=10, pady=5)
                self.entries[f] = e

        btns = ttk.Frame(self)
        btns.grid(row=len(fields), column=0, columnspan=2, pady=15)
        ttk.Button(btns, text="Save", command=self.save).pack(side='left', padx=6)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side='left', padx=6)

    def save(self):
        """Save the transaction."""
        data = {}
        for k, w in self.entries.items():
            val = w.get().strip() if hasattr(w, 'get') else w.get()
            if not val:
                messagebox.showwarning("Empty", f"{k} is required")
                return
            data[k] = val

        try:
            amount = float(data["Amount"])
        except ValueError:
            messagebox.showwarning("Invalid", "Amount must be a number")
            return

        # TODO: Add database insert logic here
        # Store the data that was collected
        self.transaction_data = data
        self.result = True
        self.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
