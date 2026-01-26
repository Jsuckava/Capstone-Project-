from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk

root = Tk()
root.title('BlockGo - Login')
root.geometry('650x450+200+100')
root.configure(bg='#F4F1EA')
root.resizable(False, False)


# --- FUNCTION: DASHBOARD (Full Screen) ---
def show_dashboard():
    # 1. Clear the login screen
    main_container.pack_forget()
    main_container.destroy()

    # 2. Expand to full screen
    root.resizable(True, True)
    root.state('zoomed')  # Maximizes window on Windows
    root.title('BlockGo System - Campus 1')

    # 3. Create Dashboard Layout
    dashboard_frame = Frame(root, bg='#F4F1EA')
    dashboard_frame.pack(fill='both', expand=True)

    # Top Navigation Bar
    top_nav = Frame(dashboard_frame, bg='#003F88', height=70)
    top_nav.pack(fill='x', side='top')

    Label(top_nav, text="BlockGo Capstone", fg='white', bg='#003F88',
          font=('Helvetica', 18, 'bold')).pack(side='left', padx=20, pady=15)

    # Simple Welcome Content
    content = Frame(dashboard_frame, bg='#F4F1EA')
    content.pack(expand=True)

    Label(content, text=f"Welcome, {user.get()}!", fg='#003F88',
          bg='#F4F1EA', font=('Helvetica', 35, 'bold')).pack()
    Label(content, text="Select an option from the menu to begin managing records.",
          fg='gray', bg='#F4F1EA', font=('Arial', 12)).pack(pady=10)


# --- FUNCTION: LOGIN VALIDATION ---
def login_check():
    username = user.get()
    password = code.get()

    # For now, let's use a simple hardcoded login
    if username == "admin" and password == "1234":
        messagebox.showinfo("Login Success", "Access Granted!")
        show_dashboard()
    else:
        messagebox.showerror("Login Failed", "Invalid Username or Password")


# --- LOGIN SCREEN SETUP ---
main_container = Frame(root, bg='#F4F1EA', highlightbackground='#003F88', highlightthickness=5)
main_container.place(relwidth=1, relheight=1)

img_open = Image.open('plvlogo.png')
img_resized = img_open.resize((100, 100))
img = ImageTk.PhotoImage(img_resized)

logo_label = Label(main_container, image=img, bg='#F4F1EA')
logo_label.pack(pady=(25, 10))

frame = Frame(main_container, width=350, height=350, bg='#F4F1EA')
frame.pack()

heading = Label(frame, text='WELCOME!', fg='#003F88', bg='#F4F1EA', font=('Helvetica', 25, 'bold'))
heading.place(x=80, y=10)


# Username Input
def on_enter(e):
    if user.get() == 'Username':
        user.delete(0, 'end')


def on_leave(e):
    if user.get() == '':
        user.insert(0, 'Username')


user_y = 80
user = Entry(frame, width=25, fg='black', border=0, bg='#F4F1EA', font=('ARIAL', 11))
user.insert(0, 'Username')
user.bind('<FocusIn>', on_enter)
user.bind('<FocusOut>', on_leave)
user.place(x=30, y=user_y)
Frame(frame, width=295, height=2, bg='black').place(x=30, y=user_y + 25)


# Password Input
def on_enter_pw(e):
    if code.get() == 'Password':
        code.delete(0, 'end')
        code.config(show="*")


def on_leave_pw(e):
    if code.get() == '':
        code.config(show="")
        code.insert(0, 'Password')


pass_y = 150
code = Entry(frame, width=25, fg='black', border=0, bg='#F4F1EA', font=('ARIAL', 11))
code.insert(0, 'Password')
code.bind('<FocusIn>', on_enter_pw)
code.bind('<FocusOut>', on_leave_pw)
code.place(x=30, y=pass_y)
Frame(frame, width=295, height=2, bg='black').place(x=30, y=pass_y + 25)


# Hover and Button
def on_enter_btn(e):
    login_btn['background'] = '#5D768B'


def on_leave_btn(e):
    login_btn['background'] = '#FFD500'


login_btn = Button(frame, width=30, pady=7, text='LOGIN',
                   bg='#FFD500', fg='#003F88', border=0,
                   command=login_check,  # Link the function here!
                   cursor='hand2', font=('ARIAL', 10, 'bold'))
login_btn.place(x=50, y=220)

login_btn.bind("<Enter>", on_enter_btn)
login_btn.bind("<Leave>", on_leave_btn)

root.mainloop()