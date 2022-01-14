import os
from tkinter import *
import tkinter.ttk as ttk
import pywhatkit as pw
from tkinter import messagebox, DISABLED
from tkinter import filedialog, simpledialog
import KeyPass as kp
from cryptography.fernet import Fernet


###################################################################################################

def access():
    file = open('Keys/gen.key', 'rb')
    key = file.read()
    file.close()
    return key


def ki():
    k = simpledialog.askstring("Generate Key", "Please Enter Your Key!")
    kp.gen_key(k)


###################################################################################################

def enc_txt(x):
    try:
        ki()
        key = access()
        msg = x
        encoded = msg.encode()  # Encoding
        f = Fernet(key)
        encrypted = f.encrypt(encoded)  # Encryption
        f_msg = encrypted.decode()  # Decoding
        bd1_lbl3.set(f_msg)

    except:
        messagebox.showwarning(title='Error!', message='Wrong Key!')


def dec_txt(x):
    try:
        ki()
        key = access()
        msg = x
        encoded = msg.encode()  # Encoding
        f = Fernet(key)
        decrypted = f.decrypt(encoded)
        f_msg = decrypted.decode()  # Decoding
        bd1_lbl3.set(f_msg)

    except:
        messagebox.showwarning(title='Error!', message='Wrong Key!')


###################################################################################################

def enc_fl(x):
    ki()
    key = access()
    fn = set_name()
    with open(x, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    enc_f = 'Enc/En-' + fn
    with open(enc_f, 'wb') as f:
        f.write(encrypted)


def dec_fl(x):
    ki()
    key = access()
    fn = set_name()
    enc_f = 'Enc/En-' + fn
    dec_f = 'Dec/De-' + fn
    with open(enc_f, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
    with open(dec_f, 'wb') as f:
        f.write(decrypted)


###################################################################################################

def set_name():
    old_file = bd2_ent1.get()
    new_file = bd2_ent2.get().capitalize()
    ext = os.path.splitext(old_file)
    final = str(new_file + ext[-1])
    return final


def show_body(body):
    body.place(relx=0.5, rely=0.1, relheight=0.6, relwidth=0.7, anchor='n')
    body.tkraise()


def br_file():
    fn = filedialog.askopenfilename(initialdir="D:", title="Select File")
    bd2_ent1.set(str(fn))


def copy(txt):
    root.clipboard_append(txt)


def sndmsg(text):
    num = simpledialog.askstring("Enter Contact", "Please Enter Recipient's Contact Number!")
    pw.sendwhatmsg_instantly("+91" + num, text)


###################################################################################################

white = '#ffffff'
black = '#000000'
teal = '#40d3df'
torq = '#008080'
font = 'Koho'

###################################################################################################

root = Tk()
root.title("Cipherer")
canvas = Canvas(root, height=500, width=750, bg=teal)
canvas.pack()

frm = ttk.Style(root)
frm.configure("TFrame", background=white)

lbl = ttk.Style(root)
lbl.configure("TLabel", background=white, foreground=torq)

btn = ttk.Style(root)
btn.configure("TButton", font=(font, 11), foreground=torq, background=white)

btn = ttk.Style(root)
btn.configure("TEntry", font=(font, 11), foreground=torq)

###################################################################################################

bd1_lbl3 = StringVar()

body1 = ttk.Frame(root)
body1.place(relx=0.5, rely=0.1, relheight=0.6, relwidth=0.7, anchor='n')

bd1_label1 = ttk.Label(body1, text="Enter Your Message :", font=(font, 15))
bd1_label1.place(relx=0.1, rely=0.01, relheight=0.15, relwidth=0.8)

bd1_entry1 = ttk.Entry(body1, font=(font, 13))
bd1_entry1.place(relx=0.1, rely=0.2, relheight=0.1, relwidth=0.8)

bd1_enc_button = ttk.Button(body1, text="Encrypt", command=lambda: enc_txt(bd1_entry1.get()))
bd1_enc_button.place(relx=0.25, rely=0.45, relheight=0.12, relwidth=0.2, anchor='w')

bd1_dec_button = ttk.Button(body1, text="Decrypt", command=lambda: dec_txt(bd1_entry1.get()))
bd1_dec_button.place(relx=0.75, rely=0.45, relheight=0.12, relwidth=0.2, anchor='e')

bd1_label2 = ttk.Label(body1, text="Processed Message : ", font=(font, 15))
bd1_label2.place(relx=0.1, rely=0.55, relheight=0.15, relwidth=0.8)

bd1_label3 = ttk.Label(body1, text="", textvariable=bd1_lbl3, font=(font, 13))
bd1_label3.place(relx=0.1, rely=0.7, relheight=0.1, relwidth=0.8)

cpy_button = ttk.Button(body1, text="Copy", command=lambda: copy(bd1_lbl3.get()))
cpy_button.place(relx=0.25, rely=0.85, relheight=0.12, relwidth=0.2)

snd_button = ttk.Button(body1, text="Send", command=lambda: sndmsg(bd1_lbl3.get()))
snd_button.place(relx=0.55, rely=0.85, relheight=0.12, relwidth=0.2)

###################################################################################################

bd2_ent1 = StringVar()
bd2_ent2 = StringVar()

body2 = ttk.Frame(root)
# body2.place(relx=0.5, rely=0.2, relheight=0.6, relwidth=0.7, anchor='n')

bd2_label1 = ttk.Label(body2, text="Select Your File :", font=(font, 15))
bd2_label1.place(relx=0.1, rely=0.01, relheight=0.15, relwidth=0.8)

bd2_entry1 = ttk.Entry(body2, state=DISABLED, textvariable=bd2_ent1, font=(font, 13))
bd2_entry1.place(relx=0.1, rely=0.2, relheight=0.1, relwidth=0.55)

bd2_btn1 = ttk.Button(body2, text="Browse...", command=br_file)
bd2_btn1.place(relx=0.69, rely=0.2, relheight=0.12, relwidth=0.21)

bd2_label2 = ttk.Label(body2, text="Set Your FileName :", font=(font, 15))
bd2_label2.place(relx=0.1, rely=0.37, relheight=0.15, relwidth=0.8)

bd2_entry2 = ttk.Entry(body2, textvariable=bd2_ent2, font=(font, 13))
bd2_entry2.place(relx=0.1, rely=0.55, relheight=0.1, relwidth=0.8)

bd2_enc_button = ttk.Button(body2, text="Encrypt", command=lambda: enc_fl(bd2_ent1.get()))
bd2_enc_button.place(relx=0.25, rely=0.8, relheight=0.12, relwidth=0.2, anchor='w')

bd2_dec_button = ttk.Button(body2, text="Decrypt", command=lambda: dec_fl(bd2_ent1.get()))
bd2_dec_button.place(relx=0.75, rely=0.8, relheight=0.12, relwidth=0.2, anchor='e')

###################################################################################################

end = ttk.Frame(root)
end.place(relx=0.5, rely=0.75, relheight=0.1, relwidth=0.7, anchor='n')

end_btn1 = ttk.Button(end, text="Text Mode", command=lambda: show_body(body1))
end_btn1.place(relx=0.15, rely=0.5, relheight=0.8, relwidth=0.3, anchor='w')

end_btn2 = ttk.Button(end, text="File Mode", command=lambda: show_body(body2))
end_btn2.place(relx=0.85, rely=0.5, relheight=0.8, relwidth=0.3, anchor='e')

root.mainloop()

###################################################################################################
