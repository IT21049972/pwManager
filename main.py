import base64
import hashlib
import sqlite3
import uuid
from functools import partial
from random import choice, randint, shuffle
from tkinter import *  # pylint: disable=(unused-wildcard-import)
from tkinter import messagebox, simpledialog

import customtkinter as ctk
import pyperclip
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
#from build.build import gui
#import build/build/gui.py
#import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#from cProfile import label


backend = default_backend()
salt = b'233' #pylint: disable=invalid-name

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256,
    length = 32,
    salt = salt ,
    iterations=100000,
    backend=backend
)

encryptionKey = 0 #pylint: disable=invalid-name

def encrypt(message: bytes, key: bytes) -> bytes:
    """ encrypts a given message using fernet symmetric alg"""
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    """ decrypts a given message using fernet symmetric alg"""
    return Fernet(token).decrypt(message)

#db
with sqlite3.connect("password_vault_db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL
);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
 password TEXT NOT NULL );
""")

def popUp(text):  #pylint: disable=invalid-name
    answer = simpledialog.askstring("Input string", text)
    return answer
    #print(answer)

#popUp("What's your name")

window = ctk.CTk()
window.title("Password Vault")

def hashPassword(input): #pylint: disable=invalid-name
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash


def firstScreen():
    window.geometry("250x150")
    for widget in window.winfo_children():  # when we switch from the loginscreen
        widget.destroy()                    # function to the password vault function
    lbl = Label(window, text="Create master password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text = "Re enter password")
    lbl1.pack(pady=5)

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()
    txt1.focus()

    lbl2 = Label(window)
    lbl2.pack()

    def savePassword(): #pylint: disable=invalid-name
        if txt.get() == txt1.get():
            sql = "DELETE FROM masterpassword WHERE id=1"
            cursor.execute(sql)


            hashedPasswords = hashPassword(txt.get().encode("utf-8"))

            key = str(uuid.uuid4().hex)
            print(key)
            file = open("key.txt", "w")
            file.write("Recovery Key: " + key)
            file.close

            recoveryKey = hashPassword(key.encode('utf-8')) #pylint: disable=invalid-name

            global encryptionKey
           # x="Abcd1234"
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recoveryKey) VALUES(?, ?) """
            cursor.execute(insert_password, [(hashedPasswords),(recoveryKey)])
            db.commit()

            recoveryScreen(key)
        else:
            lbl2.config(text="Passwords do no match")
        #print("test")


    btn = ctk.CTkButton(window, text="Submit",width=50, command=savePassword)
    btn.pack(pady=10)

def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")

    lbl = Label(window, text="SAVE this key to recover account")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.config(anchor=CENTER)
    lbl1.pack(pady=5)

   # txt1 = Entry(window, width=20, show="*")
    #txt1.pack()
    #txt1.focus()

   # lbl2 = Label(window)
    #lbl2.pack()

    def copyKey():
        pyperclip.copy(lbl1.cget("text"))

    btn = Button(window, text="Copy", command=copyKey)
    btn.pack(pady=10)

    def done():
        passwordVault()

    btn = Button(window, text="Done", command=done)
    btn.pack(pady=10)



def resetScreen(): #pylint: disable=invalid-name
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")

    lbl = Label(window, text="Enter recovery key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack(pady=5)


    def getrecoveryKey(): #pylint: disable=invalid-name
        recoveryKeyCheck = hashPassword(str(txt.get()).encode('utf-8')) #pylint: disable=invalid-name
        cursor.execute("SELECT * FROM masterpassword where id=1 AND recoveryKey = ?",
                       [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey(): #pylint: disable=invalid-name
        checked = getrecoveryKey()

        if checked:
            firstScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong key ")


    btn = Button(window, text="Check Key", command=checkRecoveryKey)
    btn.pack(pady=10)


def loginScreen(): #pylint: disable=invalid-name
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x150")

    lbl = Label(window, text="Enter master password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = ctk.CTkEntry(window, width=200, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.pack()

    def getMasterPassword(): #pylint: disable=invalid-name
        checkHashedPassword = hashPassword(txt.get().encode("utf-8"))
        global encryptionKey
        #test="testt"
        #encryptionKey = base64.urlsafe_b64encode(kdf.derive(test.encode()))
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
        print(encryptionKey)
       # kdf.reset()  # Reset the kdf instance before deriving a new key

        cursor.execute("SELECT * FROM masterpassword where id=1 AND password= ?",
                       [(checkHashedPassword)])
        print(checkHashedPassword)
        return cursor.fetchall()

    def check_Password(): #pylint: disable=invalid-name
        #password = "Test"
        match = getMasterPassword()

        print(match)


        if match:
            passwordVault()
           # print("Right password")
        else:
            #kdf.reset()
            txt.delete(0, 'end') #deletes incorrect input
            lbl1.config(text="Wrong password")
                  #  print("Test")

    def reset_Password(): #pylint: disable=invalid-name
        resetScreen()

    btn = ctk.CTkButton(window, text="Submit", command=check_Password)
    btn.pack(pady=10)

   # btn = ctk.CTkButton(window, text="Reset",width=50, command=resetPassword)
    #btn.pack(pady=10)


def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        window.geometry("350x300")
        for widget in window.winfo_children():
            widget.destroy()

        lbl = Label(window, text="Website")
        lbl.config(anchor=CENTER)
        lbl.pack()

        txt = Entry(window, width=20)
        txt.pack()
        txt.focus()

        lbl1 = Label(window, text="Username")
        lbl1.pack(pady=5)

        txt1 = Entry(window, width=20)
        txt1.pack()
        txt1.focus()

        lbl2 = Label(window, text="Password" )
        lbl2.pack(pady=5)

        txt2 = Entry(window, width=20)
        txt2.pack()
        txt2.focus()

        lbl3 = Label(window)
        lbl3.pack()

       # website = encrypt(txt.get().encode(), encryptionKey)
       # username = encrypt(txt1.get().encode(), encryptionKey)
        # password = encrypt(txt2.get().encode(), encryptionKey)



        def gen_pass():
            letters = [
                "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
                "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
                "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
                "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"
            ]

            numbers = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]

            symbols = ["!", "#", "$", "%", "&", "(", ")", "*", "+"]
            password_letters = [choice(letters) for _ in range(randint(8, 10))]
            password_symbols = [choice(symbols) for _ in range(randint(2, 4))]
            password_numbers = [choice(numbers) for _ in range(randint(2, 4))]
            password_list = password_letters + password_symbols + password_numbers
            shuffle(password_list)
            password = "".join(password_list)
            txt2.delete(0, END)
            txt2.insert(0, password)

        def insert():
            website = txt.get().strip()
            username = txt1.get().strip()
            password = txt2.get().strip()
            if not website:
                messagebox.showerror("Error", "Missing fields ")
                return
            if not username:
                messagebox.showerror("Error", "Missing fields ")
                return
            if not password:
                messagebox.showerror("Error", "Missing fields ")
                return
            website = encrypt(website.encode(), encryptionKey)
            username = encrypt(username.encode(), encryptionKey)
            password = encrypt(password.encode(), encryptionKey)

            insert_fields = """ INSERT INTO vault(website,username,password) VALUES(?,?,?) """

            cursor.execute(insert_fields, (website, username, password))
            db.commit()

            passwordVault()


        def check_Breach():
            passs = txt2.get()
            hash_password = hashlib.sha1(passs.encode()).hexdigest().upper()
            prefix = hash_password[:5]
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            try:
                response = requests.get(url,timeout=30)
                suffixes = [line.split(":")[0] for line in response.text.splitlines()]
                if hash_password[5:] in suffixes:
                    result = messagebox.askyesno("Question",
                                                 "This password has previously appeared in a data breach,"
                                                 " Are you sure you want to use this ")
                    if result is True:
                       insert()
                else:
                    insert()
            except requests.exceptions.RequestException as request_exception: #pylint: disable=(unused-variable)
             #network con issuee
             messagebox.showerror("Error",
                                  "Error connecting to API: {str(request_exception)}")

        btn = ctk.CTkButton(window, text="generate password", command=gen_pass)
        btn.pack(pady=10)

        btn = ctk.CTkButton(window, text="Submit",width=50, command=check_Breach)
        btn.pack(pady=10)

        btn = ctk.CTkButton(window, text=" << back",width=50, command=passwordVault)
        btn.pack(pady=10)

        #wbsite = txt.get()
        #usrname = txt1.get()
        #passwrd = txt2.get()


       #passwordVault()


    def remove_entry(input):
        cursor.execute("DELETE FROM vault WHERE id= ?", (input,))
        db.commit()

        passwordVault()

    window.geometry("750x450")
    # popUp("What's your name")

    lbl = ctk.CTkLabel(window, text = "Password Vault",font=ctk.CTkFont(size=30, weight="bold" ))
    lbl.grid(row=0,column=1)
    #lbl.pack(padx=10, pady=(40, 20))



    btn = ctk.CTkButton(window, text="Add +", command=addEntry)
    btn.grid(row=1,column=1, pady=10)

    def logout():
        #for widget in window.winfo_children():
        # when we switch from the loginscreen function to the password vault function
         #   widget.destroy()

            result = messagebox.askyesno("Question", "Do you want to log out?")

            # check the user's response and display a message accordingly
            if result is True:
               # for widget in window.winfo_children():
               # when we switch from the loginscreen
               # function to the password vault function
                #    widget.destroy()
               # loginScreen()
                window.after(1000,  window.destroy())
               # loginScreen()

                #result == False
               # messagebox.showinfo("Result", "You clicked Yes!")
            #else:
             #   for widget in window.winfo_children():
        # when we switch from the loginscreen function to
    # the password vault function
              #      widget.destroy()
                #passwordVault()
                #messagebox.showinfo("Result", "You clicked No!")

    #  loginScreen()

    def edit_entry(idd):
        window.geometry("350x300")
        for widget in window.winfo_children():
            widget.destroy()

        lbl = Label(window, text="Website")
        lbl.config(anchor=CENTER)
        lbl.pack()

        txt = Entry(window, width=20)
        txt.pack()
        txt.focus()

        lbl1 = Label(window, text="Username")
        lbl1.pack(pady=5)

        txt1 = Entry(window, width=20)
        txt1.pack()
        txt1.focus()

        lbl2 = Label(window, text="Password")
        lbl2.pack(pady=5)

        txt2 = Entry(window, width=20)
        txt2.pack()
        txt2.focus()

        lbl3 = Label(window)
        lbl3.pack()

        def update():
            website = txt.get().strip()
            username = txt1.get().strip()
            password = txt2.get().strip()
            if not website:
                messagebox.showerror("Error", "Missing fields ")
                return
            if not username:
                messagebox.showerror("Error", "Missing fields ")
                return
            if not password:
                messagebox.showerror("Error", "Missing fields ")
                return
            website = encrypt(website.encode(), encryptionKey)
            username = encrypt(username.encode(), encryptionKey)
            password = encrypt(password.encode(), encryptionKey)
            update_fields = """ UPDATE vault SET website=?, username=?, password=? WHERE id=? """
            cursor.execute(update_fields, (website, username, password, idd))
            db.commit()
            passwordVault()

        # passwordVault()

        btn = ctk.CTkButton(window, text="update", width=50, command=update)
        btn.pack(pady=10)
        btn = ctk.CTkButton(window, text=" << cancel",width=50, command=passwordVault)
        btn.pack(pady=10)

    btn = ctk.CTkButton(window, text="Log out", width=50, command=logout)
   # btn.configure(background="red", foreground="white")
    btn.grid(row=0,column=4, pady=10)

    lbl = ctk.CTkLabel(window, text="Website",font=ctk.CTkFont(size=16, weight="bold" ))
    lbl.grid(row=2, column=0, padx=80)

    lbl = Label(window, text="Username",font=ctk.CTkFont(size=16, weight="bold" ))
    lbl.grid(row=2, column=1, padx=80)

    lbl = Label(window, text="Password",font=ctk.CTkFont(size=16, weight="bold" ))
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")

    if cursor.fetchall() is not None:
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if (len(array) == 0 ):
                break

            lbl = ctk.CTkLabel(window,
                               text=(decrypt(array[i][1], encryptionKey)),
                               font=("Helvetica", 14))
            lbl.grid(column=0, row=(i+3))
            #print ((decrypt(array[i][1], encryptionKey)))

            lbl = ctk.CTkLabel(window,
                               text=(decrypt(array[i][2], encryptionKey)),
                               font=("Helvetica", 14))
            lbl.grid(column=1, row=(i+3))


            lbl = ctk.CTkLabel(window,
                               text=(decrypt(array[i][3], encryptionKey)),
                               font=("Helvetica", 14))
            lbl.grid(column=2, row=(i+3), padx=(0, 20))

            btn = ctk.CTkButton(window, text="edit", width=50,
                                command=partial(edit_entry, array[i][0]))
            btn.grid(column=4, row=i + 3, pady=20, padx=(0, 5))

            btn = ctk.CTkButton(window, text="Delete",width=50,
                                command= partial(remove_entry,array[i][0]))
            #btn.configure(bg="red")
            btn.grid(column=5, row=i+3, pady=20, padx=(0, 5))

           # btn = Button(window, text="Edit", command= partial(removeEntry,array[i][0]))
            #btn.grid(column=5, row=i+3, pady=20)

            i=i+1

            cursor.execute("SELECT * FROM vault")
            if len(cursor.fetchall()) <= i:
                break


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()

window.mainloop()