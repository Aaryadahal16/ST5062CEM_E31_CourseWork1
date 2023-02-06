import base64
import os
import random
import string
import customtkinter as ct
from tkinter import messagebox


from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ct.set_appearance_mode("dark")
ct.set_appearance_mode("blue")

global encrypted_text


window = ct.CTk()
window.title("password manager")
window.geometry("600x340")


# Sample Space
sampleSpace = string.ascii_letters + string.digits + string.punctuation

# Functions
# For getting the credentials


def decryptData(encrypted_text):
    base64_decrypted = base64.b64decode(encrypted_text).decode()
    rot_decrypted = rot13_decode(base64_decrypted)
    return rot_decrypted


def dec_final(master_password_entry):
    global encrypted_text

    master_pw = master_password_entry.get()
    with open("password.txt", "r") as file:
        saved_password = file.read().strip()

    if saved_password == master_pw:

        try:
            with open("decyptedCredential.txt", "w") as f:
                f.write(decryptData(encrypted_text))
            for widget in window.winfo_children():
                widget.destroy()

            master_password = ct.CTkLabel(
                window, text="Enter the master password generated to decrypted the file")
            master_password.pack(pady=17)

            home_btn = ct.CTkButton(
                window, text="Take me Home", command=first_window)
            home_btn.pack(pady=4)

        except:
            print("error")


def master():
    for widget in window.winfo_children():
        widget.destroy()

    master_password = ct.CTkLabel(
        window, text="Enter the master password u generated to decrypted the file")
    master_password.pack(pady=17)

    master_password = ct.CTkLabel(window, text="master password:")
    master_password.pack(pady=5)

    master_password_entry = ct.CTkEntry(window)
    master_password_entry.pack(pady=5)

    submit_button = ct.CTkButton(window, text="Submit", command=lambda: dec_final(
        master_password_entry))
    submit_button.pack(pady=4)

    # master_pw = master_password.get()
    # with open("password.txt", "r") as file:
    #     saved_password = file.read().strip()

    # if saved_password == master_pw:
    #     decryptData(encrypted_text)


def pw_checking(master_password, re_master_password):

    master_password_value = master_password.get()
    re_master_password_value = re_master_password.get()

    if master_password_value == re_master_password_value:
        with open("password.txt", "w") as file:
            file.write(master_password_value)
        master()
        messagebox.showinfo("info", "password has been saved successfully !!")
    else:
        # Show an error message
        ct.CTkLabel(window, text="Error: Passwords do not match.").pack()


def second_window():

    for widget in window.winfo_children():
        widget.destroy()

    master_password = ct.CTkLabel(
        window, text="Enter a Master Password that will help you to decrypted the file")
    master_password.pack(pady=17)

    master_password = ct.CTkLabel(window, text="master password:")
    master_password.pack(pady=5)

    master_password = ct.CTkEntry(window)
    master_password.pack(pady=5)

    re_master_password = ct.CTkLabel(window, text="Retype the master password")
    re_master_password.pack(pady=5)

    re_master_password = ct.CTkEntry(window)
    re_master_password.pack(pady=5)

    submit_button = ct.CTkButton(window, text="Submit", command=lambda: pw_checking(
        master_password, re_master_password))
    submit_button.pack(pady=4)


def rot13_decode(text):

    result = ""
    for char in text:
        ascii_value = ord(char)
        if 65 <= ascii_value <= 90:
            result += chr((ascii_value - 78) % 26 + 65)
        elif 97 <= ascii_value <= 122:
            result += chr((ascii_value - 110) % 26 + 97)
        else:
            result += char
    return result


def rot13_encode(text):
    result = ""
    for char in text:
        ascii_value = ord(char)
        if 65 <= ascii_value <= 90:
            result += chr((ascii_value - 65 + 13) % 26 + 65)
        elif 97 <= ascii_value <= 122:
            result += chr((ascii_value - 97 + 13) % 26 + 97)
        else:
            result += char
    return result


def encryptData(data):
    # Encryption process
    rot_encrypted = rot13_encode(data)
    base64_encrypted = base64.b64encode(rot_encrypted.encode()).decode()
    return base64_encrypted


def writedata(websiteName_entry, Username_entry, password_entry, root):
    global encrypted_text
    '''The function is used for scanning the single port of the given target through the user input.'''

    web_name = websiteName_entry.get()
    user_name = Username_entry.get()
    password = password_entry.get()

    plain_text = f"Site: {web_name}\nUser id: {user_name}\nPassword: {password}\n"
    encrypted_text = encryptData(plain_text)
    with open("credentials.txt", "a") as file:
        file.write(encrypted_text)

    root.destroy()
    a = messagebox.showinfo(
        'Info', "The data u entered have been sucessfully encrypted and saved to credentials.txt")
    if a == "ok":
        b = messagebox.askquestion(
            "Decrypt", "Do you want to decrypt the file?")
        if b == "yes":
            second_window()


def readdata():
    '''The function is used for reading the encrypted credentials from a file.'''

    with open("credentials.txt", "r") as file:
        encrypted_text = file.read()
    decrypted_text = decryptData(encrypted_text)
    print(decrypted_text)


def getCredentials():
    # Credentials Input

    root = ct.CTk()
    root.geometry("340x220")

    for widget in window.winfo_children():
        widget.destroy()
    websiteName_label = ct.CTkLabel(root, text="Website Name:")
    websiteName_label.pack()

    websiteName_entry = ct.CTkEntry(root)
    websiteName_entry.pack()

    Username_label = ct.CTkLabel(root, text="Username:")
    Username_label.pack()

    Username_entry = ct.CTkEntry(root)
    Username_entry.pack()

    password_label = ct.CTkLabel(root, text="Password:")
    password_label.pack()

    password_entry = ct.CTkEntry(root)
    password_entry.pack()

    submit_button = ct.CTkButton(
        root, text="Submit", command=lambda: writedata(websiteName_entry, Username_entry, password_entry, root))
    submit_button.pack()

    root.mainloop()


def first_window():
    for widget in window.winfo_children():
        widget.destroy()

    msg_label = ct.CTkLabel(window, text="Hello, welcome to PassBot"
                            )
    msg_label.pack(pady=10)
    msg_label = ct.CTkLabel(window, text="This is a simple,easy to use password manager,to store all your important credentials."
                            )
    msg_label.pack(pady=10)

    old_label = ct.CTkButton(
        window, text="Click here to view old encrypted passwords")
    old_label.pack(pady=15)

    new_label = ct.CTkButton(
        window, text="Click here to create new encrypted passwords", command=getCredentials)
    new_label.pack(pady=12)


first_window()

window.mainloop()

