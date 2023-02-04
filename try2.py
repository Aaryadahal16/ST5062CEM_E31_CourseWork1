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

    # for widget in window.winfo_children():
    #     widget.destroy()

    master_pw = master_password_entry.get()
    with open("password.txt", "r") as file:
        saved_password = file.read().strip()

    if saved_password == master_pw:
        
        # # decrypt by either 2 ways:
        # # 1. if only to decrypt the current instance credentials
        # decryptData(encrypted_text)
        #     # ct.CTkLabel(window, text=encrypted_text2).pack()
            
        # # 2. read all the credentials stored in file
        # with open('credentials.txt',"r") as file:
        #     decryptData(file.read())
            
        with open("decyptedCredential.txt", "w") as f:
            f.write(decryptData(encrypted_text))    



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

# decryptData('abc')


#     web_name = input("Enter the website name whose details you want to save:")
#     username = input("Enter the username/email for the site:")
#     passChoice = input("If you want to use a strong generated password type 1 or If you want to use your own password type 2:")

#     if passChoice == '1':
#         passLen=16
#         passLenChoice=input("Default password length is 16, To use a longer/shorter password type 'n' else press any other key:")
#         if passLenChoice.lower()=="n":
#             passLen = int(
#                 input(
#                     "Enter the length of the password that you want to use(e,g:8/10/69) [MAX:128]:"
#                 ))
#             if(passLen > 128):
#                 passLen=16
#                 print("Password length too big , reverting back to default size of 16.")
#         password=""
#         while passLen!=0:
#             password+=random.choice(sampleSpace)
#             passLen-=1

#     elif passChoice == '2':
#         password = input("Enter the password that you want to use:")

#     return [web_name, username, password]


# # For getting the master password


# def getMasterPassword(case):
#     if case==1:
#         masterPassword = input(
#             "Enter a master password to store all your credentials(make sure you remember it):"
#         ).encode()
#     if case==2:
#         masterPassword = input(
#                 "Enter your master password to continue:").encode()

#     return masterPassword


# # For deriving the key


# def keyDeriving(masterPassword, salt=None):
#     # Making a salt file
#     if salt != None:
#         with open("salt.txt", "wb") as slt:
#             slt.write(salt)

#     #When the salt file is already present
#     elif salt == None:
#         try:
#             with open("salt.txt","rb") as slt:
#                 salt = slt.read()
#         # If salt file is not found then it has not been created or is removed.
#         except FileNotFoundError:
#             print()
#             print(
#                 "Error! No entries found! They have been either deleted or not created at the first place."
#             )
#             quit()
#     # One time process of deriving key from master password and salt.

#     kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
#                      length=32,
#                      salt=salt,
#                      iterations=100000,
#                      backend=default_backend())
#     new_key = base64.urlsafe_b64encode(kdf.derive(masterPassword))

#     return new_key


# # For writing the data


# def writeData(web_name, username, password, mode):
#     s1 = '\n' + 'Site:' + web_name + '\n'
#     s2 = 'User id:' + username + '\n'
#     s3 = 'Password:' + password + '\n'
#     # Writing the credentials to a text file.
#     with open("credentials.txt", mode) as file:
#         file.write(s1 + s2 + s3)


# # For encryting the data


# def encryptData(key, case):
#     f = Fernet(key)

#     # Encryption process
#     with open("credentials.txt") as file:
#         data = file.read()
#     encryptedData = f.encrypt(bytes(data, encoding='utf8'))

#     with open("credentials.txt", "w") as file:
#         file.write(encryptedData.decode())
#     if case == 1:
#         print("Your credentials have been safely stored and are encrypted.")
#         return
#     if case == 2:
#         quit()
#     if case == 3:
#         print("Encrypted")


# # For decrypting the data


# def decryptData(new_key):
#     f = Fernet(new_key)
#     with open("credentials.txt") as file:
#         encryptedData = file.read()

#     try:
#         decryptedData = f.decrypt(bytes(encryptedData, encoding='utf8'))

#         with open("credentials.txt", "w") as file:
#             file.write(decryptedData.decode())

#         return
#     except InvalidToken:
#         print()
#         print("Wrong password, please try again!")

#         quit()


# # Help section


# def helpSection():
#     print()
#     print(
#         "Right now,you are viewing the help section of PassBot(A simple yet quite effective password manager)"
#     )
#     print("If you are using this for the 1st time then type 'new' \n")
#     print(
#         "If you have already used this to save some passwords and want to view them ,then type 'old' and choose option 2"
#     )
#     print(
#         "If you have already used this and want to save another password,then type 'old' and choose 1"
#     )
#     print("You will now go back to the menu.")
#     print()
#     return

# Main program starts from here.
# Greetings!


# userChoice = input("Enter your choice:").lower()

# if userChoice == 'new':

#     while True:
#         # prompt for ready

#         readyOrNot = input(
#             "Now we shall ask you for your credentials.When ready type 'ready' else type 'quit':"
#         )
#         # if ready

#         if readyOrNot.lower() == "ready":
#             # input of credentials
#             web_name, username, password = [
#                 str(x) for x in getCredentials()
#             ]

#             # Input for master password
#             masterPassword = getMasterPassword(1)

#             # One time process
#             salt = os.urandom(16)
#             key = keyDeriving(masterPassword, salt)

#             # writing the data
#             writeData(web_name, username, password, 'w')

#             # Encryption process
#             encryptData(key, 1)

#             break
#         elif readyOrNot.lower() == 'quit':
#             quit()
#         else:
#             print("Wrong Choice")
#     break
# if userChoice == 'old':
#     print(
#         "To enter new credentials type 1\nTo view saved passwords type 2:")
#     manageOrStore = input("Enter your choice:")

#         # If user wants to enter new data
#         if manageOrStore == '1':

#             masterPassword=getMasterPassword(2)

#             new_key = keyDeriving(masterPassword)

#             decryptData(new_key)

#             while True:
#                 readyOrNot = input(
#                     "Now we shall ask you for your credentials.When ready type 'ready' else type 'quit': "
#                 )
#                 if readyOrNot.lower() == "ready":

#                     web_name, username, password = [
#                         str(x) for x in getCredentials()
#                     ]

#                     writeData(web_name, username, password, 'a')

#                     encryptData(new_key, 1)

#                     break

#                 # If user wants to quit
#                 elif readyOrNot.lower() == 'quit':
#                     encryptData(new_key, 2)

#         # If user wants to view stored data
#         if manageOrStore == '2':

#             masterPassword=getMasterPassword(2)

#             new_key = keyDeriving(masterPassword)
#             decryptData(new_key)

#             print(
#                 "The file is now decrypted and you can go to it to see your credentials."
#             )

#             while True:
#                 inp = input("When done type 'encrypt': ")
#                 if inp.lower() == 'encrypt':
#                     encryptData(new_key, 3)
#                     break
#         break

#     if userChoice == 'help':
#         helpSection()
#     else:
#         print("Wrong Choice, you will be sent to the help section now")
#         print()
