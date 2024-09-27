import string
import secrets
import os
import sys
import re
import requests
import fontstyle
import json
from cryptography.fernet import Fernet
import base64

password_history= []
#Password Generation Code
def password_gen(length, incl_uppercase, incl_lowercase, incl_numbers, incl_specsym):
    characters= ""
    if incl_uppercase:
        characters+= string.ascii_uppercase
    if incl_lowercase:
        characters+= string.ascii_lowercase
    if incl_numbers:
        characters+= string.digits
    if incl_specsym:
        characters+= string.punctuation
    
    first_part=""
    if incl_uppercase:
        first_part+=string.ascii_uppercase
    if incl_lowercase:
        first_part+=string.ascii_lowercase
    
    generated_pass= ''.join(secrets.choice(first_part) for i in range(3))

    remaining_length= length-len(generated_pass)
    if remaining_length>0:
        generated_pass+= ''.join(secrets.choice(characters) for i in range(remaining_length))
    
    password_history.append(generated_pass)
    if len(password_history)>6:
        password_history.pop(0)
    return generated_pass

#Password Strength Check code
def pass_strength_check(password):
    suggestions=[]

    if len(password)<8:
        suggestions.append("Password should be at least 8 characters long")
    if not re.search(r'[A-Z]',password):
        suggestions.append("Password should consist of uppercase letters and lowercase letters")
    if not re.search(r'[a-z]',password):
        suggestions.append("Password should consist of uppercase letters and lowercase letters")
    if not re.search(r'\d',password):
        suggestions.append("Password should include numbers")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]',password):
        suggestions.append("Password should include special symbols")
    
    response= requests.get('https://lucidar.me/en/security/files/100000-most-common-passwords.json')
    common_passwords= response.json()
    if password.lower() in common_passwords:
        suggestions.append("Password is common")
    
    if len(suggestions)==0:
        return "Strong password",[]
    else:
        return "Weak password", suggestions

#Password history functions
def pass_history_view():
    last_index=0
    if len(password_history)>0:
        last_index= len(password_history)-1
        idx_numbering=1
        for pass_idx in range(last_index,-1,-1):
            print(f"{idx_numbering}: {password_history[pass_idx]}")
            idx_numbering+=1
    else:
        print("No passwords in history")
def pass_history_save(filename= 'password_history.json'):
    with open(filename, 'w') as file:
        json.dump(password_history,file)
def pass_history_load(filename='password_history.json'):
    global password_history
    try:
        with open(filename,'r') as file:
            password_history=json.load(file)
    except FileNotFoundError:
        password_history=[]
    except json.JSONDecodeError:
        password_history=[]


#Convert input into boolean
def boolean_in(prompt):
    while True:
        user_input= input(prompt).strip().lower()
        if user_input in ['y','n']:
            return user_input=='y'
        else:
            print("Invalid input. Please enter 'y' or 'n'")

#Main function for password generation
def password_gen_main():
    pass_length= int(input("Enter the desired length of the password: "))
    if pass_length<6:
        print("Enter atleast 6 length")
        sys.exit()

    incl_uppercase= boolean_in("Include Uppercase letters? (y/n): ")
    incl_lowercase= boolean_in("Include Lowercase letters? (y/n): ")
    incl_numbers=  boolean_in("Include Numbers? (y/n): ")
    incl_specsym= boolean_in("Include Special Symbols? (y/n): ")

    if (incl_uppercase==False and incl_lowercase==False and incl_numbers==False and incl_specsym==False):
        print("Please select at least one option to generate a password")
        print("Exiting the program")
        sys.exit()
    else:
        password= password_gen(pass_length, incl_uppercase, incl_lowercase, incl_numbers, incl_specsym)
        print("Generated password: "+fontstyle.apply(password,"bold"))
        pass_strength, suggestions= pass_strength_check(password)
        if pass_strength=='Strong password':
            print("\nPassword strength: "+fontstyle.apply(pass_strength,"bold/green"))
        else:
            print("\nPassword strength: "+fontstyle.apply(pass_strength,"bold/red"))
        if len(suggestions)>0:
            print("Suggestions to improve password strength:\n")
            for suggestion in suggestions:
                print(fontstyle.apply(f": {suggestion}","italic"))

#Main function for password strength check
def password_check_main():
    user_password= input("Enter a password to evaluate: ")
    pass_strength, suggestions= pass_strength_check(user_password)
    if pass_strength=='Strong password':
        print("\nPassword strength: "+fontstyle.apply(pass_strength,"bold/green"))
    else:
        print("\nPassword strength: "+fontstyle.apply(pass_strength,"bold/red"))
    if len(suggestions)>0:
        print("Suggestions to improve password strength:\n")
        for suggestion in suggestions:
            print(fontstyle.apply(f": {suggestion}","italic/yellow"))

#Key Generation for encrypting passwords
def generate_fernet_key():
    return Fernet.generate_key()
def load_fernet_key():
    return open("pass_secret.key","rb").read()
def encrypt_pass(data,key):
    crypt = Fernet(key)
    encrypted_data = crypt.encrypt(data.encode())
    return base64.b64encode(encrypted_data).decode()  # Convert bytes to base64 string
def decrypt_pass(data,key):
    crypt = Fernet(key)
    decoded_data = base64.b64decode(data.encode())
    return crypt.decrypt(decoded_data).decode()  # Decode the base64 string back to plaintext

#Password manager functions
def pass_manager_save(data):
    with open("pass_manager.json","w") as file:
        json.dump(data,file)
def pass_manager_load():
    if os.path.exists("pass_manager.json"):
        with open("pass_manager.json","r") as file:
            return json.load(file)
    return {}
def pass_manager_add(pass_manager_passwords,key):
    website= input("Enter the website name: ")
    username= input("Enter your username: ")
    usr_pass= input("Enter your password: ")
    encrypted_password = encrypt_pass(usr_pass, key)
    encrypted_username = encrypt_pass(username, key)

    pass_manager_passwords[website]={
        "username":encrypted_username,
        "password":encrypted_password
    }
    pass_manager_save(pass_manager_passwords)
    print(f"Credentials for \"{website}\" added successfully.")
def pass_manager_retrieve(pass_manager_passwords,key):
    usr_choose=input("1.Retrieve using website name\n2.Retrieve using username\n")
    if usr_choose=="1":
        website=input("Enter the website name: ")
        if website in pass_manager_passwords:
            decrypted_username = decrypt_pass(pass_manager_passwords[website]["username"], key)
            decrypted_password = decrypt_pass(pass_manager_passwords[website]["password"], key)
            print("\nCredentials\n-----------")
            print(f"Account: {website}")
            print(f"Username : {decrypted_username}")
            print(f"Password : {decrypted_password}")
        else:
            print(f"No credentials found for {website}")
    elif usr_choose=="2":
        usrname=input("Enter the username: ")
        found= False
        for website,account in pass_manager_passwords.items():
            decrypted_username = decrypt_pass(account["username"], key)
            if decrypted_username == usrname:
                decrypted_password = decrypt_pass(account["password"], key)
                print("\nCredentials\n-----------")
                print(f"Account: {website}")
                print(f"Username: {decrypted_username}")
                print(f"Password: {decrypted_password}")
                found = True
                break
            if not found:
                print(f"No credentials found for {usrname}")

#Main function for password manager
def password_manager_main():
    while True:
        if not os.path.exists("pass_secret.key"):
            key = generate_fernet_key()
            with open("pass_secret.key", "wb") as key_file:
                key_file.write(key)
    
        key = load_fernet_key()
        pass_manager_passwords = pass_manager_load()

        print("\nPassword Manager Menu:")
        print("1. Add a password\n2. Retrieve a password\n3. Go back\n4. Exit")
        choice= input("Enter your required action: ")
        if choice == "1":
            pass_manager_add(pass_manager_passwords,key)
        elif choice == "2":
            pass_manager_retrieve(pass_manager_passwords,key)
        elif choice == "3":
            break
        elif choice == "4":
            print("Exiting...")
            sys.exit()
        else:
            print("Invalid input. Please enter 1, 2, 3 or 4")
            sys.exit()


#Code execution beginning
print("Welcome to PassGen")
print("------------------")
while(True):
    initial_input= input("\n1.Generate a password\n2.Check password strength\n3.View generation history\n4.Password Manager\n5.Exit\n")

    if initial_input=='1':
        pass_history_load()
        password_gen_main()
        pass_history_save()
    elif initial_input=='2':
        password_check_main()
    elif initial_input=='3':
        pass_history_load()
        pass_history_view()
    elif initial_input=='4':
        password_manager_main()
    elif initial_input=='5':
        print("Exiting...")
        sys.exit()
    else:
        print("Invalid input. Please enter any of the options specified (Use numbers given to the left)")
        sys.exit()