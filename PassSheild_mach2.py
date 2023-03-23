import hashlib
import random
import string
import tkinter as tk
from tkinter import messagebox, simpledialog
import pyperclip


m_pass = "12345"

# Functions
def generate_password():
    """Generate a random password and insert it into the password entry field."""
    password = "".join(random.choices(string.ascii_letters + string.digits, k=10))
    pyperclip.copy(password)
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

def save_password():
    """Save the website, userid, and password to a text file."""
    website = website_entry.get()
    userid = userid_entry.get()
    password = password_entry.get()
        
    # Hash the password before saving it to the file
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Read the data from the file and check for existing passwords
    existing_password = None
    with open("passwords.txt", "r") as f:
        for line in f:
            data = line.strip().split(",")
            if data[0] == website and data[1] == userid:
                existing_password = data[2]
                break

    # If an existing password was found, ask the user if they want to retrieve or rewrite it
    if existing_password:
        response = messagebox.askyesno(title="Password Already Exists", message="A password already exists for this website and userid. Do you want to retrieve the existing password?")
        if response:
            # Ask the user to enter the master password
            master_password = simpledialog.askstring(title="Master Password",
                                                     prompt="Enter the master password to retrieve the password:")

            # Hash the master password
            hashed_master_password = hashlib.sha256(master_password.encode()).hexdigest()
            
            # You can hash your masterpassword and can keep it in the ifstatement if you need.

            # if hashed_master_password == "93d842ed8c8969c60d6807c4438a3765fe93e0de68a3301f5a6c997a045d26aa":
            if master_password == m_pass:
                # If the master password is correct, show the existing password
                password = hashlib.sha256(existing_password.encode()).hexdigest()
                pyperclip.copy(password)
                messagebox.showinfo(title="Password Retrieved", message=f"The password for {website} is {password}.")
            else:
                messagebox.showerror(title="Error", message="Incorrect master password.")
        else:
            # Rewrite the existing password with the new one
            with open("passwords.txt", "w") as f:
                f.write(f"{website},{userid},{hashed_password}\n")

                # Clear the entry fields
                website_entry.delete(0, tk.END)
                userid_entry.delete(0, tk.END)
                password_entry.delete(0, tk.END)
                pyperclip.copy(password)
                messagebox.showinfo(title="Password Saved", message="Password saved successfully.")
    else:
        # Save the data to a file
        with open("passwords.txt", "a") as f:
            f.write(f"{website},{userid},{hashed_password}\n")

        # Clear the entry fields
        website_entry.delete(0, tk.END)
        userid_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        pyperclip.copy(password)
        messagebox.showinfo(title="Password Saved", message="Password saved successfully.")

def retrieve_password():
    """Retrieve the password for the website and userid entered by the user."""
    website = website_entry.get()
    userid = userid_entry.get()

    # Read the data from the file
    with open("passwords.txt", "r") as f:
        for line in f:
            data = line.strip().split(",")
            if data[0] == website and data[1] == userid:
                hashed_password = data[2]

                # Ask the user to enter the master password
                master_password = simpledialog.askstring(title="Master Password",
                                                         prompt="Enter the master password to retrieve the password:")

                # Hash the master password
                hashed_master_password = hashlib.sha256(master_password.encode()).hexdigest()

                if hashed_master_password == "acc5a5d2a3bca30f9aa524d46e78e3bba899c7a90a688e8b73d37e1f4429cb33":
                    # If the master password is correct, show the password
                    password = hashlib.sha256(hashed_password.encode()).hexdigest()
                    pyperclip.copy(password)
                    messagebox.showinfo(title="Password Retrieved", message=f"The password for {website} is {password}.")
                else:
                    messagebox.showerror(title="Error", message="Incorrect master password.")

# To show password
def show_password():
    """Show the password entered by the user."""
    if password_entry.cget('show') == '':
        password_entry.config(show='*')
        show_button.config(text='Show Password')
    else:
        password_entry.config(show='')
        show_button.config(text='Hide Password')


# Create the window
window = tk.Tk()
window.title("Password Manager")

# Labels and entries
website_label = tk.Label(window, text="Website:")
website_label.grid(row=0, column=0, padx=5, pady=5)
website_entry = tk.Entry(window, width=30)
website_entry.grid(row=0, column=1, padx=5, pady=5)

userid_label = tk.Label(window, text="Email/Mobile:")
userid_label.grid(row=1, column=0, padx=5, pady=5)
userid_entry = tk.Entry(window, width=30)
userid_entry.grid(row=1, column=1, padx=5, pady=5)

password_label = tk.Label(window, text="Password:")
password_label.grid(row=2, column=0, padx=5, pady=5)
password_entry = tk.Entry(window, show="*", width=30)
password_entry.grid(row=2, column=1, padx=5, pady=5)

# Buttons
generate_button = tk.Button(window, text="Generate Password", command=generate_password)
generate_button.grid(row=2, column=3, padx=5, pady=5)

save_button = tk.Button(window, text="Save Password", command=save_password)
save_button.grid(row=3, column=1, padx=5, pady=5)

retrieve_button = tk.Button(window, text="Retrieve Password", command=retrieve_password)
retrieve_button.grid(row=3, column=2, padx=5, pady=5)

show_button = tk.Button(window, text="Show Password", command=show_password)
show_button.grid(row=2, column=2, padx=5, pady=5)

# Set the focus to the website entry field
website_entry.focus()

# Start the GUI
window.mainloop()


