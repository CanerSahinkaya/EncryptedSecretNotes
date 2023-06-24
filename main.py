from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from PIL import ImageTk, Image
from itertools import cycle
import base64

class CustomText(Text):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def tab_pressed(self, event):
        self.tk_focusNext().focus()
        return 'break'

wn = Tk()
wn.title("Secret Notes")
wn.minsize(width=400, height=600)
FONT = ("Courier", 12, "normal")

def encode_zip_cycle(key, clear):
    enc = [chr((ord(clear_char) + ord(key_char)) % 256)
            for clear_char, key_char in zip(clear, cycle(key))]
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode_zip_cycle(key, enc):
    enc = base64.urlsafe_b64decode(enc.encode()).decode()
    dec = [chr((256 + ord(enc_char) - ord(key_char)) % 256)
            for enc_char, key_char in zip(enc, cycle(key))]
    return "".join(dec)

def create_file():
    title_file = title_entry.get()
    text_file = secret_text.get("1.0", END)
    key_file = key_entry.get()
    file_name = (title_file + ".txt")

    if title_file == "" or text_file == "" or key_file == "":
        messagebox.showerror(title="Error!", message="Oops, you missed something!")
    else:
        save_and_encrypt = encode_zip_cycle(key_file, text_file)
        messagebox.showinfo("What's your secret?")

        with open(file_name, "w") as secret_file:
            secret_file.write(f"\n{title_file}\n{save_and_encrypt}")


def decrypt_file():
    dec_text = secret_text.get("1.0", END)
    dec_key = key_entry.get()

    if dec_text.strip() == "" or dec_key.strip() == "":
        messagebox.showerror(title="Error!", message="Please make sure you have entered all the information")
    else:
        try:
            decrypt_note = decode_zip_cycle(dec_key, dec_text)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypt_note)
        except:
            messagebox.showerror(title="Error!", message="Invalid cryptography key")

#widgets

img = ImageTk.PhotoImage(Image.open("Secret.png"))
secret_img = ttk.Label(image=img)
secret_img.pack()

title_lbl = ttk.Label(text="Enter your title", font=FONT)
title_lbl.pack()
title_entry = ttk.Entry(width=20)
title_entry.pack()
secret_lbl = ttk.Label(text="Enter your text", font=FONT)
secret_lbl.pack()
secret_text = CustomText(width=40, height=18)
secret_text.pack()
key_lbl = ttk.Label(text="Enter master key", font=FONT)
key_lbl.pack()
key_entry = ttk.Entry(width=20, show="*")
key_entry.pack()

save_encrypt_button = Button(wn, text="Save & Encrypt", background="green", command=create_file)
save_encrypt_button.pack()
decrypt_button = ttk.Button(text="Decrypt", command=decrypt_file)
decrypt_button.pack()

secret_text.bind('<Tab>', secret_text.tab_pressed)

wn.mainloop()