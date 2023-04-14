import os
import sys
import tkinter as tkinter
from tkinter import filedialog
from Signing import *

class MainWindow:

    # configure root directory path relative to this file
    
    THIS_FOLDER_G = ""
    if getattr(sys, "frozen", False):
        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:
        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

    def __init__(self, root):
        self.root = root
        self.fileUrl = tkinter.StringVar()
        self.publicKeyGenerated = tkinter.StringVar()
        self.status = tkinter.StringVar()
        self.status.set("---")

        self.shouldCancel = False

        root.title("Digital Signing")
        root.configure(bg="#FFFDD0")

        self.fileEntryLabel = tkinter.Label(
            root,
            text="Enter File Message Path Or Click SELECT FILE Button",
            bg="#FFFDD0",
            fg="#000000",
            anchor=tkinter.W
        )
        self.fileEntryLabel.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=0,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.fileEntry = tkinter.Entry(
            root,
            textvariable=self.fileUrl,
            bg="#fff",
            exportselection=0,
            relief=tkinter.FLAT
        )
        self.fileEntry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=1,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.selectBtn = tkinter.Button(
            root,
            text="SELECT FILE",
            command=self.selectFileCallback,
            width=42,
            bg="#1089ff",
            fg="#000000",
            bd=2,
            relief=tkinter.FLAT
        )
        self.selectBtn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=2,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.generatePublicKey = tkinter.Label(
            root,
            text="Generated Public Key:",
            bg="#FFFDD0",
            fg="#000000",
            anchor=tkinter.W
        )
        self.generatePublicKey.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=3,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.generatePublicKey = tkinter.Entry(
            root,
            bg="#fff",
            textvariable=self.publicKeyGenerated,
            exportselection=0,
            # state='disabled',
            relief=tkinter.FLAT,
        )
        self.generatePublicKey.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=4,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.generateBtn = tkinter.Button(
            root,
            text="GENERATE",
            command=self.generateCallback,
            bg="#ed3833",
            fg="#000000",
            bd=2,
            relief=tkinter.FLAT
        )
        self.generateBtn.grid(
            padx=(15, 6),
            pady=8,
            ipadx=24,
            ipady=6,
            row=5,
            column=0,
            columnspan=2,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )
        
        self.validateBtn = tkinter.Button(
            root,
            text="VALIDATE",
            command=self.validateCallback,
            bg="#00bd56",
            fg="#000000",
            bd=2,
            relief=tkinter.FLAT
        )
        self.validateBtn.grid(
            padx=(6, 15),
            pady=8,
            ipadx=24,
            ipady=6,
            row=5,
            column=2,
            columnspan=2,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.resetBtn = tkinter.Button(
            root,
            text="RESET",
            command=self.resetCallback,
            bg="#aaaaaa",
            fg="#000000",
            bd=2,
            relief=tkinter.FLAT
        )
        self.resetBtn.grid(
            padx=15,
            pady=(4, 12),
            ipadx=24,
            ipady=6,
            row=6,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

        self.statusBtn = tkinter.Label(
            root,
            textvariable=self.status,
            bg="#FFFDD0",
            fg="#000000",
            anchor=tkinter.W,
            justify=tkinter.LEFT,
            relief=tkinter.FLAT,
            wraplength=350
        )
        self.statusBtn.grid(
            padx=12,
            pady=(0, 12),
            ipadx=0,
            ipady=1,
            row=7,
            column=0,
            columnspan=4,
            sticky=tkinter.W+tkinter.E+tkinter.N+tkinter.S
        )

    def selectFileCallback(self):
        try:
            name = filedialog.askopenfile()
            self.fileUrl.set(name.name)
    
        except Exception as e:
            self.status.set(e)
            self.statusBtn.update()       
    
    def freezeControls(self):
        self.fileEntry.configure(state="disabled")
        self.selectBtn.configure(state="disabled")
        self.generateBtn.configure(state="disabled")
        self.validateBtn.configure(state="disabled")
        self.resetBtn.configure(text="CANCEL", command=self.cancelCallback,
            fg="#ed3833", bg="#fafafa")
        self.statusBtn.update()
    
    def unfreezeControls(self):
        self.fileEntry.configure(state="normal")
        self.selectBtn.configure(state="normal")
        self.generateBtn.configure(state="normal")
        self.validateBtn.configure(state="normal")
        self.resetBtn.configure(text="RESET", command=self.resetCallback,
            fg="#ffffff", bg="#aaaaaa")
        self.statusBtn.update()

    def saveKeyToFile(self,publicKey,privateKey):
        e, n = publicKey
        d, n = privateKey

        filePrivateKey = open("./RSAKey/key.pri","w")
        filePublicKey = open("./RSAKey/key.pub", "w")

        filePrivateKey.write("Private Key:\n")
        filePrivateKey.write("("+str(d) + ", " + str(n)+")")

        filePublicKey.write("Public Key:\n")
        filePublicKey.write("("+str(e) + ", " + str(n)+")")

        filePrivateKey.close()
        filePublicKey.close()

    def generateCallback(self):
        self.freezeControls()
        self.status.set("---")

        try: 
        
            signing = Signing()

            path = self.fileEntry.get()
            publicKey, privateKey = signing.generateKeyPair()

            self.saveKeyToFile(publicKey,privateKey)
  
            publicKeyString = str(publicKey)
            signing.generateSignMessage(path, privateKey)
            self.publicKeyGenerated.set(publicKeyString)

        except Exception as e:
            self.status.set(e)    

        self.unfreezeControls()    

    def validateCallback(self):
        self.freezeControls()

        try:
            signing = Signing()

            path = self.fileEntry.get()
            publicKey = self.publicKeyGenerated.get()

            # print(publicKey)
            
            publicKeyTupple = tuple(map(int, publicKey[1:-1].split(',')))

            # print(publicKeyTupple)

            if signing.validateSignedMessage(path, publicKeyTupple) == True:
                self.status.set("File: Authentic")
            else:
                self.status.set("File: False File")    

        except Exception as e:
            self.status.set(e)
        
        self.unfreezeControls()

    def resetCallback(self):
        self.fileUrl.set("")
        self.publicKeyGenerated.set("")
        self.status.set("---")
    
    def cancelCallback(self):
        self.shouldCancel = True


if __name__ == "__main__":
    ROOT = tkinter.Tk()
    MAIN_WINDOW = MainWindow(ROOT)
    ROOT.mainloop()